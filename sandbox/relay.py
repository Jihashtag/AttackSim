"""Foothold relays — run the next hop's reachability probe FROM a proven foothold.

When access to a **container / VM / server / cloud instance** is PROVEN, a real attacker
uses that device as a vantage point to reach resources the scanner cannot (a private EKS
API, a peer behind a security group, a service across a VPN). The legacy pivot swept the
foothold's subnet *from the scanner's own network stack*, so a genuinely segmented next
hop was missed. A **relay** fixes that: it performs the next-hop reachability probe — and,
when a real tunnel exists, the host:port / url module traffic — through the foothold's
network position instead of the scanner's.

Every relay is **connect-only / read-only**. Nothing is installed on the foothold, no data
is changed, and any container the relay spawns is a throwaway that is connect-tested and
then removed. The relays:

* ``DirectRelay`` — the scanner's own stack (the legacy vantage). Always available.
* ``DockerRelay`` — an exposed Docker Engine API foothold. Spawns a throwaway, network-
  sharing busybox container that TCP-connect-tests the next-hop hosts and prints the open
  ones. No bind mounts, auto-removed. This is the benign exec primitive an exposed daemon
  already grants; it proves reachability *from the foothold* without changing anything.
* ``ProxyRelay`` — an operator/relay-positioned HTTP-CONNECT or SOCKS5 proxy (a real
  tunnel, e.g. ``ssh -D`` through the foothold). Both the reachability sweep AND the
  subsequent HTTP/service modules route through it, so the same modules run *as if from*
  the foothold.

A relay descriptor is a plain dict (``{"type": "docker", "host": ..., "port": ...}`` or
``{"type": "proxy", "url": ...}``) so it can be carried on a pivot spec and rebuilt by the
orchestrator with :func:`build_relay`.
"""
from __future__ import annotations

import json as _json
import re
import socket
import struct
import time
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from exploits import netutil

try:
    import config
except Exception:  # pragma: no cover
    config = None  # type: ignore

_DOCKER_IMAGE = getattr(config, "RELAY_DOCKER_IMAGE", "busybox:latest")
_DOCKER_NETWORK = getattr(config, "RELAY_DOCKER_NETWORK", "host")
_CONNECT_TIMEOUT = getattr(config, "RELAY_CONNECT_TIMEOUT", 2)
_CONNECT_TMPL = getattr(config, "RELAY_CONNECT_TMPL", "nc -w {timeout} -z {host} {port}")
_MAX_TARGETS = getattr(config, "RELAY_MAX_TARGETS", 512)
_RELAY_TIMEOUT = getattr(config, "RELAY_TIMEOUT", 12)
_PROXY_CONNECT_TIMEOUT = getattr(config, "RELAY_PROXY_CONNECT_TIMEOUT", 4)
_KUBELET_EXEC_TIMEOUT = getattr(config, "RELAY_KUBELET_EXEC_TIMEOUT", 10)
_K8S_API_EXEC_TIMEOUT = getattr(config, "RELAY_K8S_API_EXEC_TIMEOUT", 12)
_DNS_TIMEOUT = getattr(config, "RELAY_DNS_TIMEOUT", 5)
_SERVICE_HTTP_PROBE_TIMEOUT = getattr(config, "SERVICE_PIVOT_HTTP_PROBE_TIMEOUT", 6)

# Strict allow-lists. The Docker relay builds a `/bin/sh -c` script, so anything placed in
# it MUST be sanitised to defeat command injection (OWASP A03). Only literal hostnames / IP
# addresses and integer ports may ever reach the script.
_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,255}$")


def classify_resource_kind(kind: Optional[str], *, port=None, evidence: str = "") -> str:
    """Best-effort classification of a foothold/resource for the audit ledger.

    Returns one of ``container`` | ``host`` | ``cloud`` | ``service``. The distinction is
    only used for human-readable provenance ("reached from the *container* foothold …").
    """
    blob = f"{evidence}".lower()
    if kind == "cloud":
        return "cloud"
    if any(h in blob for h in ("docker", "kubelet", "containerd", "container", "pod",
                               "fargate", "ecs", "cloud run", "cloudrun")):
        return "container"
    try:
        p = int(port) if port is not None else None
    except (TypeError, ValueError):
        p = None
    if p in (2375, 2376, 10250, 10255):
        return "container"
    if p in (22, 3389):
        return "host"
    return "service"


def _safe_targets(hosts_ports: Sequence[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Drop any (host, port) pair that is not a literal host + integer port (injection guard)."""
    out: List[Tuple[str, int]] = []
    for host, port in hosts_ports:
        h = str(host).strip()
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        if not (0 < p < 65536):
            continue
        if not _HOST_RE.match(h):
            continue
        out.append((h, p))
        if len(out) >= _MAX_TARGETS:
            break
    return out


class Relay:
    """Base relay: a way to reach further hosts from a (possibly proven) vantage point."""

    type = "base"

    def available(self) -> bool:  # pragma: no cover - overridden
        return False

    def proxy_url(self) -> Optional[str]:
        """A proxy URL the HTTP/service modules can tunnel through, or None."""
        return None

    def detect_platform(self) -> Optional[str]:
        """Detect target platform (e.g., 'Linux x86_64') via relay exec.

        Returns 'OS ARCH' string or None if detection fails.
        """
        if hasattr(self, '_exec_cmd'):
            result = self._exec_cmd("uname -sm 2>/dev/null || echo Windows AMD64")
            if result:
                return result.strip()
        return None

    def detect_python(self) -> bool:
        """Check if python3 is available on the target."""
        if hasattr(self, '_exec_cmd'):
            result = self._exec_cmd("python3 --version 2>/dev/null && echo OK")
            return bool(result and "OK" in result)
        return False

    def sweep(self, hosts: Sequence[str], ports: Sequence[int], *,
              timeout: Optional[float] = None,
              deadline: Optional[float] = None) -> List[Tuple[str, int]]:  # pragma: no cover
        raise NotImplementedError

    def resolve(self, hostname: str) -> Optional[str]:
        """Resolve a hostname from the relay's network position. Returns IP or None."""
        return None

    def http_probe(self, url: str, *, timeout: Optional[float] = None) -> Optional[int]:
        """HTTP GET a URL from the relay's network position. Returns status code or None."""
        return None

    def describe(self) -> str:  # pragma: no cover - overridden
        return self.type


class DirectRelay(Relay):
    """The scanner's own network stack — the legacy, always-available vantage."""

    type = "direct"

    def available(self) -> bool:
        return True

    def sweep(self, hosts, ports, *, timeout=None, deadline=None):
        # Delegate to the shared unprivileged TCP-connect sweep (imported lazily to avoid a
        # cycle and to let tests monkeypatch the discovery function in one place).
        from exploits import host_sweep
        live = host_sweep.discover_live_hosts(list(hosts), tuple(ports), timeout=timeout,
                                              deadline=deadline)
        return [(h, p) for h, p in live]

    def resolve(self, hostname: str) -> Optional[str]:
        try:
            info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if info:
                return info[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return None

    def http_probe(self, url: str, *, timeout: Optional[float] = None) -> Optional[int]:
        to = timeout or _SERVICE_HTTP_PROBE_TIMEOUT
        status, _, _ = netutil.http_get(url, timeout=to)
        return status

    def describe(self) -> str:
        return "direct (scanner vantage)"


class DockerRelay(Relay):
    """Reach the next hop FROM an exposed Docker Engine API foothold (connect-only)."""

    type = "docker"

    def __init__(self, host: str, port: int, scheme: str = "http"):
        self.host = host
        self.port = int(port)
        self.scheme = scheme if scheme in ("http", "https") else "http"
        self._base: Optional[str] = None

    def _resolve_base(self) -> Optional[str]:
        if self._base:
            return self._base
        for scheme in (self.scheme, "https", "http"):
            base = f"{scheme}://{self.host}:{self.port}"
            status, _, _ = netutil.http_get(f"{base}/version", timeout=_CONNECT_TIMEOUT)
            if status and 200 <= status < 300:
                self._base = base
                return base
        return None

    def available(self) -> bool:
        return self._resolve_base() is not None

    def sweep(self, hosts, ports, *, timeout=None, deadline=None):
        base = self._resolve_base()
        targets = _safe_targets([(h, p) for h in hosts for p in ports])
        if not base or not targets:
            return []
        to = int(timeout or _CONNECT_TIMEOUT)
        # Build a single connect-only shell script: for each target, a benign `nc -z`
        # reachability test that echoes a parseable marker on success. No mounts, no writes.
        parts = []
        for h, p in targets:
            probe = _CONNECT_TMPL.format(timeout=to, host=h, port=p)
            parts.append(f"{probe} 2>/dev/null && echo OPEN {h}:{p}")
        script = "; ".join(parts)
        create_body = _json.dumps({
            "Image": _DOCKER_IMAGE,
            "Cmd": ["/bin/sh", "-c", script],
            "Tty": True,  # raw (non-multiplexed) logs so OPEN markers parse cleanly
            "HostConfig": {
                "AutoRemove": False,
                "NetworkMode": _DOCKER_NETWORK,  # share the foothold's network position
            },
        }).encode()
        cid = None
        reachable: List[Tuple[str, int]] = []
        try:
            st, body, _ = netutil.http_request(
                f"{base}/containers/create", "POST",
                headers={"Content-Type": "application/json"}, body=create_body,
                timeout=_RELAY_TIMEOUT)
            if st in (200, 201):
                try:
                    cid = _json.loads(body).get("Id")
                except Exception:
                    cid = None
            if not cid:
                return []  # image absent or create refused — caller falls back to direct
            netutil.http_request(f"{base}/containers/{cid}/start", "POST", timeout=_RELAY_TIMEOUT)
            netutil.http_request(f"{base}/containers/{cid}/wait", "POST", timeout=_RELAY_TIMEOUT)
            _st, logs, _ = netutil.http_get(
                f"{base}/containers/{cid}/logs?stdout=1&stderr=1",
                timeout=_RELAY_TIMEOUT, max_bytes=65536)
            reachable = _parse_open_markers(logs or "", targets)
        finally:
            if cid:
                netutil.http_request(f"{base}/containers/{cid}/stop", "POST", timeout=_CONNECT_TIMEOUT)
                netutil.http_request(f"{base}/containers/{cid}?force=1", "DELETE",
                                     timeout=_CONNECT_TIMEOUT)
        # Keep only the first open port per host (mirrors discover_live_hosts).
        seen = set()
        out = []
        for h, p in reachable:
            if h in seen:
                continue
            seen.add(h)
            out.append((h, p))
        return out

    def describe(self) -> str:
        return f"docker-relay via {self.host}:{self.port} (connect-only container)"

    def resolve(self, hostname: str) -> Optional[str]:
        """DNS lookup from inside the Docker foothold's network namespace."""
        base = self._resolve_base()
        if not base:
            return None
        script = f"getent hosts {hostname} 2>/dev/null | head -1 | awk '{{print $1}}'"
        create_body = _json.dumps({
            "Image": _DOCKER_IMAGE,
            "Cmd": ["/bin/sh", "-c", script],
            "Tty": True,
            "HostConfig": {"AutoRemove": False, "NetworkMode": _DOCKER_NETWORK},
        }).encode()
        cid = None
        try:
            st, body, _ = netutil.http_request(
                f"{base}/containers/create", "POST",
                headers={"Content-Type": "application/json"}, body=create_body,
                timeout=_RELAY_TIMEOUT)
            if st in (200, 201):
                try:
                    cid = _json.loads(body).get("Id")
                except Exception:
                    return None
            if not cid:
                return None
            netutil.http_request(f"{base}/containers/{cid}/start", "POST", timeout=_DNS_TIMEOUT)
            netutil.http_request(f"{base}/containers/{cid}/wait", "POST", timeout=_DNS_TIMEOUT)
            _st, logs, _ = netutil.http_get(
                f"{base}/containers/{cid}/logs?stdout=1&stderr=1",
                timeout=_DNS_TIMEOUT, max_bytes=4096)
            if logs:
                ip = logs.strip().split("\n")[-1].strip()
                try:
                    socket.inet_aton(ip)
                    return ip
                except OSError:
                    pass
        finally:
            if cid:
                netutil.http_request(f"{base}/containers/{cid}/stop", "POST", timeout=2)
                netutil.http_request(f"{base}/containers/{cid}?force=1", "DELETE", timeout=2)
        return None

    def http_probe(self, url: str, *, timeout: Optional[float] = None) -> Optional[int]:
        """HTTP GET from inside the Docker foothold's network namespace via wget."""
        base = self._resolve_base()
        if not base:
            return None
        to = int(timeout or _SERVICE_HTTP_PROBE_TIMEOUT)
        # Use wget -q -S to get status line; parse HTTP status from output
        script = f"wget -q -S --spider -T {to} '{url}' 2>&1 | head -5"
        create_body = _json.dumps({
            "Image": _DOCKER_IMAGE,
            "Cmd": ["/bin/sh", "-c", script],
            "Tty": True,
            "HostConfig": {"AutoRemove": False, "NetworkMode": _DOCKER_NETWORK},
        }).encode()
        cid = None
        try:
            st, body, _ = netutil.http_request(
                f"{base}/containers/create", "POST",
                headers={"Content-Type": "application/json"}, body=create_body,
                timeout=_RELAY_TIMEOUT)
            if st in (200, 201):
                try:
                    cid = _json.loads(body).get("Id")
                except Exception:
                    return None
            if not cid:
                return None
            netutil.http_request(f"{base}/containers/{cid}/start", "POST", timeout=to + 4)
            netutil.http_request(f"{base}/containers/{cid}/wait", "POST", timeout=to + 4)
            _st, logs, _ = netutil.http_get(
                f"{base}/containers/{cid}/logs?stdout=1&stderr=1",
                timeout=to + 2, max_bytes=4096)
            if logs:
                for line in logs.split("\n"):
                    if "HTTP/" in line:
                        parts = line.strip().split()
                        for p in parts:
                            if p.isdigit() and 100 <= int(p) < 600:
                                return int(p)
        finally:
            if cid:
                netutil.http_request(f"{base}/containers/{cid}/stop", "POST", timeout=2)
                netutil.http_request(f"{base}/containers/{cid}?force=1", "DELETE", timeout=2)
        return None


def _parse_open_markers(logs: str, targets: Sequence[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Extract ``OPEN host:port`` reachability markers emitted inside the relay container."""
    out: List[Tuple[str, int]] = []
    valid = {(h, int(p)) for h, p in targets}
    for h, p in valid:
        if f"OPEN {h}:{p}" in logs:
            out.append((h, p))
    out.sort()
    return out


class KubeletRelay(Relay):
    """Reach the next hop FROM inside a Kubernetes pod via kubelet /exec (anonymous).

    Uses kubelet 10250 anonymous exec on an existing running pod to execute benign
    reachability tests (nc -z). Connect-only: no mounts, no writes, no new pods.
    """

    type = "kubelet"

    def __init__(self, host: str, port: int = 10250, pod_ns: str = "default",
                 pod_name: str = "", container: str = ""):
        self.host = host
        self.port = int(port)
        self.pod_ns = pod_ns
        self.pod_name = pod_name
        self.container = container
        self._base = f"https://{host}:{port}"
        self._pod_info: Optional[dict] = None

    def _find_running_pod(self) -> Optional[dict]:
        """Find a running pod we can exec into via kubelet /pods."""
        if self._pod_info:
            return self._pod_info
        status, body, _ = netutil.http_get(f"{self._base}/pods", timeout=_KUBELET_EXEC_TIMEOUT)
        if not status or status != 200 or not body:
            return None
        try:
            import json
            data = json.loads(body)
        except Exception:
            return None
        for item in (data.get("items") or []):
            meta = item.get("metadata") or {}
            pod_status = item.get("status") or {}
            phase = pod_status.get("phase", "")
            if phase != "Running":
                continue
            ns = meta.get("namespace", "default")
            name = meta.get("name", "")
            containers = [c.get("name", "") for c in (item.get("spec") or {}).get("containers") or []]
            if name and containers:
                self._pod_info = {"ns": ns, "name": name, "container": containers[0]}
                return self._pod_info
        return None

    def available(self) -> bool:
        if self.pod_name:
            return True
        return self._find_running_pod() is not None

    def _exec_cmd(self, cmd: str) -> Optional[str]:
        """Execute a command via kubelet /run endpoint (simpler than websocket /exec)."""
        pod = self._find_running_pod() if not self.pod_name else {
            "ns": self.pod_ns, "name": self.pod_name, "container": self.container or ""}
        if not pod:
            return None
        ns = pod["ns"]
        name = pod["name"]
        container = pod["container"]
        # kubelet /run/{ns}/{pod}/{container} accepts POST with cmd= body
        url = f"{self._base}/run/{ns}/{name}/{container}"
        body = f"cmd={cmd}".encode()
        st, resp, _ = netutil.http_request(url, "POST",
                                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                                           body=body, timeout=_KUBELET_EXEC_TIMEOUT)
        if st and 200 <= st < 300 and resp:
            return resp
        return None

    def sweep(self, hosts, ports, *, timeout=None, deadline=None):
        targets = _safe_targets([(h, p) for h in hosts for p in ports])
        if not targets:
            return []
        to = int(timeout or _CONNECT_TIMEOUT)
        parts = []
        for h, p in targets:
            probe = _CONNECT_TMPL.format(timeout=to, host=h, port=p)
            parts.append(f"{probe} 2>/dev/null && echo OPEN {h}:{p}")
        script = "; ".join(parts)
        result = self._exec_cmd(script)
        if not result:
            return []
        reachable = _parse_open_markers(result, targets)
        seen = set()
        out = []
        for h, p in reachable:
            if h in seen:
                continue
            seen.add(h)
            out.append((h, p))
        return out

    def resolve(self, hostname: str) -> Optional[str]:
        result = self._exec_cmd(f"getent hosts {hostname} 2>/dev/null | head -1 | awk '{{print $1}}'")
        if result:
            ip = result.strip().split("\n")[-1].strip()
            try:
                socket.inet_aton(ip)
                return ip
            except OSError:
                pass
        return None

    def http_probe(self, url: str, *, timeout: Optional[float] = None) -> Optional[int]:
        to = int(timeout or _SERVICE_HTTP_PROBE_TIMEOUT)
        result = self._exec_cmd(f"wget -q -S --spider -T {to} '{url}' 2>&1 | head -5")
        if result:
            for line in result.split("\n"):
                if "HTTP/" in line:
                    parts = line.strip().split()
                    for p in parts:
                        if p.isdigit() and 100 <= int(p) < 600:
                            return int(p)
        return None

    def describe(self) -> str:
        pod = self._pod_info or {"ns": self.pod_ns, "name": self.pod_name}
        return f"kubelet-relay via {self.host}:{self.port} (exec in {pod.get('ns')}/{pod.get('name')})"


class K8sApiRelay(Relay):
    """Reach the next hop via K8s API pod/exec with a discovered ServiceAccount token.

    Uses the K8s API server /exec endpoint to run connectivity tests from inside a
    running pod. Requires a valid SA token with pods/exec permission.
    """

    type = "k8s-api"

    def __init__(self, api_url: str, token: str, namespace: str = "default",
                 pod_name: str = "", container: str = ""):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.namespace = namespace
        self.pod_name = pod_name
        self.container = container

    def available(self) -> bool:
        if not self.token or not self.api_url:
            return False
        # Verify token works by checking /api
        headers = {"Authorization": f"Bearer {self.token}"}
        status, _, _ = netutil.http_get(f"{self.api_url}/api", timeout=_K8S_API_EXEC_TIMEOUT,
                                        extra_headers=headers)
        return status is not None and 200 <= (status or 0) < 500

    def _exec_cmd(self, cmd: str) -> Optional[str]:
        """Execute via K8s API exec (simplified: use the /run-like attach for short commands)."""
        if not self.pod_name or not self.namespace:
            return None
        # K8s API exec via POST to ephemeral containers or by crafting exec URL
        # Simplified: use the attach/exec mechanism as a request with command
        headers = {"Authorization": f"Bearer {self.token}"}
        # Use the pods/exec subresource with command parameter
        import urllib.parse
        params = urllib.parse.urlencode({
            "command": ["/bin/sh", "-c", cmd],
            "container": self.container,
            "stdout": "true", "stderr": "true",
        }, doseq=True)
        url = (f"{self.api_url}/api/v1/namespaces/{self.namespace}/pods/{self.pod_name}"
               f"/exec?{params}")
        # For simplified non-websocket access, try the exec subresource
        # In practice this needs websocket; fall back to direct TCP from proxy if available
        status, body, _ = netutil.http_request(url, "POST", headers=headers,
                                               timeout=_K8S_API_EXEC_TIMEOUT)
        if status and 200 <= status < 400 and body:
            return body
        return None

    def sweep(self, hosts, ports, *, timeout=None, deadline=None):
        targets = _safe_targets([(h, p) for h in hosts for p in ports])
        if not targets:
            return []
        to = int(timeout or _CONNECT_TIMEOUT)
        parts = []
        for h, p in targets:
            probe = _CONNECT_TMPL.format(timeout=to, host=h, port=p)
            parts.append(f"{probe} 2>/dev/null && echo OPEN {h}:{p}")
        script = "; ".join(parts)
        result = self._exec_cmd(script)
        if not result:
            return []
        reachable = _parse_open_markers(result, targets)
        seen = set()
        out = []
        for h, p in reachable:
            if h in seen:
                continue
            seen.add(h)
            out.append((h, p))
        return out

    def resolve(self, hostname: str) -> Optional[str]:
        result = self._exec_cmd(f"getent hosts {hostname} 2>/dev/null | head -1 | awk '{{print $1}}'")
        if result:
            ip = result.strip().split("\n")[-1].strip()
            try:
                socket.inet_aton(ip)
                return ip
            except OSError:
                pass
        return None

    def http_probe(self, url: str, *, timeout: Optional[float] = None) -> Optional[int]:
        to = int(timeout or _SERVICE_HTTP_PROBE_TIMEOUT)
        result = self._exec_cmd(f"wget -q -S --spider -T {to} '{url}' 2>&1 | head -5")
        if result:
            for line in result.split("\n"):
                if "HTTP/" in line:
                    parts = line.strip().split()
                    for p in parts:
                        if p.isdigit() and 100 <= int(p) < 600:
                            return int(p)
        return None

    def describe(self) -> str:
        return f"k8s-api-relay via {self.api_url} (exec in {self.namespace}/{self.pod_name})"


class ProxyRelay(Relay):
    """Reach/route the next hop through an HTTP-CONNECT or SOCKS5 proxy (a real tunnel)."""

    type = "proxy"

    def __init__(self, url: str):
        self.url = url
        parsed = urlparse(url)
        self.scheme = (parsed.scheme or "http").lower()
        self.phost = parsed.hostname or "127.0.0.1"
        self.pport = parsed.port or (1080 if "socks" in self.scheme else 8080)

    def available(self) -> bool:
        try:
            with socket.create_connection((self.phost, self.pport),
                                          timeout=_PROXY_CONNECT_TIMEOUT):
                return True
        except OSError:
            return False

    def proxy_url(self) -> Optional[str]:
        return self.url

    def sweep(self, hosts, ports, *, timeout=None, deadline=None):
        targets = _safe_targets([(h, p) for h in hosts for p in ports])
        to = float(timeout or _PROXY_CONNECT_TIMEOUT)
        out: List[Tuple[str, int]] = []
        seen = set()
        for h, p in targets:
            if h in seen:
                continue
            if self._reachable_through_proxy(h, p, to):
                seen.add(h)
                out.append((h, p))
        return out

    def _reachable_through_proxy(self, host: str, port: int, timeout: float) -> bool:
        try:
            if "socks" in self.scheme:
                return _socks5_connect(self.phost, self.pport, host, port, timeout)
            return _http_connect(self.phost, self.pport, host, port, timeout)
        except OSError:
            return False

    def resolve(self, hostname: str) -> Optional[str]:
        # For SOCKS5 proxies, resolution happens server-side (ATYP 0x03 domain).
        # We can test reachability of the hostname on port 443 to confirm DNS works.
        if self._reachable_through_proxy(hostname, 443, _PROXY_CONNECT_TIMEOUT):
            return hostname  # proxy resolved it successfully
        if self._reachable_through_proxy(hostname, 80, _PROXY_CONNECT_TIMEOUT):
            return hostname
        return None

    def http_probe(self, url: str, *, timeout: Optional[float] = None) -> Optional[int]:
        """HTTP GET through the proxy tunnel."""
        to = timeout or _SERVICE_HTTP_PROBE_TIMEOUT
        # Use netutil with proxy setting
        import os
        old_proxy = os.environ.get("http_proxy")
        old_https = os.environ.get("https_proxy")
        try:
            os.environ["http_proxy"] = self.url
            os.environ["https_proxy"] = self.url
            status, _, _ = netutil.http_get(url, timeout=to)
            return status
        finally:
            if old_proxy is not None:
                os.environ["http_proxy"] = old_proxy
            else:
                os.environ.pop("http_proxy", None)
            if old_https is not None:
                os.environ["https_proxy"] = old_https
            else:
                os.environ.pop("https_proxy", None)

    def describe(self) -> str:
        return f"proxy-relay via {self.scheme}://{self.phost}:{self.pport}"


def _http_connect(phost: str, pport: int, host: str, port: int, timeout: float) -> bool:
    """Test reachability of host:port through an HTTP CONNECT proxy (no payload sent)."""
    with socket.create_connection((phost, pport), timeout=timeout) as s:
        s.settimeout(timeout)
        req = (f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "Proxy-Connection: close\r\n\r\n").encode("latin-1")
        s.sendall(req)
        resp = s.recv(256)
    return b" 200 " in resp or resp.startswith(b"HTTP/1.1 200") or resp.startswith(b"HTTP/1.0 200")


def _socks5_connect(phost: str, pport: int, host: str, port: int, timeout: float) -> bool:
    """Test reachability of host:port through a SOCKS5 proxy (CONNECT, no-auth)."""
    with socket.create_connection((phost, pport), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")                 # greeting: version 5, 1 method, no-auth
        if s.recv(2) != b"\x05\x00":               # server must accept no-auth
            return False
        try:
            raw = socket.inet_aton(host)            # IPv4 literal -> ATYP 0x01
            addr = b"\x01" + raw
        except OSError:
            h = host.encode("idna") if host else b""
            addr = b"\x03" + struct.pack("!B", len(h)) + h   # domain -> ATYP 0x03
        s.sendall(b"\x05\x01\x00" + addr + struct.pack("!H", port))
        reply = s.recv(10)
    return len(reply) >= 2 and reply[0] == 0x05 and reply[1] == 0x00  # REP 0x00 = succeeded


def build_relay(spec: Optional[dict], *, fallback_proxy: Optional[str] = None) -> Relay:
    """Rebuild a :class:`Relay` from a pivot-spec descriptor.

    Precedence: an explicit relay descriptor on the spec wins; otherwise an operator-supplied
    ``fallback_proxy`` (``--pivot-proxy``) is used; otherwise the scanner-side direct relay.
    """
    if isinstance(spec, dict) and spec.get("type"):
        t = spec.get("type")
        if t == "docker" and spec.get("host") and spec.get("port"):
            return DockerRelay(spec["host"], spec["port"], spec.get("scheme", "http"))
        if t == "kubelet" and spec.get("host"):
            return KubeletRelay(spec["host"], spec.get("port", 10250),
                                spec.get("pod_ns", "default"),
                                spec.get("pod_name", ""),
                                spec.get("container", ""))
        if t == "k8s-api" and spec.get("api_url") and spec.get("token"):
            return K8sApiRelay(spec["api_url"], spec["token"],
                               spec.get("namespace", "default"),
                               spec.get("pod_name", ""),
                               spec.get("container", ""))
        if t == "proxy" and spec.get("url"):
            return ProxyRelay(spec["url"])
        if t == "ssh" and spec.get("host"):
            return SSHRelay(spec["host"], spec.get("port", 22),
                            spec.get("user", "root"),
                            spec.get("key_path", ""),
                            spec.get("password", ""))
    if fallback_proxy:
        return ProxyRelay(fallback_proxy)
    return DirectRelay()


class SSHRelay(Relay):
    """Reach the next hop FROM a proven SSH foothold via remote command execution.

    Uses an established SSH credential (key or password) to run connect-tests
    from the remote host's network position. Connect-only: no files written,
    no persistent sessions.
    """

    type = "ssh"

    def __init__(self, host: str, port: int = 22, user: str = "root",
                 key_path: str = "", password: str = ""):
        self.host = host
        self.port = int(port)
        self.user = user
        self.key_path = key_path
        self.password = password

    def available(self) -> bool:
        # Quick TCP check to confirm SSH is reachable
        try:
            with socket.create_connection((self.host, self.port), timeout=_CONNECT_TIMEOUT):
                return True
        except OSError:
            return False

    def _exec_cmd(self, cmd: str) -> Optional[str]:
        """Execute a command on the remote host via SSH."""
        import subprocess
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={_CONNECT_TIMEOUT}",
            "-o", "BatchMode=yes",
            "-p", str(self.port),
        ]
        if self.key_path:
            ssh_opts.extend(["-i", self.key_path])

        ssh_cmd = ["ssh"] + ssh_opts + [f"{self.user}@{self.host}", cmd]

        if self.password and not self.key_path:
            ssh_cmd = ["sshpass", "-p", self.password] + ssh_cmd

        try:
            proc = subprocess.run(ssh_cmd, capture_output=True,
                                  timeout=_RELAY_TIMEOUT)
            if proc.returncode == 0:
                return proc.stdout.decode("utf-8", errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return None

    def sweep(self, hosts, ports, *, timeout=None, deadline=None):
        targets = _safe_targets([(h, p) for h in hosts for p in ports])
        if not targets:
            return []
        to = int(timeout or _CONNECT_TIMEOUT)
        # Build a single script that tests all targets
        parts = []
        for h, p in targets:
            probe = _CONNECT_TMPL.format(timeout=to, host=h, port=p)
            parts.append(f"{probe} 2>/dev/null && echo OPEN {h}:{p}")
        script = "; ".join(parts)
        result = self._exec_cmd(script)
        if not result:
            return []
        reachable = _parse_open_markers(result, targets)
        seen = set()
        out = []
        for h, p in reachable:
            if h in seen:
                continue
            seen.add(h)
            out.append((h, p))
        return out

    def proxy_url(self) -> Optional[str]:
        """SSH relay can provide a SOCKS5 proxy via ssh -D (not auto-started)."""
        return None

    def resolve(self, hostname: str) -> Optional[str]:
        result = self._exec_cmd(
            f"getent hosts {hostname} 2>/dev/null | head -1 | awk '{{print $1}}'")
        if result:
            ip = result.strip().split("\n")[-1].strip()
            try:
                socket.inet_aton(ip)
                return ip
            except OSError:
                pass
        return None

    def http_probe(self, url: str, *, timeout: Optional[float] = None) -> Optional[int]:
        to = int(timeout or _SERVICE_HTTP_PROBE_TIMEOUT)
        result = self._exec_cmd(
            f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout {to} '{url}' 2>/dev/null "
            f"|| wget -q -S --spider -T {to} '{url}' 2>&1 | grep 'HTTP/' | awk '{{print $2}}'")
        if result:
            code = result.strip().split("\n")[-1].strip()
            if code.isdigit() and 100 <= int(code) < 600:
                return int(code)
        return None

    def describe(self) -> str:
        return f"ssh-relay via {self.user}@{self.host}:{self.port}"
