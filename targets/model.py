"""Target abstraction and resolver.

A *target* is whatever the toolkit is asked to attack. It can be:

* ``repo``     — a local directory **or** a remote git URL (shallow-cloned to a
                 temp dir, then treated as a local repo).
* ``url``      — a live HTTP(S) endpoint, optionally with a ``jwt`` or ``api_key``.
* ``creds``    — a set of credentials to validate, optionally against a ``url``.
* ``hostport`` — a ``host:port`` network service.

If nothing is supplied, the resolver falls back to the workspace repository that
contains this toolkit, preserving the original behaviour.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import tempfile
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})$")

REPO = "repo"
URL = "url"
CREDS = "creds"
HOSTPORT = "hostport"
LOCAL = "local"
CLOUD = "cloud"
NETRANGE = "netrange"

_GIT_URL_RE = re.compile(r"^(https?://\S+\.git|git@[\w.\-]+:\S+|ssh://\S+|git://\S+)$", re.IGNORECASE)
_HTTP_RE = re.compile(r"^https?://", re.IGNORECASE)
_HOSTPORT_RE = re.compile(r"^(?P<host>\[[0-9a-fA-F:]+\]|[\w.\-]+):(?P<port>\d{1,5})$")
# host:port-spec where the spec may be a single port, a range, or a comma list.
_PORTSPEC = r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*"
_HOSTPORTS_RE = re.compile(
    r"^(?P<host>\[[0-9a-fA-F:]+\]|[\w.\-]+):(?P<ports>" + _PORTSPEC + r")$"
)
_PORTSPEC_RE = re.compile(r"^" + _PORTSPEC + r"$")

# IPv4 CIDR (a.b.c.d/nn), dotted-quad last-octet range (a.b.c.d-e), or full-IP range
# (a.b.c.d-a.b.c.f), each optionally followed by ``:portspec``.
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
# Loose IPv6 matcher: hex groups and colons with at least one ':' (so it never matches a
# bare IPv4/hostname). Real validation is deferred to ipaddress.ip_network in parse_hosts.
_IPV6 = r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*"
_NETRANGE_CORE = (
    r"(?:" + _IPV4 + r"/\d{1,2}"                       # IPv4 CIDR
    r"|" + _IPV4 + r"-\d{1,3}"                          # last-octet range
    r"|" + _IPV4 + r"-" + _IPV4 +                       # full-IP range
    r"|\[" + _IPV6 + r"\]/\d{1,3}"                      # bracketed IPv6 CIDR ([2001:db8::]/64)
    r"|" + _IPV6 + r"/\d{1,3}"                          # bare IPv6 CIDR (2001:db8::/64)
    r")"
)
_NETRANGE_RE = re.compile(
    r"^(?P<net>" + _NETRANGE_CORE + r")(?::(?P<ports>" + _PORTSPEC + r"))?$"
)

# Safety cap so an accidental 0-65535 sweep cannot run unbounded.
# Sourced from the central config; re-exported here for backwards compatibility.
try:
    from config import MAX_PORTS  # type: ignore
except Exception:  # pragma: no cover - config always present in normal runs
    MAX_PORTS = 2048

try:
    from config import MAX_HOSTS, MAX_HOST_PORT_PRODUCT  # type: ignore
except Exception:  # pragma: no cover
    MAX_HOSTS = 1024
    MAX_HOST_PORT_PRODUCT = 65536



class TargetError(ValueError):
    """Raised when the supplied target cannot be understood or prepared."""


@dataclass
class Target:
    kind: str
    raw: str = ""
    root: Optional[str] = None          # filesystem path (repo only)
    url: Optional[str] = None
    jwt: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    email: Optional[str] = None         # email address (domain used for SMTP targets)
    host: Optional[str] = None
    port: Optional[int] = None
    ports: List[int] = field(default_factory=list)   # full list to scan (hostport)
    hosts: List[str] = field(default_factory=list)   # expanded hosts (netrange)
    cred_kind: Optional[str] = None     # e.g. 'basic', 'bearer', 'apikey', 'aws'
    auth_header: Optional[str] = None   # custom header NAME to carry the token
    auth_scheme: Optional[str] = None   # value prefix; None => per-type default
    is_temp_clone: bool = False
    notes: List[str] = field(default_factory=list)

    # -- credentialed cloud assessment (discovery-driven, opt-in) ----------
    cloud_inventory: object = None      # sandbox.cloud_creds.CloudInventory (in-memory)
    cloud_endpoints: Dict[str, str] = field(default_factory=dict)  # test/region overrides

    # -- opt-in proof-of-access flags (set by main.py) ---------------------
    prove_access: bool = False
    prove_access_writes: bool = False
    prove_access_shell: bool = False

    # -- intensity / scope governor + active-module options (set by main.py) ---
    scope_guard: object = None          # sandbox.scope_guard.ScopeGuard
    intensity: Optional[str] = None     # run intensity tier
    spray: bool = False                 # enable default-credential spraying
    canary_url: Optional[str] = None    # operator callback for active SSRF confirm
    oob_listener: object = None          # sandbox.oob_listener.OOBListener (for was_hit confirm)
    nse_scripts: Optional[str] = None   # opt-in nmap NSE selector
    live_hosts: List[str] = field(default_factory=list)  # discovered by host_sweep
    discovered_services: List[dict] = field(default_factory=list)  # for cred spray

    # -- authenticated-session passthrough (operator-supplied, read-only) ----
    cookies: Optional[str] = None       # raw Cookie header value
    session_headers: Dict[str, str] = field(default_factory=dict)  # extra request headers
    proxy: Optional[str] = None         # operator HTTP/SOCKS proxy for active traffic
    budget: object = None               # sandbox.budget.RequestBudget (global governor)

    # -- second identity for object-level authz (BOLA/IDOR) testing ----------
    idor_alt_headers: Dict[str, str] = field(default_factory=dict)  # alt-user request headers

    # -- inter-module iteration / lateral-movement pivots --------------------
    # Modules that discover further reachable surface (a crawl, an SSM-reachable
    # instance's subnet peers, …) append host:port/url specs here; the orchestrator
    # re-runs the applicable modules against them, bounded by ``pivot_depth``.
    discovered_urls: List[str] = field(default_factory=list)   # spider output (same-origin)
    pivot_targets: List[dict] = field(default_factory=list)    # [{kind,host,port,ports,via,note}]
    pivot_depth: int = 0                # how many pivot hops produced this target (0 = original)

    # -- foothold-relayed scanning + proof-of-access identification ----------
    # When access is PROVEN, the next hop is reached FROM the foothold via a relay
    # (sandbox/relay.py) rather than the scanner's stack; ``reached_via`` names the parent
    # foothold so the ledger can attribute the access, and ``proof_ledger`` (shared by
    # reference across all pivots) records the end-to-end identification path.
    via_relay: object = None            # sandbox.relay.Relay used to reach THIS target (or None)
    reached_via: str = "scanner"        # parent foothold identity this target was reached from
    pivot_proxy: Optional[str] = None   # operator relay tunnel (--pivot-proxy) for foothold traffic
    proof_ledger: object = None         # sandbox.ledger.ProofLedger (shared across pivots)

    # -- auth header construction ------------------------------------------
    def jwt_header(self) -> Optional[tuple]:
        """Return (header_name, header_value) for the JWT, or None."""
        if not self.jwt:
            return None
        name = self.auth_header or "Authorization"
        scheme = "Bearer" if self.auth_scheme is None else self.auth_scheme
        prefix = f"{scheme} " if scheme else ""
        return (name, f"{prefix}{self.jwt}")

    def api_key_header(self) -> Optional[tuple]:
        """Return (header_name, header_value) for the API key, or None."""
        if not self.api_key:
            return None
        name = self.auth_header or "X-API-Key"
        scheme = "" if self.auth_scheme is None else self.auth_scheme
        prefix = f"{scheme} " if scheme else ""
        return (name, f"{prefix}{self.api_key}")

    def auth_headers(self) -> dict:
        """All token-based auth headers combined (for presenting alongside a request)."""
        headers = {}
        for pair in (self.jwt_header(), self.api_key_header()):
            if pair:
                headers[pair[0]] = pair[1]
        return headers

    def request_headers(self) -> dict:
        """Auth + session headers an active module should present to test *behind* login.

        Combines token auth (``auth_headers``), an operator ``Cookie`` value, and any
        extra ``session_headers`` (e.g. ``X-CSRF-Token``). All are operator-supplied and
        used read-only.
        """
        out = dict(self.auth_headers())
        if self.cookies:
            out["Cookie"] = self.cookies
        if self.session_headers:
            out.update(self.session_headers)
        return out

    # -- presentation -------------------------------------------------------
    def describe(self) -> str:
        if self.kind == REPO:
            origin = f" (cloned from {self.raw})" if self.is_temp_clone else ""
            return f"repo:{self.root}{origin}"
        if self.kind == URL:
            extra = []
            if self.jwt:
                extra.append("jwt")
            if self.api_key:
                extra.append("api-key")
            tail = f" [+{'+'.join(extra)}]" if extra else ""
            return f"url:{self.url}{tail}"
        if self.kind == CREDS:
            against = f" against {self.url}" if self.url else ""
            return f"creds:{self.cred_kind or 'generic'}{against}"
        if self.kind == HOSTPORT:
            if self.ports and len(self.ports) > 1:
                return f"hostport:{self.host}:[{len(self.ports)} ports]"
            return f"hostport:{self.host}:{self.port}"
        if self.kind == NETRANGE:
            return (f"netrange:{self.raw} "
                    f"[{len(self.hosts)} host(s) x {len(self.ports)} port(s)]")
        if self.kind == LOCAL:
            return "local:this-host (introspection)"
        if self.kind == CLOUD:
            inv = self.cloud_inventory
            n = len(getattr(inv, "credentials", []) or []) if inv else 0
            provs = ",".join(getattr(inv, "providers", lambda: [])()) if inv else ""
            return f"cloud:[{n} discovered cred(s){(' ' + provs) if provs else ''}]"
        return f"{self.kind}:{self.raw}"

    def cleanup(self) -> None:
        if self.is_temp_clone and self.root and os.path.isdir(self.root):
            shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------
def looks_like_git_url(value: str) -> bool:
    return bool(_GIT_URL_RE.match(value.strip()))


def looks_like_http_url(value: str) -> bool:
    return bool(_HTTP_RE.match(value.strip()))


def looks_like_hostport(value: str) -> bool:
    m = _HOSTPORT_RE.match(value.strip())
    if not m:
        return False
    return 0 < int(m.group("port")) <= 65535


def looks_like_hostports(value: str) -> bool:
    """True for host:port, host:a-b, or host:a,b,c forms."""
    return bool(_HOSTPORTS_RE.match(value.strip()))


def parse_ports(spec: str) -> List[int]:
    """Expand a port spec ('22', '1-1024', '22,80,443', '8000-8100,9443') to a list."""
    spec = spec.strip()
    if not _PORTSPEC_RE.match(spec):
        raise TargetError(f"invalid port spec: {spec!r} (use N, N-M, or comma lists).")
    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b:
                a, b = b, a
            ports.extend(range(a, b + 1))
        else:
            ports.append(int(part))
    valid = sorted({p for p in ports if 0 < p <= 65535})
    if not valid:
        raise TargetError(f"no valid ports in spec: {spec!r}")
    if len(valid) > MAX_PORTS:
        raise TargetError(
            f"port spec expands to {len(valid)} ports (cap {MAX_PORTS}); narrow the range."
        )
    return valid


def looks_like_netrange(value: str) -> bool:
    """True for a CIDR / IP-range, optionally with a ``:portspec`` suffix."""
    return bool(_NETRANGE_RE.match(value.strip()))


def parse_hosts(spec: str, *, max_hosts: Optional[int] = None) -> List[str]:
    """Expand a CIDR / IP-range to a list of host IPs (network/broadcast excluded).

    Accepts ``a.b.c.d/nn`` (CIDR), ``a.b.c.d-e`` (last-octet range), or
    ``a.b.c.d-a.b.c.f`` (full-IP range). The optional ``:portspec`` suffix is *not*
    handled here — callers split it off first. Capped at ``max_hosts`` (config
    ``MAX_HOSTS``) so an accidental wide range cannot expand unbounded.
    """
    cap = MAX_HOSTS if max_hosts is None else max_hosts
    spec = spec.strip()
    # Accept bracketed IPv6 CIDR ([2001:db8::]/64) by stripping the brackets.
    if spec.startswith("[") and "]" in spec:
        spec = spec.replace("[", "", 1).replace("]", "", 1)
    hosts: List[str] = []
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            # For anything wider than a /31, drop network + broadcast addresses.
            iterator = net.hosts() if net.num_addresses > 2 else net
            for ip in iterator:
                hosts.append(str(ip))
                if len(hosts) > cap:
                    raise TargetError(
                        f"network {spec!r} expands past the {cap}-host cap; narrow it "
                        "or raise --max-hosts.")
        elif "-" in spec:
            start_s, end_s = spec.split("-", 1)
            start = ipaddress.ip_address(start_s)
            if "." in end_s:
                end = ipaddress.ip_address(end_s)
            else:  # last-octet shorthand: a.b.c.d-e
                prefix = start_s.rsplit(".", 1)[0]
                end = ipaddress.ip_address(f"{prefix}.{end_s}")
            if int(end) < int(start):
                start, end = end, start
            if int(end) - int(start) + 1 > cap:
                raise TargetError(
                    f"range {spec!r} expands to more than the {cap}-host cap; narrow it "
                    "or raise --max-hosts.")
            cur = int(start)
            while cur <= int(end):
                hosts.append(str(ipaddress.ip_address(cur)))
                cur += 1
        else:
            hosts.append(str(ipaddress.ip_address(spec)))
    except TargetError:
        raise
    except ValueError as exc:
        raise TargetError(f"invalid network/range {spec!r}: {exc}")
    if not hosts:
        raise TargetError(f"network/range {spec!r} expands to no usable hosts.")
    return hosts


# ---------------------------------------------------------------------------
# Repo cloning
# ---------------------------------------------------------------------------
def clone_repo(url: str, depth: int = 1) -> str:
    """Shallow-clone ``url`` into a temp dir and return the path.

    No credentials are injected; only public / already-authorised remotes will
    succeed (consistent with the credential-free guarantee).
    """
    if not shutil.which("git"):
        raise TargetError("git is required to clone a repository URL but was not found on PATH.")
    tmp = tempfile.mkdtemp(prefix="sectest_clone_")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", str(depth), "--quiet", url, tmp],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"},
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise TargetError(f"timed out cloning {url}")
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        msg = (proc.stderr or proc.stdout or "unknown error").strip().splitlines()[-1:]
        raise TargetError(f"failed to clone {url}: {msg[0] if msg else 'unknown error'}")
    return tmp


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
def _infer_cred_kind(username, password, jwt, api_key) -> str:
    if jwt:
        return "bearer"
    if api_key:
        return "apikey"
    if username or password:
        return "basic"
    return "generic"


def looks_like_email(value: str) -> bool:
    """True when ``value`` looks like a valid email address."""
    return bool(_EMAIL_RE.match(value.strip()))


def _email_domain(email: str) -> str:
    """Extract the domain part of an email address."""
    if "@" in email:
        return email.split("@", 1)[1].strip()
    return email.strip()


def _make_email_target(email: str, ports: Optional[str] = None,
                       username: Optional[str] = None,
                       password: Optional[str] = None) -> Target:
    """Build a HOSTPORT target on SMTP ports for an email address.

    The domain is resolved to its MX host when possible so the SMTP probe
    reaches the actual mail server; falls back to the domain itself.
    """
    domain = _email_domain(email)
    # Real MX lookup via the project's stdlib DNS helper (no external dependencies).
    # getaddrinfo() only does A/AAAA resolution — it never returns the MX host, so for
    # any domain whose MX != A record (the common case, e.g. gmail.com) the probe used
    # to hit the wrong host (BUG-9). Resolve the lowest-preference MX exchange; fall back
    # to the domain's A record only if MX resolution yields nothing.
    smtp_host = domain
    try:
        from exploits import dnsutil
        resolvers = dnsutil.system_resolvers() or ["1.1.1.1"]
        mx_rdata: List[str] = []
        for rv in resolvers:
            mx_rdata = dnsutil.resolve(domain, "MX", rv, timeout=4)
            if mx_rdata:
                break
        # rdata is "<pref> <exchange.>"; choose the lowest preference.
        parsed = []
        for rd in mx_rdata:
            parts = rd.split()
            if len(parts) == 2 and parts[0].isdigit():
                parsed.append((int(parts[0]), parts[1].rstrip(".")))
        if parsed:
            parsed.sort(key=lambda x: x[0])
            smtp_host = parsed[0][1] or domain
    except Exception:
        # Any DNS failure (offline CI, no resolver) → fall back to the domain itself.
        smtp_host = domain
    smtp_ports = [25, 587, 465]
    if ports:
        try:
            smtp_ports = parse_ports(ports)
        except TargetError:
            pass
    return Target(
        kind=HOSTPORT, raw=email, host=smtp_host, email=email,
        port=smtp_ports[0], ports=smtp_ports,
        username=username, password=password,
    )


def resolve(
    *,
    positional: Optional[str] = None,
    repo: Optional[str] = None,
    url: Optional[str] = None,
    jwt: Optional[str] = None,
    api_key: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    email: Optional[str] = None,
    host_port: Optional[str] = None,
    ports: Optional[str] = None,
    auth_header: Optional[str] = None,
    auth_scheme: Optional[str] = None,
    default_repo: Optional[str] = None,
    local: bool = False,
    cidr: Optional[str] = None,
    max_hosts: Optional[int] = None,
) -> Target:
    """Turn CLI inputs into a single concrete :class:`Target`.

    Precedence: explicit local-introspection > network range (--cidr) > repo > email >
    creds > url > host:port > auto-detected positional > default workspace repo.
    (email is resolved before creds so `--email` combined with `--username/--password`
    yields an SMTP-AUTH target rather than silently dropping the email — BUG-8.)
    """
    has_basic = bool(username or password)
    has_token = bool(jwt or api_key)

    # 0. Explicit local host-introspection (container-escape / cloud-IMDS / IOC scan).
    if local:
        return Target(kind=LOCAL, raw="local")

    # 0b. Explicit network range / CIDR (via --cidr).
    if cidr:
        return _make_netrange(cidr, ports, max_hosts=max_hosts)

    # 1. Explicit repository (path or URL).
    if repo:
        return _make_repo(repo)

    # 1b. Email address => SMTP hostport target on the mail domain. Handled before plain
    #     credentials so that `--email` is not silently dropped when username/password are
    #     also supplied (BUG-8); any creds ride along for SMTP AUTH against the MX.
    if email:
        return _make_email_target(email, ports, username=username, password=password)

    # 2. Username/password => credentials target (a URL, if given, is what we
    #    validate them against).
    if has_basic:
        return Target(
            kind=CREDS, raw=(username or "creds"),
            url=url, jwt=jwt, api_key=api_key, username=username, password=password,
            cred_kind=_infer_cred_kind(username, password, jwt, api_key),
            auth_header=auth_header, auth_scheme=auth_scheme,
        )

    # 3. A URL is primarily a live-endpoint target; jwt/api-key ride along.
    if url:
        return Target(kind=URL, raw=url, url=url, jwt=jwt, api_key=api_key,
                      auth_header=auth_header, auth_scheme=auth_scheme)

    # 4. A token with no URL => credentials target (validate the token itself).
    if has_token:
        return Target(
            kind=CREDS, raw=(jwt or api_key or "token"),
            jwt=jwt, api_key=api_key,
            cred_kind=_infer_cred_kind(username, password, jwt, api_key),
            auth_header=auth_header, auth_scheme=auth_scheme,
        )

    # 5. Explicit host:port (+ optional --ports to override/extend).
    if host_port:
        host, primary = _resolve_host_and_ports(host_port, ports)
        return Target(kind=HOSTPORT, raw=host_port, host=host,
                      port=primary[0], ports=primary)

    # 6. A bare --ports needs a host from the positional value.
    if ports and positional:
        host = positional.strip().strip("[]")
        plist = parse_ports(ports)
        return Target(kind=HOSTPORT, raw=f"{host}:{ports}", host=host,
                      port=plist[0], ports=plist)

    # 7. Auto-detect a positional target.
    if positional:
        value = positional.strip()
        if os.path.isdir(value):
            return Target(kind=REPO, raw=value, root=os.path.abspath(value))
        if looks_like_email(value):
            return _make_email_target(value, ports)
        if looks_like_git_url(value):
            return _make_repo(value)
        if looks_like_netrange(value):
            return _make_netrange(value, ports, max_hosts=max_hosts)
        if looks_like_hostports(value):
            host, plist = _split_hostports(value)
            return Target(kind=HOSTPORT, raw=value, host=host,
                          port=plist[0], ports=plist)
        if looks_like_http_url(value):
            return Target(kind=URL, raw=value, url=value, jwt=jwt, api_key=api_key,
                          auth_header=auth_header, auth_scheme=auth_scheme)
        raise TargetError(
            f"could not interpret target {value!r}: not a directory, git URL, "
            "http(s) URL, email address, host:port, or CIDR/IP-range."
        )

    # 8. Fallback: the workspace repo that hosts this toolkit.
    if default_repo and os.path.isdir(default_repo):
        return Target(kind=REPO, raw=default_repo, root=os.path.abspath(default_repo))

    raise TargetError("no target supplied and no default repository available.")


def _resolve_host_and_ports(host_port: str, ports: Optional[str]):
    """From --host-port (host, host:port, or host:spec) and optional --ports."""
    value = host_port.strip()
    if looks_like_hostports(value):
        host, plist = _split_hostports(value)
        if ports:  # --ports overrides the inline spec
            plist = parse_ports(ports)
        return host, plist
    # No inline port => host only; --ports must supply them.
    host = value.strip("[]")
    if not ports:
        raise TargetError(f"not a valid host:port: {host_port!r} (or add --ports).")
    return host, parse_ports(ports)


# Default ports scanned across a network range when none are supplied — a compact,
# high-signal set covering web, remote-admin, datastores, container/k8s control planes.
_NETRANGE_DEFAULT_PORTS = (22, 80, 443, 2375, 3389, 5432, 6379, 6443, 8080, 8443,
                           9090, 9200, 10250)


def _make_netrange(value: str, ports: Optional[str], *,
                   max_hosts: Optional[int] = None) -> Target:
    """Build a NETRANGE target from a CIDR/range and optional ports.

    Ports come from (in order): an inline ``:portspec`` on the value, ``--ports``, then
    the compact default set. Enforces both the host cap and the hosts x ports product
    cap so a wide scan cannot expand unbounded.
    """
    value = value.strip()
    m = _NETRANGE_RE.match(value)
    if not m:
        raise TargetError(f"not a valid CIDR/IP-range: {value!r}.")
    net = m.group("net")
    inline_ports = m.group("ports")

    if ports:
        plist = parse_ports(ports)
    elif inline_ports:
        plist = parse_ports(inline_ports)
    else:
        plist = list(_NETRANGE_DEFAULT_PORTS)

    hosts = parse_hosts(net, max_hosts=max_hosts)

    product = len(hosts) * len(plist)
    if product > MAX_HOST_PORT_PRODUCT:
        raise TargetError(
            f"{value!r} expands to {len(hosts)} host(s) x {len(plist)} port(s) = {product} "
            f"probes (cap {MAX_HOST_PORT_PRODUCT}); narrow the range or port set.")

    return Target(kind=NETRANGE, raw=value, hosts=hosts,
                  ports=plist, port=plist[0], host=hosts[0])


def _make_repo(value: str) -> Target:
    value = value.strip()
    if os.path.isdir(value):
        return Target(kind=REPO, raw=value, root=os.path.abspath(value))
    if looks_like_git_url(value) or looks_like_http_url(value):
        path = clone_repo(value)
        return Target(kind=REPO, raw=value, root=path, is_temp_clone=True)
    raise TargetError(f"repository {value!r} is neither an existing directory nor a clonable URL.")


def _split_hostport(value: str):
    m = _HOSTPORT_RE.match(value.strip())
    host = m.group("host").strip("[]")
    port = int(m.group("port"))
    return host, port


def _split_hostports(value: str):
    m = _HOSTPORTS_RE.match(value.strip())
    host = m.group("host").strip("[]")
    plist = parse_ports(m.group("ports"))
    return host, plist


# ---------------------------------------------------------------------------
# JSON target-file resolution
# ---------------------------------------------------------------------------
def resolve_from_dict(entry: dict, *, max_hosts: Optional[int] = None) -> List[Target]:
    """Resolve a structured dict (from a JSON targets file) into one or more Targets.

    Supported keys (all optional; at least one must be present):
        - ``url``       — HTTP(S) endpoint (produces a URL target).
        - ``host``      — hostname/IP (combined with ``port``/``ports`` → hostport).
        - ``port``      — single port (int or str).
        - ``ports``     — port spec string or list of ints.
        - ``email``     — email address (domain extracted → hostport on SMTP ports).
        - ``cidr``      — network range (produces a NETRANGE target).
        - ``repo``      — local path or git URL (produces a REPO target).
        - ``jwt``       — JWT token (attached to URL target or standalone creds).
        - ``api_key``   — API key (attached to URL target or standalone creds).
        - ``username``  — username for credential testing.
        - ``password``  — password for credential testing.
        - ``auth_header`` — custom auth header name.
        - ``auth_scheme`` — auth scheme prefix.

    Returns a list because one entry can produce multiple targets (e.g. an email
    generates both an SMTP hostport and optionally a URL target if ``url`` is also set).
    """
    targets: List[Target] = []
    url = entry.get("url")
    host = entry.get("host")
    port = entry.get("port")
    ports_spec = entry.get("ports")
    email = entry.get("email")
    cidr = entry.get("cidr")
    repo = entry.get("repo")
    jwt = entry.get("jwt")
    api_key = entry.get("api_key") or entry.get("apiKey")
    username = entry.get("username") or entry.get("user")
    password = entry.get("password") or entry.get("pass")
    auth_header = entry.get("auth_header") or entry.get("authHeader")
    auth_scheme = entry.get("auth_scheme") or entry.get("authScheme")

    # Resolve ports — a non-numeric port in the JSON must produce a clear TargetError,
    # not an uncaught ValueError that aborts the whole targets-file load (BUG-23).
    plist: Optional[List[int]] = None
    try:
        if ports_spec:
            if isinstance(ports_spec, list):
                plist = sorted(int(p) for p in ports_spec if 0 < int(p) <= 65535)
            elif isinstance(ports_spec, (int, float)):
                plist = [int(ports_spec)]
            else:
                plist = parse_ports(str(ports_spec))
        elif port:
            plist = [int(port)]
    except (ValueError, TypeError) as exc:
        raise TargetError(
            f"invalid port in targets entry {entry!r}: {exc}"
        ) from exc

    # 1. Email → extract domain for SMTP probing
    if email:
        if "@" in email:
            domain = email.split("@", 1)[1].strip()
        else:
            domain = email.strip()
        smtp_ports = plist or [25, 587, 465]
        targets.append(Target(
            kind=HOSTPORT, raw=email, host=domain, email=email,
            port=smtp_ports[0], ports=smtp_ports,
            username=username, password=password,
        ))
        # Auto-add URL companion for the email domain when no explicit URL is given,
        # so the domain's web surface is also scanned (not just the SMTP service).
        if not url:
            _companion_url = f"https://{domain}"
            targets.append(Target(
                kind=URL, raw=_companion_url, url=_companion_url,
                jwt=jwt, api_key=api_key,
                username=username, password=password,
                auth_header=auth_header, auth_scheme=auth_scheme,
                email=email,
            ))

    # 2. URL target — normalize missing scheme to https://
    if url:
        if "://" not in url:
            url = f"https://{url}"
        targets.append(Target(
            kind=URL, raw=url, url=url,
            jwt=jwt, api_key=api_key,
            username=username, password=password,
            auth_header=auth_header, auth_scheme=auth_scheme,
            email=email,
        ))

    # 3. Host:port target (if not already covered by email)
    if host and not email:
        h = host.strip().strip("[]")
        hp = plist or [80, 443]
        targets.append(Target(
            kind=HOSTPORT, raw=f"{h}:{hp[0]}", host=h,
            port=hp[0], ports=hp,
            username=username, password=password,
            jwt=jwt, api_key=api_key,
            auth_header=auth_header, auth_scheme=auth_scheme,
        ))

    # 4. Network range
    if cidr:
        targets.append(_make_netrange(cidr, str(",".join(str(p) for p in plist)) if plist else None,
                                      max_hosts=max_hosts))

    # 5. Repository
    if repo:
        targets.append(_make_repo(repo))

    # 6. Standalone credentials (username/password/jwt without url or host)
    if not targets and (username or password or jwt or api_key):
        targets.append(Target(
            kind=CREDS, raw=(username or jwt or api_key or "creds"),
            url=url, jwt=jwt, api_key=api_key,
            username=username, password=password, email=email,
            cred_kind=_infer_cred_kind(username, password, jwt, api_key),
            auth_header=auth_header, auth_scheme=auth_scheme,
        ))

    if not targets:
        raise TargetError(f"JSON entry has no actionable fields: {entry!r}")

    return targets

