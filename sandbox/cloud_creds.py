"""Discovery-driven cloud credential inventory.

A real attacker who lands on a compromised host does not bring cloud keys with them —
they inherit whatever the host already has: an instance/VM **metadata role**, an
on-disk profile (``~/.aws/credentials``, ``~/.config/gcloud``), or a credential
**environment variable**. This module reproduces exactly that discovery, and nothing
more, so the credentialed cloud path can model that attacker faithfully.

Hard contract
-------------
* **Discovery only.** This module reads what is already present; it never writes,
  rotates, or transmits credentials anywhere except into the in-memory inventory the
  cloud modules consume.
* **Must run before the credential guard scrubs the environment.** ``main.py`` calls
  :func:`discover` *before* ``credential_guard.scrub()`` so the inventory captures the
  ambient state; the guard then scrubs env/files/IMDS so no *other* module or SDK can
  reuse them. Only the explicitly opt-in cloud modules read this inventory.
* **Activation gate.** If nothing is discovered the inventory is empty and the cloud
  path stays dormant — the credentialed cloud modules refuse to run.

Credential *values* are held in memory only and are never written to the report; the
report records the *source* (e.g. "instance metadata role ``my-role``") and a masked
key id, never the secret.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import config
except Exception:  # pragma: no cover
    config = None  # type: ignore

# Imported lazily inside functions to avoid a hard dependency at import time.
_IMDS_TIMEOUT = 2.0


@dataclass
class CloudCredential:
    """One usable cloud credential set discovered on the host."""

    provider: str                       # "aws" | "gcp" | "azure"
    source: str                         # human description of where it came from
    secret: Dict[str, str] = field(default_factory=dict)   # in-memory only, never reported
    region: Optional[str] = None
    identity_hint: Optional[str] = None  # e.g. role name / account / project (non-secret)

    def masked(self) -> str:
        """A non-secret, reportable description (never reveals the secret)."""
        key = self.secret.get("access_key") or self.secret.get("client_id") or ""
        tail = f" (key …{key[-4:]})" if len(key) >= 4 else ""
        return f"{self.provider}: {self.source}{tail}"


@dataclass
class CloudInventory:
    """All cloud credentials discovered on the host."""

    credentials: List[CloudCredential] = field(default_factory=list)
    sources_checked: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.credentials)

    def for_provider(self, provider: str) -> List[CloudCredential]:
        return [c for c in self.credentials if c.provider == provider]

    def providers(self) -> List[str]:
        seen: List[str] = []
        for c in self.credentials:
            if c.provider not in seen:
                seen.append(c.provider)
        return seen


# ---------------------------------------------------------------------------
# AWS discovery
# ---------------------------------------------------------------------------
def _aws_from_env() -> Optional[CloudCredential]:
    ak = os.environ.get("AWS_ACCESS_KEY_ID")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if ak and sk:
        secret = {"access_key": ak, "secret_key": sk}
        tok = os.environ.get("AWS_SESSION_TOKEN") or os.environ.get("AWS_SECURITY_TOKEN")
        if tok:
            secret["session_token"] = tok
        return CloudCredential(
            provider="aws", source="AWS_* environment variables", secret=secret,
            region=os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION"),
        )
    return None


def _aws_from_files() -> List[CloudCredential]:
    import configparser
    creds_path = os.path.expanduser("~/.aws/credentials")
    out: List[CloudCredential] = []
    if not os.path.isfile(creds_path):
        return out
    parser = configparser.ConfigParser()
    try:
        parser.read(creds_path)
    except Exception:
        return out
    for section in parser.sections():
        ak = parser.get(section, "aws_access_key_id", fallback=None)
        sk = parser.get(section, "aws_secret_access_key", fallback=None)
        if ak and sk:
            secret = {"access_key": ak, "secret_key": sk}
            tok = parser.get(section, "aws_session_token", fallback=None)
            if tok:
                secret["session_token"] = tok
            out.append(CloudCredential(
                provider="aws", source=f"~/.aws/credentials [{section}]", secret=secret,
            ))
    return out


def _aws_from_imds() -> Optional[CloudCredential]:
    """Fetch instance-profile creds from IMDS (IMDSv2 first, then IMDSv1)."""
    from . import netutil  # local import: keeps discovery import-light
    base = (getattr(config, "AWS_IMDS_BASE", "http://169.254.169.254")
            if config else "http://169.254.169.254")
    token_header: Dict[str, str] = {}
    # IMDSv2: obtain a session token (PUT). Best-effort; fall back to v1.
    st, tok, _ = netutil.http_request(
        f"{base}/latest/api/token", "PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        timeout=_IMDS_TIMEOUT,
    )
    if st and 200 <= st < 300 and tok:
        token_header = {"X-aws-ec2-metadata-token": tok.strip()}

    role_url = f"{base}/latest/meta-data/iam/security-credentials/"
    st, roles, _ = netutil.http_get(role_url, headers=token_header, timeout=_IMDS_TIMEOUT)
    if not st or st >= 300 or not roles.strip():
        return None
    role = roles.strip().splitlines()[0].strip()
    st, body, _ = netutil.http_get(role_url + role, headers=token_header, timeout=_IMDS_TIMEOUT)
    if not st or st >= 300:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    ak, sk = data.get("AccessKeyId"), data.get("SecretAccessKey")
    if not (ak and sk):
        return None
    secret = {"access_key": ak, "secret_key": sk}
    if data.get("Token"):
        secret["session_token"] = data["Token"]
    return CloudCredential(
        provider="aws", source=f"EC2 instance metadata role '{role}'",
        secret=secret, identity_hint=role,
    )


# ---------------------------------------------------------------------------
# GCP discovery
# ---------------------------------------------------------------------------
def _gcp_from_files() -> List[CloudCredential]:
    adc = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    out: List[CloudCredential] = []
    if os.path.isfile(adc):
        try:
            with open(adc, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            data = {}
        if data:
            out.append(CloudCredential(
                provider="gcp", source="~/.config/gcloud/application_default_credentials.json",
                secret={"adc": json.dumps(data)},
                identity_hint=data.get("client_email") or data.get("type"),
            ))
    return out


def _gcp_from_imds() -> Optional[CloudCredential]:
    from . import netutil
    base = (getattr(config, "GCP_IMDS_BASE", "http://metadata.google.internal")
            if config else "http://metadata.google.internal")
    hdr = {"Metadata-Flavor": "Google"}
    st, body, _ = netutil.http_get(
        f"{base}/computeMetadata/v1/instance/service-accounts/default/token",
        headers=hdr, timeout=_IMDS_TIMEOUT)
    if not st or st >= 300:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not data.get("access_token"):
        return None
    # Also grab the SA email for a non-secret identity hint.
    _, email, _ = netutil.http_get(
        f"{base}/computeMetadata/v1/instance/service-accounts/default/email",
        headers=hdr, timeout=_IMDS_TIMEOUT)
    return CloudCredential(
        provider="gcp", source="GCE instance metadata service-account token",
        secret={"access_token": data["access_token"]},
        identity_hint=(email or "").strip() or None,
    )


# ---------------------------------------------------------------------------
# Azure discovery
# ---------------------------------------------------------------------------
def _azure_from_imds() -> Optional[CloudCredential]:
    from . import netutil
    base = (getattr(config, "AZURE_IMDS_BASE", "http://169.254.169.254")
            if config else "http://169.254.169.254")
    hdr = {"Metadata": "true"}
    st, body, _ = netutil.http_get(
        f"{base}/metadata/identity/oauth2/token"
        "?api-version=2018-02-01&resource=https://management.azure.com/",
        headers=hdr, timeout=_IMDS_TIMEOUT)
    if not st or st >= 300:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not data.get("access_token"):
        return None
    return CloudCredential(
        provider="azure", source="Azure IMDS managed-identity token",
        secret={"access_token": data["access_token"]},
    )


def _azure_from_files() -> List[CloudCredential]:
    tokens = os.path.expanduser("~/.azure/accessTokens.json")
    out: List[CloudCredential] = []
    if os.path.isfile(tokens):
        try:
            with open(tokens, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            data = None
        if data:
            out.append(CloudCredential(
                provider="azure", source="~/.azure/accessTokens.json",
                secret={"tokens": json.dumps(data)},
            ))
    return out


# ---------------------------------------------------------------------------
# Top-level discovery
# ---------------------------------------------------------------------------
def discover(*, probe_imds: bool = True) -> CloudInventory:
    """Discover ambient cloud credentials. MUST run before the credential guard scrub.

    ``probe_imds`` can be disabled (e.g. in tests) to skip link-local metadata calls.
    """
    inv = CloudInventory()

    # AWS
    inv.sources_checked.append("aws:env")
    env_aws = _aws_from_env()
    if env_aws:
        inv.credentials.append(env_aws)
    inv.sources_checked.append("aws:~/.aws/credentials")
    inv.credentials.extend(_aws_from_files())

    # GCP
    inv.sources_checked.append("gcp:adc")
    inv.credentials.extend(_gcp_from_files())

    # Azure
    inv.sources_checked.append("azure:~/.azure")
    inv.credentials.extend(_azure_from_files())

    if probe_imds:
        for label, fn in (("aws:imds", _aws_from_imds),
                          ("gcp:imds", _gcp_from_imds),
                          ("azure:imds", _azure_from_imds)):
            inv.sources_checked.append(label)
            try:
                cred = fn()
            except Exception:
                cred = None
            if cred:
                inv.credentials.append(cred)

    # Extended providers (OVH, Scaleway, OCI, Nutanix, DO, Hetzner, Linode, Vultr, Alibaba, Confluent)
    try:
        from sandbox.cloud_creds_extended import discover_all as _discover_extended
        for ext_cred in _discover_extended():
            inv.sources_checked.append(f"{ext_cred.provider}:{ext_cred.source}")
            inv.credentials.append(ext_cred)
    except Exception:
        pass  # extended module may not be importable in all environments

    return inv
