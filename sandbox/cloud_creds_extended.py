"""Extended cloud credential discovery for additional providers.

Discovers ambient credentials for cloud providers beyond AWS/GCP/Azure:
* OVH Public Cloud (OpenStack)
* Scaleway
* Oracle Cloud Infrastructure (OCI)
* Nutanix
* DigitalOcean
* Hetzner Cloud
* Linode / Akamai
* Vultr
* Alibaba Cloud
* Confluent Cloud

Discovery sources (per provider):
* Environment variables (provider-specific prefixes)
* On-disk credential/config files (standard paths)
* Instance metadata services (where applicable)

This module extends sandbox/cloud_creds.py with the same security model:
* Credentials are held in memory only, never written to reports.
* Discovery runs BEFORE the credential guard scrubs the environment.
* Only handed to the credentialed cloud modules (opt-in via --use-discovered-cloud-creds).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import config
except Exception:  # pragma: no cover
    config = None  # type: ignore


@dataclass
class ExtendedCloudCredential:
    """A discovered credential for an extended cloud provider."""
    provider: str           # e.g. "scaleway", "ovh", "oci", ...
    source: str             # where it was found (env var name, file path, etc.)
    secret: str             # the credential value (token, key, etc.)
    identity: str = ""      # user/project/org identifier if known
    endpoint: str = ""      # API endpoint if discoverable
    extra: dict = field(default_factory=dict)  # provider-specific metadata

    def masked(self) -> str:
        """Return a masked representation for logging (never expose the secret)."""
        s = self.secret
        if len(s) > 8:
            masked_val = s[:4] + "…" + s[-4:]
        else:
            masked_val = "***"
        return f"{self.provider}({self.source}={masked_val})"


# ===========================================================================
# Provider-specific discovery functions
# ===========================================================================

def _discover_ovh() -> List[ExtendedCloudCredential]:
    """Discover OVH/OpenStack credentials."""
    creds: List[ExtendedCloudCredential] = []

    # Environment variables
    token = os.environ.get("OS_TOKEN") or os.environ.get("OS_AUTH_TOKEN")
    if token:
        creds.append(ExtendedCloudCredential(
            provider="ovh", source="OS_TOKEN", secret=token,
            endpoint=os.environ.get("OS_AUTH_URL", ""),
            identity=os.environ.get("OS_PROJECT_NAME", ""),
        ))

    app_key = os.environ.get("OVH_APPLICATION_KEY")
    app_secret = os.environ.get("OVH_APPLICATION_SECRET")
    if app_key and app_secret:
        creds.append(ExtendedCloudCredential(
            provider="ovh", source="OVH_APPLICATION_KEY", secret=app_secret,
            identity=app_key,
            endpoint=getattr(config, "OVH_API_ENDPOINT", "https://api.ovh.com/1.0"),
        ))

    # Config files
    for cred_file in getattr(config, "OVH_CRED_FILES", ()):
        path = Path(os.path.expanduser(cred_file))
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")[:2048]
                if "password" in content.lower() or "token" in content.lower():
                    creds.append(ExtendedCloudCredential(
                        provider="ovh", source=str(path), secret="[file-credential]",
                        extra={"file": str(path)},
                    ))
            except OSError:
                pass

    return creds


def _discover_scaleway() -> List[ExtendedCloudCredential]:
    """Discover Scaleway credentials."""
    creds: List[ExtendedCloudCredential] = []

    secret_key = os.environ.get("SCW_SECRET_KEY")
    if secret_key:
        creds.append(ExtendedCloudCredential(
            provider="scaleway", source="SCW_SECRET_KEY", secret=secret_key,
            identity=os.environ.get("SCW_ACCESS_KEY", ""),
            endpoint=getattr(config, "SCW_API_ENDPOINT", "https://api.scaleway.com"),
            extra={"org": os.environ.get("SCW_DEFAULT_ORGANIZATION_ID", "")},
        ))

    for cred_file in getattr(config, "SCW_CRED_FILES", ()):
        path = Path(os.path.expanduser(cred_file))
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")[:2048]
                if "secret_key" in content:
                    creds.append(ExtendedCloudCredential(
                        provider="scaleway", source=str(path), secret="[file-credential]",
                        extra={"file": str(path)},
                    ))
            except OSError:
                pass

    return creds


def _discover_oci() -> List[ExtendedCloudCredential]:
    """Discover Oracle Cloud Infrastructure credentials."""
    creds: List[ExtendedCloudCredential] = []

    tenancy = os.environ.get("OCI_CLI_TENANCY")
    key_file = os.environ.get("OCI_CLI_KEY_FILE")
    if tenancy and key_file:
        creds.append(ExtendedCloudCredential(
            provider="oci", source="OCI_CLI_TENANCY", secret=key_file,
            identity=tenancy,
            extra={"user": os.environ.get("OCI_CLI_USER", ""),
                   "fingerprint": os.environ.get("OCI_CLI_FINGERPRINT", "")},
        ))

    for cred_file in getattr(config, "OCI_CRED_FILES", ()):
        path = Path(os.path.expanduser(cred_file))
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")[:2048]
                if "key_file" in content or "tenancy" in content:
                    creds.append(ExtendedCloudCredential(
                        provider="oci", source=str(path), secret="[file-credential]",
                        extra={"file": str(path)},
                    ))
            except OSError:
                pass

    return creds


def _discover_nutanix() -> List[ExtendedCloudCredential]:
    """Discover Nutanix credentials."""
    creds: List[ExtendedCloudCredential] = []

    username = os.environ.get("NUTANIX_USERNAME")
    password = os.environ.get("NUTANIX_PASSWORD")
    endpoint = os.environ.get("NUTANIX_ENDPOINT")
    if username and password:
        creds.append(ExtendedCloudCredential(
            provider="nutanix", source="NUTANIX_USERNAME/PASSWORD", secret=password,
            identity=username, endpoint=endpoint or "",
        ))

    return creds


def _discover_digitalocean() -> List[ExtendedCloudCredential]:
    """Discover DigitalOcean credentials."""
    creds: List[ExtendedCloudCredential] = []

    token = os.environ.get("DIGITALOCEAN_ACCESS_TOKEN") or os.environ.get("DIGITALOCEAN_TOKEN")
    if token:
        creds.append(ExtendedCloudCredential(
            provider="digitalocean", source="DIGITALOCEAN_ACCESS_TOKEN", secret=token,
            endpoint=getattr(config, "DO_API_ENDPOINT", "https://api.digitalocean.com/v2"),
        ))

    for cred_file in getattr(config, "DO_CRED_FILES", ()):
        path = Path(os.path.expanduser(cred_file))
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")[:2048]
                if "access-token" in content:
                    creds.append(ExtendedCloudCredential(
                        provider="digitalocean", source=str(path), secret="[file-credential]",
                        extra={"file": str(path)},
                    ))
            except OSError:
                pass

    return creds


def _discover_hetzner() -> List[ExtendedCloudCredential]:
    """Discover Hetzner Cloud credentials."""
    creds: List[ExtendedCloudCredential] = []

    token = os.environ.get("HCLOUD_TOKEN")
    if token:
        creds.append(ExtendedCloudCredential(
            provider="hetzner", source="HCLOUD_TOKEN", secret=token,
            endpoint=getattr(config, "HCLOUD_API_ENDPOINT", "https://api.hetzner.cloud/v1"),
        ))

    return creds


def _discover_linode() -> List[ExtendedCloudCredential]:
    """Discover Linode/Akamai credentials."""
    creds: List[ExtendedCloudCredential] = []

    token = os.environ.get("LINODE_TOKEN") or os.environ.get("LINODE_CLI_TOKEN")
    if token:
        creds.append(ExtendedCloudCredential(
            provider="linode", source="LINODE_TOKEN", secret=token,
            endpoint=getattr(config, "LINODE_API_ENDPOINT", "https://api.linode.com/v4"),
        ))

    for cred_file in getattr(config, "LINODE_CRED_FILES", ()):
        path = Path(os.path.expanduser(cred_file))
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")[:2048]
                if "token" in content.lower():
                    creds.append(ExtendedCloudCredential(
                        provider="linode", source=str(path), secret="[file-credential]",
                        extra={"file": str(path)},
                    ))
            except OSError:
                pass

    return creds


def _discover_vultr() -> List[ExtendedCloudCredential]:
    """Discover Vultr credentials."""
    creds: List[ExtendedCloudCredential] = []

    key = os.environ.get("VULTR_API_KEY")
    if key:
        creds.append(ExtendedCloudCredential(
            provider="vultr", source="VULTR_API_KEY", secret=key,
            endpoint=getattr(config, "VULTR_API_ENDPOINT", "https://api.vultr.com/v2"),
        ))

    return creds


def _discover_alibaba() -> List[ExtendedCloudCredential]:
    """Discover Alibaba Cloud credentials."""
    creds: List[ExtendedCloudCredential] = []

    access_key = (os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID")
                  or os.environ.get("ALICLOUD_ACCESS_KEY"))
    secret_key = (os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
                  or os.environ.get("ALICLOUD_SECRET_KEY"))
    if access_key and secret_key:
        creds.append(ExtendedCloudCredential(
            provider="alibaba", source="ALIBABA_CLOUD_ACCESS_KEY_ID", secret=secret_key,
            identity=access_key,
        ))

    for cred_file in getattr(config, "ALIBABA_CRED_FILES", ()):
        path = Path(os.path.expanduser(cred_file))
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")[:2048]
                if "access_key" in content:
                    creds.append(ExtendedCloudCredential(
                        provider="alibaba", source=str(path), secret="[file-credential]",
                        extra={"file": str(path)},
                    ))
            except OSError:
                pass

    return creds


def _discover_confluent_cloud() -> List[ExtendedCloudCredential]:
    """Discover Confluent Cloud credentials."""
    creds: List[ExtendedCloudCredential] = []

    api_key = os.environ.get("CONFLUENT_CLOUD_API_KEY")
    api_secret = os.environ.get("CONFLUENT_CLOUD_API_SECRET")
    if api_key and api_secret:
        creds.append(ExtendedCloudCredential(
            provider="confluent_cloud", source="CONFLUENT_CLOUD_API_KEY", secret=api_secret,
            identity=api_key,
            endpoint=getattr(config, "CONFLUENT_CLOUD_API_ENDPOINT",
                             "https://api.confluent.cloud"),
        ))

    for cred_file in getattr(config, "CONFLUENT_CLOUD_CRED_FILES", ()):
        path = Path(os.path.expanduser(cred_file))
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")[:2048]
                if "api_key" in content or "api_secret" in content:
                    creds.append(ExtendedCloudCredential(
                        provider="confluent_cloud", source=str(path), secret="[file-credential]",
                        extra={"file": str(path)},
                    ))
            except OSError:
                pass

    return creds


# ===========================================================================
# Network Appliance Credential Discovery
# ===========================================================================

def _discover_f5() -> List[ExtendedCloudCredential]:
    """Discover F5 BIG-IP credentials."""
    creds: List[ExtendedCloudCredential] = []
    host = os.environ.get("F5_HOST", "") or os.environ.get("BIGIP_HOST", "")
    user = os.environ.get("F5_USER", "") or os.environ.get("BIGIP_USER", "admin")
    password = os.environ.get("F5_PASSWORD", "") or os.environ.get("BIGIP_PASSWORD", "")
    token = os.environ.get("F5_TOKEN", "") or os.environ.get("BIGIP_TOKEN", "")

    if host and (password or token):
        creds.append(ExtendedCloudCredential(
            provider="f5", source="F5_HOST+F5_PASSWORD" if password else "F5_HOST+F5_TOKEN",
            secret=password or token, identity=user, endpoint=host,
        ))
    return creds


def _discover_fortinet() -> List[ExtendedCloudCredential]:
    """Discover Fortinet FortiGate credentials."""
    creds: List[ExtendedCloudCredential] = []
    host = os.environ.get("FORTIOS_HOST", "") or os.environ.get("FORTIGATE_HOST", "")
    token = os.environ.get("FORTIOS_ACCESS_TOKEN", "") or os.environ.get("FORTIGATE_TOKEN", "")

    if host and token:
        creds.append(ExtendedCloudCredential(
            provider="fortinet", source="FORTIOS_ACCESS_TOKEN",
            secret=token, endpoint=host,
        ))
    return creds


def _discover_meraki() -> List[ExtendedCloudCredential]:
    """Discover Cisco Meraki Dashboard API credentials."""
    creds: List[ExtendedCloudCredential] = []
    api_key = os.environ.get("MERAKI_DASHBOARD_API_KEY", "")

    if api_key:
        creds.append(ExtendedCloudCredential(
            provider="meraki", source="MERAKI_DASHBOARD_API_KEY",
            secret=api_key,
        ))
    return creds


def _discover_cisco_asa() -> List[ExtendedCloudCredential]:
    """Discover Cisco ASA/FTD credentials."""
    creds: List[ExtendedCloudCredential] = []
    host = os.environ.get("CISCO_ASA_HOST", "") or os.environ.get("ASA_HOST", "")
    user = os.environ.get("CISCO_ASA_USER", "") or os.environ.get("ASA_USER", "admin")
    password = os.environ.get("CISCO_ASA_PASSWORD", "") or os.environ.get("ASA_PASSWORD", "")

    if host and password:
        creds.append(ExtendedCloudCredential(
            provider="cisco_asa", source="CISCO_ASA_HOST",
            secret=password, identity=user, endpoint=host,
        ))
    return creds


def _discover_cisco_ise() -> List[ExtendedCloudCredential]:
    """Discover Cisco ISE credentials."""
    creds: List[ExtendedCloudCredential] = []
    host = os.environ.get("ISE_HOST", "")
    user = os.environ.get("ISE_USER", "") or os.environ.get("ISE_USERNAME", "")
    password = os.environ.get("ISE_PASSWORD", "")

    if host and user and password:
        creds.append(ExtendedCloudCredential(
            provider="cisco_ise", source="ISE_HOST",
            secret=password, identity=user, endpoint=host,
        ))
    return creds


def _discover_catalyst_center() -> List[ExtendedCloudCredential]:
    """Discover Cisco Catalyst Center (DNAC) credentials."""
    creds: List[ExtendedCloudCredential] = []
    host = os.environ.get("DNAC_HOST", "") or os.environ.get("CATALYST_CENTER_HOST", "")
    user = os.environ.get("DNAC_USER", "") or os.environ.get("CATALYST_CENTER_USER", "")
    password = os.environ.get("DNAC_PASSWORD", "") or os.environ.get("CATALYST_CENTER_PASSWORD", "")

    if host and user and password:
        creds.append(ExtendedCloudCredential(
            provider="catalyst_center", source="DNAC_HOST",
            secret=password, identity=user, endpoint=host,
        ))
    return creds


# ===========================================================================
# Public API
# ===========================================================================

_DISCOVER_FUNCS = {
    "ovh": _discover_ovh,
    "scaleway": _discover_scaleway,
    "oci": _discover_oci,
    "nutanix": _discover_nutanix,
    "digitalocean": _discover_digitalocean,
    "hetzner": _discover_hetzner,
    "linode": _discover_linode,
    "vultr": _discover_vultr,
    "alibaba": _discover_alibaba,
    "confluent_cloud": _discover_confluent_cloud,
    "f5": _discover_f5,
    "fortinet": _discover_fortinet,
    "meraki": _discover_meraki,
    "cisco_asa": _discover_cisco_asa,
    "cisco_ise": _discover_cisco_ise,
    "catalyst_center": _discover_catalyst_center,
}


def discover_all() -> List[ExtendedCloudCredential]:
    """Discover credentials for all extended cloud providers.

    Returns a list of discovered credentials (may be empty).
    """
    all_creds: List[ExtendedCloudCredential] = []
    for provider, func in _DISCOVER_FUNCS.items():
        try:
            creds = func()
            all_creds.extend(creds)
        except Exception:
            pass  # Never crash; discovery is best-effort
    return all_creds


def discover_provider(provider: str) -> List[ExtendedCloudCredential]:
    """Discover credentials for a specific provider."""
    func = _DISCOVER_FUNCS.get(provider)
    if not func:
        return []
    try:
        return func()
    except Exception:
        return []
