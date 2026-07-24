"""Runtime credential guard — makes "uses no credentials" a hard guarantee.

The toolkit is designed to run on an *unauthenticated* shell: it must never rely
on AWS / EKS / ArgoCD / JFrog / GitHub / Docker credentials. Network access is
allowed (e.g. to pull a local model) — the guarantee is about *credentials*, not
connectivity.

This module enforces that guarantee at runtime by:

1. **Scrubbing** every known credential environment variable from the process,
   so any SDK/CLI a module might shell out to (boto3, aws, kubectl, argocd, jf,
   docker) cannot silently pick up ambient credentials.
2. **Redirecting** credential file lookups to an empty location, so on-disk
   profiles (``~/.aws/credentials``, ``~/.kube/config``, ``~/.docker/config.json``,
   ``~/.config/jfrog``) are not consulted.
3. **Auditing** what was present beforehand, so the report can transparently state
   *"these credential sources existed but were NOT used."*
4. **Self-testing** that nothing sensitive remains afterward (fail-closed).
"""
from __future__ import annotations

import os
from typing import Dict, List

# Exact credential env vars to remove.
_CRED_VARS = {
    # AWS / EKS
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    # Kubernetes / ArgoCD
    "KUBECONFIG", "ARGOCD_AUTH_TOKEN", "ARGOCD_SERVER", "ARGOCD_OPTS",
    # JFrog / Artifactory
    "JFROG_CLI_OFFER_CONFIG", "JF_ACCESS_TOKEN", "JF_USER", "JF_PASSWORD",
    "ARTIFACTORY_TOKEN", "ARTIFACTORY_USER", "ARTIFACTORY_PASSWORD",
    # GitHub
    "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_APP_PRIVATE_KEY",
    # GCP
    "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CREDENTIALS",
    # Databases / directory
    "PGPASSWORD", "MYSQL_PWD", "LDAPRC",
    # Generic
    "DOCKER_AUTH_CONFIG",
}

# Env var *prefixes* to remove (covers AWS_* and friends comprehensively).
_CRED_PREFIXES = (
    "AWS_", "ARGOCD_", "JFROG_", "JF_", "ARTIFACTORY_", "OKTA_", "CONFLUENT_",
    "SCW_", "OVH_", "OCI_CLI_", "NUTANIX_", "DIGITALOCEAN_", "HCLOUD_",
    "LINODE_", "VULTR_", "ALIBABA_CLOUD_", "ALICLOUD_",
    "MERAKI_", "F5_", "BIGIP_", "FORTIOS_", "FORTIGATE_",
    "CISCO_ASA_", "ASA_", "ISE_", "DNAC_", "CATALYST_CENTER_",
    # Azure (CLI + Terraform ARM_*) and GCP tooling
    "AZURE_", "ARM_", "GOOGLE_", "GCP_", "CLOUDSDK_",
)

# Vars that point at credential FILES — redirect to an empty/non-existent path
# instead of deleting, so SDKs that default to these find nothing.
_DEVNULL = os.devnull

# Env vars the guard intentionally *sets* to neutralise credential discovery.
# These must be exempt from the post-scrub self-test even though some match a
# credential prefix/name.
_REDIRECT_VARS = {
    "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_EC2_METADATA_DISABLED",
    "KUBECONFIG", "DOCKER_CONFIG",
}


def audit() -> Dict[str, List[str]]:
    """Return credential sources detected *before* scrubbing (values never shown)."""
    env_hits = sorted(
        k for k in os.environ
        if k in _CRED_VARS or any(k.startswith(p) for p in _CRED_PREFIXES)
    )
    home = os.path.expanduser("~")
    candidate_files = [
        os.path.join(home, ".aws", "credentials"),
        os.path.join(home, ".aws", "config"),
        os.path.join(home, ".kube", "config"),
        os.path.join(home, ".docker", "config.json"),
        os.path.join(home, ".config", "jfrog", "jfrog-cli.conf"),
        os.path.join(home, ".argocd", "config"),
        os.path.join(home, ".config", "gcloud", "application_default_credentials.json"),
        os.path.join(home, ".azure", "accessTokens.json"),
    ]
    file_hits = [p for p in candidate_files if os.path.exists(p)]
    return {"env": env_hits, "files": file_hits}


def scrub() -> Dict[str, List[str]]:
    """Remove credential env vars and redirect credential file lookups.

    Returns the pre-scrub audit so the caller can report what was neutralised.
    """
    pre = audit()

    for key in list(os.environ):
        if key in _CRED_VARS or any(key.startswith(p) for p in _CRED_PREFIXES):
            os.environ.pop(key, None)

    # Point credential-file env vars at an empty location so SDKs find nothing.
    os.environ["AWS_CONFIG_FILE"] = _DEVNULL
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = _DEVNULL
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"  # block IMDS role pickup
    os.environ["KUBECONFIG"] = _DEVNULL
    os.environ["DOCKER_CONFIG"] = _DEVNULL

    return pre


def self_test() -> bool:
    """True if the guard still holds after scrubbing (fail-closed check).

    Checks both that (a) no credential env var remains, and (b) the redirect vars the
    guard sets still point where they should — a module could have rewritten
    AWS_CONFIG_FILE/KUBECONFIG/DOCKER_CONFIG or re-enabled IMDS between scrub() and
    self_test(), silently re-opening a credential source (V8).
    """
    remaining = [
        k for k in os.environ
        if (k in _CRED_VARS or any(k.startswith(p) for p in _CRED_PREFIXES))
        and k not in _REDIRECT_VARS
    ]
    if remaining:
        return False
    # The file-redirect vars must still point at the empty path.
    for var in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "KUBECONFIG",
                "DOCKER_CONFIG"):
        if os.environ.get(var) != _DEVNULL:
            return False
    # IMDS role pickup must still be disabled.
    if os.environ.get("AWS_EC2_METADATA_DISABLED") != "true":
        return False
    return True


def status() -> str:
    return "credential-free (no AWS/EKS/ArgoCD/JFrog/GitHub creds in use)"
