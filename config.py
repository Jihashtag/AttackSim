"""Central configuration: network timeouts, retries, limits, and identity.

Every module imports its tunables from here so behaviour is consistent and a
single edit changes the whole toolkit. Values are deliberately conservative to
keep the simulation non-destructive and time-bounded.

**Environment-variable overrides:** Every constant can be overridden at runtime via
an environment variable named ``SECTEST_<CONSTANT_NAME>``. For example, setting
``SECTEST_HTTP_TIMEOUT=12`` overrides ``HTTP_TIMEOUT`` to 12. Type coercion is
automatic (int, float, bool, tuple of strings, tuple of ints). Unknown env vars
are ignored. The runtime-mutable overlay (``config_runtime``) takes precedence for
values updated by discovery (e.g. VPC endpoints).
"""
from __future__ import annotations

import json as _json
import os as _os


def _env(name: str, default, *, cast=None):
    """Read a SECTEST_<name> env var, coercing to the type of *default*.

    Supports: int, float, bool, str, tuple(str), tuple(int), tuple(float).
    For tuples, the env value is JSON or comma-separated.
    """
    env_key = f"SECTEST_{name}"
    raw = _os.environ.get(env_key)
    if raw is None:
        return default
    if cast is not None:
        return cast(raw)
    if isinstance(default, bool):
        return raw.lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        try:
            return int(raw)
        except ValueError:
            return default
    if isinstance(default, float):
        try:
            return float(raw)
        except ValueError:
            return default
    if isinstance(default, tuple):
        # Try JSON first, then comma-separated
        try:
            val = _json.loads(raw)
            if isinstance(val, list):
                if default and isinstance(default[0], int):
                    return tuple(int(v) for v in val)
                if default and isinstance(default[0], float):
                    return tuple(float(v) for v in val)
                return tuple(str(v) for v in val)
        except (ValueError, TypeError):
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if default and isinstance(default[0], int):
                return tuple(int(p) for p in parts)
            if default and isinstance(default[0], float):
                return tuple(float(p) for p in parts)
            return tuple(parts)
    return raw


# -- identity ---------------------------------------------------------------
USER_AGENT = _env("USER_AGENT", "security_test/1.0 (+authorized-assessment)")

# -- HTTP (http_probe / cred_tester) ----------------------------------------
HTTP_TIMEOUT = 8           # per-request socket timeout (seconds)
HTTP_MAX_REDIRECTS = 5     # cap redirect chains (avoid loops / SSRF pivots)
HTTP_TOTAL_BUDGET = 30     # hard wall-clock budget for one module (seconds)

# -- Advanced recon (discovery + metadata extraction) ----------

# Web surface + cloud storage discovery
SITEMAP_FETCH_TIMEOUT = 10              # timeout per sitemap fetch (seconds)
SITEMAP_MAX_URLS = 5000                 # max URLs to process per sitemap
SITEMAP_MAX_REDIRECTS = 3               # max HTTP redirects to follow
STORAGE_PROBE_TIMEOUT = 5               # timeout per storage probe (seconds)
STORAGE_BRUTE_MAX = 1000                # max bucket names to attempt (brute-force limit)
CREDENTIAL_PROPAGATION_ENABLED = True   # enable credential routing to aggressive modules
CREDENTIAL_ROUTE_INTENSITY = "intrusive"  # min intensity to route credentials

# API and cloud metadata extraction
API_METADATA_MAX_PARAMETERS = 200       # max parameters to extract per endpoint
API_METADATA_MAX_ENDPOINTS = 60         # max endpoints to analyze
CLOUD_METADATA_EXTRACTION_ENABLED = True  # enable infrastructure metadata parsing
CLOUD_METADATA_MAX_ROLES = 100          # max IAM roles to track
CLOUD_METADATA_MAX_INSTANCES = 500      # max instances to track

# Credential routing and lateral movement planning
CREDENTIAL_ROUTING_INTEGRATION_ENABLED = True  # enable credential → module routing
CREDENTIAL_ESCALATION_MAX_DEPTH = 5     # max escalation hops (default propagation depth)
CREDENTIAL_QUEUE_RERUNS = True          # auto-queue module re-runs on credential discovery
LATERAL_MOVEMENT_PLANNING_ENABLED = True # plan attack paths using metadata + creds
CREDENTIAL_CACHE_DURATION = 0           # (seconds) 0 = clear immediately after use

# -- TCP / port scanning (port_probe / tls_grader) --------------------------
TCP_CONNECT_TIMEOUT_SWEEP = 2.0    # used when scanning many ports
TCP_CONNECT_TIMEOUT_SINGLE = 6.0   # used for a handful of ports
TCP_SWEEP_THRESHOLD = 8            # >this many ports => use the sweep timeout
BANNER_READ_TIMEOUT = 3            # passive banner read (seconds)
PORT_SCAN_MAX_WORKERS = 64         # bounded thread pool
PORT_SCAN_WALL_BUDGET = 120        # hard wall-clock budget for a full sweep
MAX_PORTS = 2048                   # safety cap on a single scan request

# -- network-range scanning (host_sweep / netrange fan-out) -----------------
MAX_HOSTS = 1024                   # safety cap on hosts expanded from a CIDR/range
MAX_HOST_PORT_PRODUCT = 65536      # cap on hosts x ports for a whole netrange run
HOST_SWEEP_PROBE_PORTS = (22, 80, 443, 3389, 6443, 8080)  # liveness probe-port set
HOST_SWEEP_CONNECT_TIMEOUT = 1.5   # per-probe connect timeout during discovery
HOST_SWEEP_MAX_WORKERS = 128       # bounded concurrency for the discovery sweep
HOST_SWEEP_WALL_BUDGET = 180       # hard wall-clock budget for host discovery
NETRANGE_WALL_BUDGET = 600         # hard wall-clock budget for a whole netrange run

# -- external-tool integrations (toolrunner: nmap / nuclei) -----------------
TOOL_DEFAULT_TIMEOUT = 120         # default per-invocation wall-clock budget (seconds)
TOOL_MAX_OUTPUT_BYTES = 2_000_000  # truncate captured stdout/stderr to this many bytes


# -- TLS --------------------------------------------------------------------
DEPRECATED_TLS = ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")

# -- path_probe -------------------------------------------------------------
PATH_PROBE_MAX = 60        # safety cap on the number of paths requested
PATH_PROBE_WALL_BUDGET = 45  # hard wall-clock budget for the whole sweep

# -- jwt_attacker -----------------------------------------------------------
JWT_FORGE_CLAIMS = {       # claims injected into forged tokens
    "sub": "attacker", "name": "Pentest Admin",
    "role": "ADMIN", "roles": ["ADMIN"], "scope": "admin",
    "admin": True, "iss": "security_test",
}

# -- llm/advisor (local Ollama) ---------------------------------------------
OLLAMA_DEFAULT_HOST = "http://localhost:11434"
# Ollama < 0.1.34 is vulnerable to CVE-2024-37032 ("Probllama", path-traversal RCE).
OLLAMA_MIN_SAFE_VERSION = (0, 1, 34)
LLM_PAYLOAD_MAX_CHARS = 12000   # truncate the findings JSON sent to the model

# -- active infra probes (k8s / kafka / services / metadata / argocd) --------
PROBE_TIMEOUT = 6              # per-endpoint timeout for the infra probes (seconds)
PROBE_WALL_BUDGET = 60        # hard wall-clock budget per infra-probe module
PROBE_MAX_WORKERS = 32        # bounded concurrency for multi-endpoint probes

# Default ports each infra probe inspects when none are supplied.
K8S_DEFAULT_PORTS = (6443, 8443, 10250, 10255, 2379)
KAFKA_DEFAULT_PORTS = (9092, 8081, 8083, 8082)
UNAUTH_SERVICE_PORTS = (6379, 11211, 9200, 9300, 27017, 2375, 2376, 5000, 9090, 5432)
# Kyverno exposes Prometheus metrics on :8000 by default (kyverno_build_info etc.).
KYVERNO_DEFAULT_PORTS = (8000, 8443)

# ingress-nginx versions fixed for CVE-2025-1974 ("IngressNightmare").
INGRESS_NGINX_FIXED = ((1, 11, 5), (1, 12, 1))

# IMDS / cloud-metadata endpoints reached via an SSRF primitive on the target URL.
IMDS_AWS = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
IMDS_GCP = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
IMDS_AZURE = ("http://169.254.169.254/metadata/identity/oauth2/token"
              "?api-version=2018-02-01&resource=https://management.azure.com/")

# -- access-prover (opt-in proof-of-access) ----------------------------------
# This module is OFF unless explicitly enabled (--prove-access). When enabled it
# creates the smallest possible HARMLESS proof that an already-confirmed
# unauthenticated control-plane (or a reachable/compromised filesystem) is real.
# Policy (enforced in code, not just documented):
#   * Allowed: create clearly-labelled, HARMLESS artifacts only — a marker file on
#     any writable/compromised filesystem, a benign datastore key/doc, or a
#     throwaway container. Artifacts PERSIST (they are NOT self-expiring) so the blue
#     team can independently discover and verify them.
#   * Forbidden, always: configuration changes, data destruction/modification,
#     encryption, DoS, privilege escalation, rootkits/implants/backdoors.
# Persistence is intentional; every artifact is inert and safe to delete.
PROVE_MARKER_PREFIX = "sectest_proof_"          # visible, discoverable marker file / key prefix
PROVE_MARKER_MSG = ("AUTHORIZED-ASSESSMENT harmless proof-of-access marker created by "
                    "security_test; changes no config, destroys no data; safe to delete")
PROVE_CANARY_INDEX = "sectest-canary"           # dedicated ES index for the persistent proof doc
PROVE_CONTAINER_IMAGE = "busybox:latest"        # tiny image for the container-execution proof
PROVE_TIMEOUT = 10                              # per-step timeout for proof actions (seconds)
PROVE_SHELL_TTL = 3600                          # seconds the shell-handle container stays alive
                                                # (persistent: it is NOT auto-removed)
PROVE_HOST_MOUNT = "/host"                      # in-container mount point used for the host-rootfs proof
# Substrings in a Docker /info or cgroup view that indicate the daemon's host is itself
# containerised / ephemeral (kept for operator risk context only).
EPHEMERAL_HINTS = ("kubepods", "docker", "containerd", "ecs", "fargate",
                   "kata", "/actions_job/", "runner")


# -- credentialed cloud assessment (AWS / GCP / Azure) -----------------------
# This path is the cloud analogue of the local proof-of-access model. It is
# DISCOVERY-DRIVEN: the toolkit never accepts operator-supplied cloud keys. The
# credentialed cloud modules activate ONLY when --use-discovered-cloud-creds is set
# AND ambient credentials were actually discovered (an instance/VM metadata role,
# an on-disk profile such as ~/.aws/credentials or ~/.config/gcloud, or a
# credential environment variable) — exactly what a real attacker on a compromised
# host would inherit. With no discovery, the cloud path stays dormant.
CLOUD_TIMEOUT = 8                 # per cloud-API request timeout (seconds)
CLOUD_WALL_BUDGET = 90            # hard wall-clock budget per cloud module (seconds)
CLOUD_MAX_PRINCIPALS = 200       # safety cap on principals enumerated/iterated
CLOUD_MAX_ASSUME_DEPTH = 4       # cap on the role-assumption chain depth we walk

# Cloud-provider API endpoints. STS/IAM are global services that answer in
# us-east-1; the IMDS endpoints mirror those used by metadata_ssrf. Endpoints can
# be overridden per-run via ``target.cloud_endpoints`` (used by the offline tests).
AWS_STS_ENDPOINT = "https://sts.amazonaws.com/"
AWS_IAM_ENDPOINT = "https://iam.amazonaws.com/"
AWS_STS_API_VERSION = "2011-06-15"
AWS_IAM_API_VERSION = "2010-05-08"
AWS_DEFAULT_REGION = "us-east-1"
# Regional Query-protocol endpoints used by the read-only resource enumerator
# (cloud_enum). {region} is substituted at call time; override via target.cloud_endpoints.
AWS_EC2_ENDPOINT = "https://ec2.{region}.amazonaws.com/"
AWS_RDS_ENDPOINT = "https://rds.{region}.amazonaws.com/"
AWS_EC2_API_VERSION = "2016-11-15"
AWS_RDS_API_VERSION = "2014-10-31"
AWS_IMDS_BASE = "http://169.254.169.254"
GCP_IMDS_BASE = "http://metadata.google.internal"
GCP_RM_ENDPOINT = "https://cloudresourcemanager.googleapis.com"
GCP_IAM_ENDPOINT = "https://iam.googleapis.com"
GCP_OAUTH_TOKENINFO = "https://oauth2.googleapis.com/tokeninfo"
AZURE_IMDS_BASE = "http://169.254.169.254"
AZURE_ARM_ENDPOINT = "https://management.azure.com"

# On-disk credential locations probed during discovery (per user home).
CLOUD_CRED_FILES = {
    "aws": ("~/.aws/credentials", "~/.aws/config"),
    "gcp": ("~/.config/gcloud/application_default_credentials.json",
            "~/.config/gcloud/credentials.db"),
    "azure": ("~/.azure/accessTokens.json", "~/.azure/azureProfile.json",
              "~/.azure/msal_token_cache.json"),
}

# Permissions that, if reachable, make a principal capable of the harmless
# grant-nothing proof (or indicate dangerous privilege-escalation potential).
CLOUD_SENSITIVE_PERMS = {
    "aws": ("iam:CreateUser", "iam:CreateAccessKey", "iam:PutUserPolicy",
            "iam:AttachUserPolicy", "iam:CreateRole", "iam:AttachRolePolicy",
            "iam:PutRolePolicy", "iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole", "*"),
    "gcp": ("iam.serviceAccounts.create", "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccountKeys.create", "resourcemanager.projects.setIamPolicy",
            "iam.roles.create"),
    "azure": ("Microsoft.Authorization/roleAssignments/write",
              "Microsoft.Authorization/roleDefinitions/write",
              "Microsoft.ManagedIdentity/userAssignedIdentities/write",
              "*"),
}

# -- cloud grant-nothing proof (opt-in, persistent, harmless) ----------------
# The cloud analogue of the marker file: create ONE clearly-labelled principal that
# grants nothing and holds no usable credential (NO access key / client secret is
# ever generated). It persists for blue-team discovery. Gated behind --prove-access
# AND a simulate-first check that the discovered identity truly holds the create
# permission. The grant-nothing policy documents live in ./policies/.
CLOUD_PROOF_PREFIX = "sectest-proof-grant-nothing"   # principal name prefix
CLOUD_PROOF_TAG_KEY = "AUTHORIZED-ASSESSMENT"
CLOUD_PROOF_TAG_VALUE = "safe-to-delete"
CLOUD_PROOF_MSG = ("AUTHORIZED-ASSESSMENT harmless proof-of-access principal created by "
                   "security_test; grants nothing, holds no usable credential; safe to delete")
CLOUD_POLICY_DIR = "policies"                        # relative to the toolkit root
CLOUD_POLICY_FILES = {
    "aws": "aws_iam_grant_nothing.json",
    "gcp": "gcp_iam_grant_nothing.json",
    "azure": "azure_role_grant_nothing.json",
}
# Cloud writes that are NEVER permitted, even with --prove-access (defence in depth;
# also enforced in code). Creating any usable credential is explicitly forbidden.
CLOUD_FORBIDDEN_ACTIONS = (
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicyVersion", "iam.serviceAccountKeys.create",
)

# -- nmap integration (optional binary; service/version + SAFE NSE only) -----
# Unprivileged TCP connect scan (-sT) keeps the toolkit rootless. NSE scripts are
# constrained to non-intrusive categories — enforced in code, not just documented.
NMAP_TIMEOUT = 300                 # per-invocation wall-clock budget (seconds)
NMAP_HOST_TIMEOUT = "60s"          # nmap --host-timeout per host
NMAP_MIN_RATE = None               # leave unset => nmap's default (avoid aggressive rates)
# NSE categories an operator may opt into. Everything that can change target state,
# brute-force, fuzz, exploit, or phone a third party is forbidden.
NSE_ALLOWED_CATEGORIES = ("safe", "default", "discovery", "version")
NSE_FORBIDDEN_CATEGORIES = ("intrusive", "exploit", "dos", "brute", "vuln",
                            "malware", "external", "fuzzer")

# -- nuclei integration (optional binary; read-only templates) ---------------
NUCLEI_TIMEOUT = 600               # per-invocation wall-clock budget (seconds)
NUCLEI_RATE_LIMIT = 50             # requests/second cap passed to nuclei
NUCLEI_ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
# Template tags excluded in the argv builder so nuclei stays HARMLESS / non-DoS and
# never reaches third-party OAST infrastructure (-no-interactsh is also set).
NUCLEI_EXCLUDED_TAGS = ("intrusive", "dos", "fuzz", "fuzzing", "brute", "bruteforce",
                        "sqli", "xss", "rce", "lfi", "ssrf", "oast")

# -- offline CVE enrichment --------------------------------------------------
# Maps product+version evidence already collected by the active modules to CVEs using
# a bundled, pinned offline feed (no network, no new runtime dependency).
CVE_FEED_DIR = "data/cve"          # relative to the toolkit root
CVE_ENRICH_MAX_FINDINGS = 200      # safety cap on enrichment findings per run


# ===========================================================================
# Intensity tiers + scope allow-list (sandbox/scope_guard.py)
# ===========================================================================
# Every active module declares a minimum INTENSITY; the run executes it only when the
# run's --intensity is at least that high. At/above SCOPE_REQUIRE_ALLOWLIST_AT an
# explicit scope allow-list (hosts/CIDRs/domains) is MANDATORY or the run is refused.
DEFAULT_INTENSITY = "active"           # detective + active run by default
SCOPE_REQUIRE_ALLOWLIST_AT = "intrusive"

# -- default-credential spraying (exploits/default_creds.py; INTENSITY=intrusive) ---
# Lockout-aware: a single pass, no rotation, bounded attempts per account, serial per
# service. Enforced in code, not just config.
SPRAY_CREDS_FILE = "data/creds/default_creds.json"
SPRAY_MAX_ATTEMPTS_PER_ACCOUNT = 3     # hard cap; one pass, no retry/rotation
SPRAY_WALL_BUDGET = 120                # whole-module wall-clock budget (seconds)
SPRAY_REQUEST_TIMEOUT = 6             # per auth attempt
SPRAY_LOCKOUT_STATUSES = (429,)       # any of these aborts that account immediately

# -- protocol auth-surface probes (exploits/proto_auth.py) -------------------
PROTO_AUTH_TIMEOUT = 5
SNMP_COMMUNITIES = ("public", "private")   # community-string guessing is intrusive
PROTO_AUTH_PORTS = {
    "ftp": (21,), "ldap": (389, 636), "smb": (445,), "snmp": (161,), "nfs": (2049,),
}

# -- message-broker auth probes (exploits/mqtt_amqp_probe.py; intrusive) ------------
BROKER_AUTH_TIMEOUT = 5
BROKER_AUTH_PORTS = {"mqtt": (1883,), "amqp": (5672,)}
BROKER_AUTH_CLIENT_ID = "sectest-authorized-assessment"
AMQP_DEFAULT_USER = "guest"
AMQP_DEFAULT_PASS = "guest"

# -- multi-target fan-out (--targets-file) ------------------------------------------
TARGETS_FILE_MAX = 256                 # hard cap on targets resolved from a file

# -- gRPC server-reflection probe (exploits/grpc_reflection.py; detective) ----------
GRPC_TIMEOUT = 10
GRPC_PORTS = (50051,)                   # common gRPC port; explicit --ports also honoured

# -- content discovery / dir-busting (exploits/content_discovery.py; intrusive) -----
CONTENT_DISCOVERY_WORDLIST = "data/wordlists/web_common.txt"
CONTENT_DISCOVERY_MAX = 400            # cap on paths requested per run
CONTENT_DISCOVERY_MAX_WORKERS = 16
CONTENT_DISCOVERY_WALL_BUDGET = 90
CONTENT_DISCOVERY_TIMEOUT = 6

# -- active SSRF / traversal confirmation (exploits/active_confirm.py; intrusive) ---
# Confirmation only ever fetches back the toolkit's OWN labelled canary; it never reads
# arbitrary files or exfiltrates target data.
ACTIVE_CONFIRM_CANARY_TOKEN = "sectest-canary-7Q2K"
ACTIVE_CONFIRM_TIMEOUT = 6
ACTIVE_CONFIRM_MAX_PARAMS = 40

# -- web misconfiguration checks (exploits/web_misconfig.py; active) ---------
WEB_MISCONFIG_TIMEOUT = 6
WEB_MISCONFIG_EVIL_ORIGIN = "https://sectest-evil.example"

# -- Kubernetes enumeration (exploits/k8s_enum.py; intrusive, read-only) -----
K8S_ENUM_TIMEOUT = 6
K8S_ENUM_MAX_ITEMS = 100               # cap on listed namespaces/pods/secrets
# In-pod service-account token (read if present; an attacker on a pod inherits this).
K8S_SA_TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_ENUM_API_PORTS = (6443, 8443, 443)  # API-server ports tried for credentialed enum

# -- cloud object/service enumeration (exploits/cloud_enum.py; read-only) ----
CLOUD_ENUM_MAX_BUCKETS = 200
CLOUD_ENUM_MAX_OBJECTS = 50            # per bucket, for the public-read sample
# GCP/Azure read-only enumeration endpoints (overridable via target.cloud_endpoints).
GCP_COMPUTE_ENDPOINT = "https://compute.googleapis.com"
AZURE_COMPUTE_API_VERSION = "2023-03-01"
AZURE_NETWORK_API_VERSION = "2023-05-01"
AZURE_SUBSCRIPTIONS_API_VERSION = "2020-01-01"
AZURE_ROLEDEF_API_VERSION = "2022-04-01"   # custom role-definition write (grant-nothing proof)

# -- IAM privilege-escalation rules (exploits/cloud_iam_analyzer.py F7) ------
IAM_PRIVESC_RULES_FILE = "data/iam/privesc_rules.json"

# -- access-prover proof expansion (exploits/access_prover.py F9) ------------
PROVE_CANARY_TOPIC = "sectest-canary"          # Kafka canary topic
PROVE_CANARY_COLLECTION = "sectest_canary"     # MongoDB canary collection
PROVE_CANARY_REGISTRY_REPO = "sectest-canary"  # container-registry canary repo

# -- bounded fuzzing tier (exploits/fuzz_probe.py; INTENSITY=fuzz) -----------
# Hard-gated: never runs unless --intensity fuzz AND a non-empty scope allow-list.
# Rate-limited and budgeted so it tests robustness (5xx/stack-trace disclosure) WITHOUT
# becoming a DoS. Payloads come from a reviewed corpus; responses are analysed but a
# discovered fault is never chained into exploitation.
FUZZ_CORPUS_DIR = "data/fuzz"
FUZZ_MAX_REQUESTS = 300                # hard cap on total fuzz requests per run
FUZZ_RATE_LIMIT = 10                   # requests/second ceiling (anti-DoS)
FUZZ_WALL_BUDGET = 120
FUZZ_TIMEOUT = 6
FUZZ_MAX_PARAMS = 25                   # cap on params/headers mutated

# -- reporting (SARIF / HTML / baseline diff) --------------------------------
SARIF_TOOL_URI = "https://example.invalid/security_test"


# ===========================================================================
# Detective-tier recon modules
# ===========================================================================
# -- DNS recon (exploits/dns_recon.py + dnsutil.py; detective, read-only) ----
# Single, env-overridable definition (SECTEST_DNS_TIMEOUT). Previously this was shadowed
# by a second `DNS_TIMEOUT = _env(...)` further down, making this line dead code (BUG-2).
DNS_TIMEOUT = _env("DNS_TIMEOUT", 4)
DNS_AXFR_ENABLED = True                 # attempt zone transfer (read-only request)
DNS_PUBLIC_RESOLVER = "1.1.1.1"         # fallback resolver if /etc/resolv.conf is empty

# -- subdomain takeover (exploits/subdomain_takeover.py; detective) ----------
TAKEOVER_FINGERPRINTS = "data/takeover/fingerprints.json"
TAKEOVER_TIMEOUT = 6

# -- GraphQL probe (exploits/graphql_probe.py; detective) --------------------
GRAPHQL_TIMEOUT = 6
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query",
                 "/api/graphql/v1", "/graphiql", "/graphql/console")

# -- API spec discovery (exploits/api_spec_discovery.py; detective) ----------
API_SPEC_TIMEOUT = 6
API_SPEC_MAX_ENDPOINTS = 40             # cap on declared endpoints probed unauthenticated
API_SPEC_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/.well-known/openapi.json", "/.well-known/security.txt",
    "/actuator", "/actuator/mappings", "/swagger-ui/index.html",
)

# -- public storage enum (exploits/public_storage_enum.py; active, read-only) ----
STORAGE_ENUM_TIMEOUT = 6
STORAGE_ENUM_MAX_CANDIDATES = 24        # cap on candidate bucket names tried per provider
STORAGE_ENUM_S3 = "https://{bucket}.s3.amazonaws.com/?list-type=2"
STORAGE_ENUM_GCS = "https://storage.googleapis.com/{bucket}/"
STORAGE_ENUM_AZURE = "https://{bucket}.blob.core.windows.net/?comp=list"

# -- etcd probe (exploits/etcd_probe.py; detective, read-only) ---------------
ETCD_TIMEOUT = 6
ETCD_PORTS = (2379, 2380, 4001)


# ===========================================================================
# Cross-cutting governors (global request budget)
# ===========================================================================
# A single run-wide ceiling enforced on top of each module's own caps (defence in
# depth). The effective limit on any module is the minimum of its local cap and this
# global budget, so no combination of modules can exceed one outbound-volume ceiling.
GLOBAL_MAX_REQUESTS = 5000      # hard cap on total active requests across the whole run
GLOBAL_RATE_LIMIT = 50         # requests/second ceiling across the whole run (anti-DoS)
GLOBAL_WALL_BUDGET = 1800      # hard wall-clock budget for the whole run (seconds)


# ===========================================================================
# Active confirmation modules + OOB listener
# ===========================================================================
# -- SSTI confirmation (exploits/ssti_confirm.py; intrusive) -----------------
SSTI_TIMEOUT = 6
SSTI_MAX_PARAMS = 25
SSTI_OPERAND_A = 7411          # arithmetic proof operands (product is the SSTI signal)
SSTI_OPERAND_B = 8923

# -- OIDC/OAuth misconfig (exploits/oidc_oauth_misconfig.py; active) ---------
OIDC_TIMEOUT = 6
OIDC_WELL_KNOWN_PATHS = ("/.well-known/openid-configuration",
                         "/.well-known/oauth-authorization-server")

# -- cache poisoning (exploits/cache_poisoning.py; active) -------------------
CACHE_POISON_TIMEOUT = 6
CACHE_POISON_EVIL_HOST = "sectest-cache.example"


# ===========================================================================
# New active modules (db-auth, web confirms, ssh, smtp) + cloud service exposure
# ===========================================================================
# -- database protocol auth (exploits/db_auth.py; intrusive) -----------------
# A SINGLE, non-brute-force authentication attempt per engine (trust/blank-password/
# anonymous detection only). Read-only protocol verbs; no queries, no writes.
DB_AUTH_TIMEOUT = 6
DB_AUTH_PORTS = {"postgres": (5432,), "mysql": (3306,), "mssql": (1433,), "oracle": (1521,)}
DB_AUTH_PG_USER = "postgres"          # benign probe user for the Postgres trust-auth check
DB_AUTH_MYSQL_USER = "root"           # single blank-password attempt (no brute-force)

# -- SQL injection confirmation (exploits/sqli_confirm.py; intrusive) --------
# Benign error/boolean/short-sleep signals only; never extracts data or stacks writes.
SQLI_TIMEOUT = 8
SQLI_MAX_PARAMS = 20
SQLI_SLEEP_SECONDS = 4                 # single bounded time-based delay (anti-DoS)

# -- XXE confirmation (exploits/xxe_confirm.py; intrusive) -------------------
# External entities resolve ONLY to the operator canary (never file://, internal, 3rd party).
XXE_TIMEOUT = 6
XXE_MARKER = "SECTEST-XXE-7Q2K"

# -- path traversal / LFI confirmation (exploits/path_traversal_confirm.py; intrusive) ---
# Confirms via non-secret OS file signatures; only the matched signature line is captured.
TRAVERSAL_TIMEOUT = 6
TRAVERSAL_MAX_PARAMS = 20
TRAVERSAL_MAX_DEPTH = 8

# -- HTTP request smuggling detection (exploits/request_smuggling.py; intrusive) ----
# Timing-based detection ONLY; probes use a dedicated, non-pipelined connection.
SMUGGLE_CONNECT_TIMEOUT = 6
SMUGGLE_DELAY_THRESHOLD = 5            # seconds of stall that signals a desync
SMUGGLE_READ_TIMEOUT = 9

# -- SSH posture probe (exploits/ssh_probe.py; detective, read-only) ---------
SSH_TIMEOUT = 6
SSH_PORTS = (22,)

# -- SMTP open-relay / transport posture (exploits/smtp_probe.py; active) ----
# The relay test never reaches DATA (RSET/QUIT first), so no mail is ever sent.
SMTP_TIMEOUT = 6
SMTP_PLAIN_PORTS = (25, 587)
SMTP_TLS_PORTS = (465,)
SMTP_EHLO_NAME = "security-test.local"
SMTP_RELAY_FROM = "probe@sectest-authorized-assessment.example"
SMTP_RELAY_TO = "relay-test@example.com"

# -- SMTP enumeration (exploits/smtp_enum.py; active) ---------------------------
SMTP_ENUM_USERS = (
    "admin", "root", "postmaster", "info", "support", "contact",
    "webmaster", "sales", "marketing", "noreply", "no-reply",
    "test", "user", "mail", "office", "help", "abuse",
    "security", "billing", "hr",
)
SMTP_ENUM_FROM = "probe@sectest-assessment.example"

# -- SMTP credential spray (exploits/smtp_auth_spray.py; intrusive) -------------
SMTP_SPRAY_DELAY = _env("SMTP_SPRAY_DELAY", 2.0)
SMTP_SPRAY_MAX_ATTEMPTS = _env("SMTP_SPRAY_MAX_ATTEMPTS", 5)

# -- SMTP anti-spam posture (exploits/smtp_antispam.py; active) -----------------
SMTP_BOMB_TEST_COUNT = _env("SMTP_BOMB_TEST_COUNT", 10)
SMTP_BOMB_TEST_INTERVAL = _env("SMTP_BOMB_TEST_INTERVAL", 0.1)

# -- SMTP email posture / DNS analysis (exploits/smtp_email_posture.py; active) --------
# (DNS_TIMEOUT is defined once above, in the DNS recon section — BUG-2.)
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mailjet",
    "cm", "amazonses", "protonmail",
)

# -- proof-of-access marker command (exploits/proof_marker.py) -------------------------
# Executed on every confirmed foothold: echo + id captures privilege level; a labelled
# marker file is written to /tmp for blue-team correlation. No destructive actions.
PROOF_MARKER_CMD = "id"

# -- cloud application-service exposure (exploits/cloud_service_exposure.py; active) ---
# Read-only: Lambda/SNS/SQS/Secrets Manager/SSM/KMS/Transfer. Never fetches secret VALUES.
CLOUD_SERVICE_MAX_ITEMS = 100
AWS_LAMBDA_ENDPOINT = "https://lambda.{region}.amazonaws.com"
AWS_SNS_ENDPOINT = "https://sns.{region}.amazonaws.com/"
AWS_SQS_ENDPOINT = "https://sqs.{region}.amazonaws.com/"
AWS_SECRETSMANAGER_ENDPOINT = "https://secretsmanager.{region}.amazonaws.com"
AWS_SSM_ENDPOINT = "https://ssm.{region}.amazonaws.com"
AWS_KMS_ENDPOINT = "https://kms.{region}.amazonaws.com"
AWS_TRANSFER_ENDPOINT = "https://transfer.{region}.amazonaws.com"
AWS_SNS_API_VERSION = "2010-03-31"
AWS_SQS_API_VERSION = "2012-11-05"


# ===========================================================================
# Run orchestration: module-level parallelism, scan profiles, resume state
# ===========================================================================
# Modules are independent; the orchestrator may run them concurrently (bounded). The
# global RequestBudget still paces total outbound volume, so parallelism never raises the
# request ceiling. Set MODULE_MAX_WORKERS=1 (or --jobs 1) for fully sequential execution.
MODULE_MAX_WORKERS = 8

# Scan profiles bundle an intensity + parallelism + rate preset (--profile).
SCAN_PROFILES = {
    "quick":    {"intensity": "detective", "jobs": 12, "rate_limit": 50},
    "standard": {"intensity": "active",    "jobs": 8,  "rate_limit": 50},
    "deep":     {"intensity": "intrusive", "jobs": 8,  "rate_limit": 40},
    "stealth":  {"intensity": "active",    "jobs": 2,  "rate_limit": 5},
}

# Resume/state file: records completed (target, module) pairs so a re-run with --resume
# skips work already done (useful for large --cidr / --targets-file sweeps).
RESUME_STATE_VERSION = 1


# ===========================================================================
# Value-add feature modules + lateral-movement iteration (this session)
# ===========================================================================
# -- API object-level authz (exploits/api_idor.py; intrusive, read-only GET) --------
# Confirms BOLA/IDOR by missing-auth re-fetch, neighbour-id probing, and (optional)
# cross-identity access. GET only; bodies compared locally, never exfiltrated.
API_IDOR_TIMEOUT = 6
API_IDOR_MAX_IDS = 6                    # cap on neighbour ids tried per object
API_IDOR_SIMILARITY_SAME = 0.98        # bodies this similar are "the same object"
API_IDOR_SIMILARITY_DIFF = 0.85        # bodies less similar than this are "a different object"

# -- authenticated spider (exploits/web_spider.py; active, read-only GET) -----------
# Same-origin only; obvious state-changing links (logout/delete) are never followed.
SPIDER_TIMEOUT = 6
SPIDER_MAX_PAGES = 60                   # hard cap on pages fetched
SPIDER_MAX_DEPTH = 3                    # link-following depth
SPIDER_WALL_BUDGET = 60                 # whole-module wall-clock budget (seconds)
SPIDER_MAX_BYTES = 131072              # per-page body cap parsed for links/secrets

# -- LLM endpoint probe (exploits/llm_probe.py; active, benign canary prompts) ------
LLM_PROBE_TIMEOUT = 15
LLM_PROBE_MARKER = "SECTEST-LLM-CANARY-7Q2K"
LLM_PROBE_MAX_BYTES = 16384
LLM_PROBE_PATHS = ("", "/v1/chat/completions", "/v1/completions", "/api/chat", "/chat",
                   "/api/generate", "/v1/messages", "/completion", "/ask", "/query",
                   "/api/v1/chat")

# -- deserialization probe (exploits/deserialization_probe.py; intrusive) -----------
# Detects sinks + (with an OOB canary) confirms reachability via a benign, NON-executable
# payload. No RCE/gadget payload is ever sent (enforced in code).
DESERIAL_TIMEOUT = 6
DESERIAL_MAX_PARAMS = 20

# -- SAML/SSO misconfig (exploits/saml_misconfig.py; active, detection-only) ---------
SAML_TIMEOUT = 6
SAML_MAX_BYTES = 262144
SAML_PATHS = ("/saml/metadata", "/saml2/metadata", "/saml/metadata.xml", "/sp/metadata",
              "/simplesaml/saml2/idp/metadata.php",
              "/FederationMetadata/2007-06/FederationMetadata.xml", "/adfs/ls/",
              "/auth/saml2/metadata", "/sso/saml/metadata", "/metadata", "/saml/sso",
              "/saml/login", "/Shibboleth.sso/Metadata")

# -- cloud posture / CSPM-lite (exploits/cloud_posture.py; cloud, read-only) ---------
CLOUD_POSTURE_STALE_KEY_DAYS = 90      # age beyond which an access key is "stale"
AWS_CLOUDTRAIL_ENDPOINT = "https://cloudtrail.{region}.amazonaws.com"

# -- GCP/Azure service-exposure parity (exploits/cloud_service_exposure.py) ----------
GCP_STORAGE_ENDPOINT = "https://storage.googleapis.com"
GCP_FUNCTIONS_ENDPOINT = "https://cloudfunctions.googleapis.com"
AZURE_STORAGE_API_VERSION = "2023-01-01"
AZURE_KEYVAULT_API_VERSION = "2022-07-01"

# -- SBOM / dependency scan (exploits/sbom_scan.py; detective; optional binary) ------
SBOM_SCAN_TIMEOUT = 300                # per-scan wall-clock budget (seconds)
SBOM_SCAN_MAX_FINDINGS = 100
SBOM_SCAN_MIN_SEVERITY = "MEDIUM"      # only surface vulns at/above this severity

# -- HTTP/2 rapid-reset exposure (exploits/http2_probe.py; detective, DETECT-ONLY) ---
# Fingerprints HTTP/2 support only; never opens/resets a stream (the vuln is a DoS).
HTTP2_TIMEOUT = 6
HTTP2_TLS_PORTS = (443, 8443)

# -- EPSS + MITRE ATT&CK enrichment (exploits/cve_enrich.py post-pass) ---------------
EPSS_FEED_FILE = "epss.json"           # under CVE_FEED_DIR; offline EPSS subset
ATTACK_MAP_FILE = "attack_map.json"    # under CVE_FEED_DIR; category/tag -> technique map

# -- lateral-movement iteration / SSM pivot (exploits/cloud_pivot.py + main.py) ------
# cloud-pivot maps SSM-reachable instances to their subnet peers and publishes them as
# pivot_targets; the orchestrator re-runs the host:port modules against each (bounded by
# depth + scope). SendCommand/StartSession are SIMULATED, never executed.
PIVOT_DEFAULT_PORTS = (22, 80, 443, 3306, 5432, 6379, 8080)
PIVOT_MAX_PEERS = 64                    # cap on subnet peers queued per run
PIVOT_MAX_DEPTH = 2                     # max lateral hops the orchestrator will follow
PIVOT_WALL_BUDGET = 600                 # hard wall-clock budget for the whole pivot fan-out

# Proven-access subnet broadening (exploits/access_prover.py -> main._expand_subnet_spec):
# when access to a device is PROVEN, its subnet is queued so the orchestrator sweeps it for
# live hosts and re-runs the host:port modules against each (every peer is scope-checked).
PIVOT_SUBNET_PREFIX = 24                # /N subnet derived around a proven-access device
PIVOT_SUBNET_MAX_HOSTS = 256            # cap on hosts a derived subnet may expand to
PIVOT_SWEEP_TIMEOUT = 1.0               # per-host TCP-connect timeout for the subnet liveness sweep

# -- foothold-relayed scanning (sandbox/relay.py) -----------------------------------
# When access to a container / VM / server / cloud instance is PROVEN, the next hop must be
# reached FROM that foothold's network position, not the scanner's. A "relay" performs the
# next-hop reachability probe (and optionally tunnels HTTP/service traffic) through the
# foothold. Every relay is connect-only / read-only — nothing is installed, no data changes.
#   * docker  — an exposed Docker Engine API foothold runs a THROWAWAY, auto-removed,
#               connect-only busybox container that TCP-tests the next-hop hosts. No mounts.
#   * proxy   — an operator/relay-positioned HTTP-CONNECT or SOCKS5 proxy (a real tunnel):
#               both the reachability sweep AND the host:port/url modules route through it.
RELAY_DOCKER_IMAGE = "busybox:latest"   # tiny image for the connect-only relay container
RELAY_DOCKER_NETWORK = "host"           # container network: share the foothold's stack exactly
RELAY_CONNECT_TIMEOUT = 2               # per-target connect timeout used INSIDE the foothold (s)
RELAY_CONNECT_TMPL = "nc -w {timeout} -z {host} {port}"  # connect test run inside the foothold
RELAY_MAX_TARGETS = 512                 # cap on host:port pairs a single relay sweep may test
RELAY_TIMEOUT = 12                      # wall-clock budget for one relay container/sweep (s)
RELAY_PROXY_CONNECT_TIMEOUT = 4         # per-target connect timeout for a proxy relay sweep (s)

# -- proof-of-access ledger (sandbox/ledger.py) -------------------------------------
# Every hop the toolkit REACHES or PROVES is recorded as one auditable ledger entry
# (resource kind, identity, reached-from, relay used, proof artifact, scope status). The
# ledger reconstructs the end-to-end lateral-movement path so each accessible resource has a
# clearly-identified proof — the "adequate path to identification" of every access.
LEDGER_MODULE_NAME = "proof-ledger"     # name used for the synthesized ledger result
LEDGER_MAX_HOPS = 1024                  # safety cap on recorded hops


# ===========================================================================
# Workstream 1 — K8s Service/Endpoint Enumeration
# ===========================================================================
K8S_SERVICE_ENUM_KINDS = ("LoadBalancer", "ExternalName", "NodePort")
K8S_CONFIGMAP_URL_PATTERN = r"https?://[^\s\"'<>]+"
K8S_INGRESS_ANNOTATIONS_BACKEND = ("nginx.ingress.kubernetes.io/backend-protocol",)
K8S_SERVICE_ENUM_TIMEOUT = 8
K8S_SERVICE_ENUM_MAX_URLS = 64          # cap on discovered pivot URLs per cluster

# ===========================================================================
# Workstream 2 — Kubernetes Relay (kubelet exec / K8s API exec)
# ===========================================================================
RELAY_KUBELET_EXEC_TIMEOUT = 10
RELAY_K8S_API_EXEC_TIMEOUT = 12
RELAY_DNS_TIMEOUT = 5
RELAY_KUBELET_PROBE_CMD = "nc -w {timeout} -z {host} {port}"
RELAY_K8S_POD_SELECT_STRATEGY = "first-running"

# ===========================================================================
# Workstream 3 — GCP / Azure Cloud Pivot
# ===========================================================================
GCP_COMPUTE_API = "https://compute.googleapis.com/compute/v1"
GCP_RUN_API = "https://run.googleapis.com/v2"
GCP_CONTAINER_API = "https://container.googleapis.com/v1"
GCP_FUNCTIONS_API = "https://cloudfunctions.googleapis.com/v2"
AZURE_MGMT_API = "https://management.azure.com"
AZURE_API_VERSION_COMPUTE = "2024-07-01"
AZURE_API_VERSION_NETWORK = "2024-05-01"
AZURE_API_VERSION_CONTAINER = "2024-05-01"
AZURE_API_VERSION_WEBAPP = "2023-12-01"
IAM_ASSUME_ROLE_MAX_DEPTH = 2           # cap on role-assumption chain depth

# ===========================================================================
# Workstream 4 — URL/Service-Based Pivot Generalization
# ===========================================================================
SERVICE_PIVOT_MAX_URLS = 32             # cap on URL-based pivot specs queued per run
SERVICE_PIVOT_HTTP_PROBE_TIMEOUT = 6    # timeout for relay HTTP probe of URL targets

# ===========================================================================
# Workstream 5 — K8s/Cloud Proof-of-Access Extensions
# ===========================================================================
K8S_PROOF_CONFIGMAP_NS = "default"
K8S_PROOF_CONFIGMAP_PREFIX = "sectest-proof-"
K8S_PROOF_POD_MARKER_PATH = "/tmp/sectest_proof_{ts}.txt"
CLOUD_RUN_PROOF_MARKER = "AUTHORIZED-ASSESSMENT-{ts}"
GCS_PROOF_BUCKET_PREFIX = "sectest-proof-"

# ===========================================================================
# Workstream 7 — Bonus: Service Mesh / Network Policy / IAM Chaining
# ===========================================================================
SERVICE_MESH_ADMIN_PORTS = (15000, 15001, 9901)
NETWORK_POLICY_MAX_RULES = 200          # cap on parsed network policy rules

# ===========================================================================
# Script Propagation (--propagate-script)
# ===========================================================================
PROPAGATE_TIMEOUT = 300                 # max seconds to wait for propagated scan (full network scan)
PROPAGATE_CLEANUP = True                # auto-remove deployed payload after execution
PROPAGATE_DEPLOY_PATH = "/tmp/.sectest_propagate"
PROPAGATE_MAX_OUTPUT = 65536            # max bytes of stdout to collect from propagated scan
PROPAGATE_MAX_DEPTH = 2                 # default depth (decremented each hop; 0 = no further propagation)

# Strategy selection: 'auto' (default), 'native', 'zipapp', 'source'
PROPAGATE_STRATEGY = "auto"             # auto = native > zipapp > source (best available)
PROPAGATE_CHUNK_SIZE = 48000            # max base64 bytes per chunk (kubelet body limit)
PROPAGATE_PAYLOADS_DIR = "data/payloads"  # relative to project root

# Transport priority override (comma-separated, or empty for default priority):
# Default priority: ssh, docker-volume, kubelet, k8s-api, cloud-storage
PROPAGATE_TRANSPORT_PRIORITY = ""

# Cross-cloud propagation settings
PROPAGATE_CLOUD_UPLOAD_BUCKET = ""      # S3/GCS/Blob bucket for large payloads (optional)
PROPAGATE_CLOUD_PRESIGN_TTL = 300       # presigned URL expiry in seconds
PROPAGATE_SSH_TIMEOUT = 30              # SSH connect timeout for SSH-based transport

# ===========================================================================
# v5: SSH Auth Spray Settings
# ===========================================================================
SSH_AUTH_TIMEOUT = _env("SSH_AUTH_TIMEOUT", 10)
SSH_AUTH_DELAY = _env("SSH_AUTH_DELAY", 1.0)
SSH_AUTH_MAX_ATTEMPTS = _env("SSH_AUTH_MAX_ATTEMPTS", 5)
SSH_AUTH_PORTS = (22,)

# ===========================================================================
# v5: Shellshock / CGI Module Settings
# ===========================================================================
SHELLSHOCK_TIMEOUT = _env("SHELLSHOCK_TIMEOUT", 8)
SHELLSHOCK_MAX_PATHS = _env("SHELLSHOCK_MAX_PATHS", 30)

PHP_CGI_TIMEOUT = _env("PHP_CGI_TIMEOUT", 8)
PHP_CGI_MAX_PATHS = _env("PHP_CGI_MAX_PATHS", 20)

CMD_INJECT_TIMEOUT = _env("CMD_INJECT_TIMEOUT", 8)
CMD_INJECT_MAX_PARAMS = _env("CMD_INJECT_MAX_PARAMS", 20)

# ===========================================================================
# v5: LLM Endpoint Enumeration Settings
# ===========================================================================
LLM_ENUM_TIMEOUT = _env("LLM_ENUM_TIMEOUT", 6)
LLM_ENUM_PORTS = (11434, 8080, 8000, 5000, 3000)

# ===========================================================================
# Live CVE Resolution (--cve-lookup)
# ===========================================================================
CVE_REACHABILITY_TIMEOUT = 3            # seconds for the internet reachability probe
CVE_REACHABILITY_ENDPOINTS = (          # tried in order; first success = reachable
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
    "https://api.osv.dev/",
)
CVE_REACHABLE_HTTP_CODES = (200, 400, 403, 429)  # any of these = internet is reachable
CVE_RETRY_COUNT = 3                     # retries when internet drops mid-resolution
CVE_RETRY_WAIT_SECONDS = 600            # 10 minutes between retries
CVE_CONSECUTIVE_FAIL_THRESHOLD = 2      # consecutive failures before declaring "internet dropped"


# ===========================================================================
# New feature modules (F1-F6): TLS probe, passive discovery, git proof,
# DB credential access, datastore access, cloud lateral broadening
# ===========================================================================

# -- pkg-tls-probe (exploits/pkg_tls_probe.py; active) ----------------------
PKG_TLS_TIMEOUT = 8
PKG_TLS_PORTS = (443, 8443, 9443, 636, 993, 995, 5671, 6443)
PKG_TLS_STARTTLS_PORTS = {"25": "smtp", "587": "smtp", "143": "imap", "110": "pop3", "389": "ldap"}

# -- passive-discovery (exploits/passive_discovery.py; active, local/hostport) --
PASSIVE_DISCOVERY_LISTEN_TIMEOUT = 5    # seconds to listen for broadcast traffic
PASSIVE_DISCOVERY_ARP_CMD = "ip neigh show"

# -- git-push-proof (exploits/git_push_proof.py; proof, opt-in) --------------
GIT_PROOF_TIMEOUT = 30                  # per-git-command timeout (seconds)
GIT_PROOF_BRANCH_PREFIX = "sectest-proof-access"
GIT_PROOF_PROTECTED_BRANCHES = ("main", "master", "develop", "release", "production", "staging")

# -- db-cred-access (exploits/db_cred_access.py; proof, opt-in) --------------
# Uses DB_AUTH_TIMEOUT and DB_AUTH_PORTS from existing db_auth config above.

# -- datastore-access (exploits/datastore_access.py; proof, cloud) -----------
# Uses CLOUD_TIMEOUT and existing cloud endpoint configs. Additional endpoints:
AWS_S3_ENDPOINT = "https://s3.amazonaws.com"
AWS_DYNAMODB_ENDPOINT = "https://dynamodb.{region}.amazonaws.com"
GCP_FIRESTORE_ENDPOINT = "https://firestore.googleapis.com"
GCP_BIGQUERY_ENDPOINT = "https://bigquery.googleapis.com"
AZURE_COSMOS_API_VERSION = "2023-04-15"
ATLAS_API_ENDPOINT = "https://cloud.mongodb.com/api/atlas/v1.0"

# -- cloud-lateral (exploits/cloud_lateral.py; active, cloud) ----------------
# Uses CLOUD_MAX_ASSUME_DEPTH, CLOUD_MAX_PRINCIPALS, and existing IAM/STS configs.
CLOUD_LATERAL_MAX_IMPERSONATION_DEPTH = 3  # GCP SA impersonation chain depth
CLOUD_LATERAL_K8S_MAX_NAMESPACES = 20      # cap on namespaces checked via SelfSubjectAccessReview
# When True, cloud-lateral will actually execute sts:AssumeRole (not just simulate it),
# minting real temporary credentials. This is an ACTIVE action — keep False unless the
# engagement explicitly authorises active role assumption.
CLOUD_LATERAL_ACTIVE_ASSUME = False
# OCI Identity REST endpoint (override in target.cloud_endpoints for offline tests)
OCI_IDENTITY_ENDPOINT = "https://identity.us-ashburn-1.oraclecloud.com"


# ===========================================================================
# WAF / Firewall / Cloud Firewall proof (exploits/waf_firewall_proof.py)
# ===========================================================================
WAF_PROOF_ALLOW_CIDR = "10.0.0.0/8"       # private range (low disruption risk)
WAF_PROOF_PRIORITY = 99999                 # lowest priority so existing rules still apply
WAF_PROOF_DESCRIPTION = "AUTHORIZED-ASSESSMENT proof-of-access safe-to-delete"
WAF_PROOF_TIMEOUT = 15                     # per-API call timeout (seconds)
# AWS WAF
AWS_WAF_ENDPOINT = "https://wafv2.{region}.amazonaws.com"
AWS_WAF_API_VERSION = "2019-07-29"
# GCP Cloud Armor
GCP_ARMOR_ENDPOINT = "https://compute.googleapis.com/compute/v1"
# Azure WAF (Front Door / Application Gateway)
AZURE_NETWORK_SECURITY_API_VERSION = "2023-09-01"


# ===========================================================================
# Git CLI propagation (exploits/git_cli_proof.py; proof, opt-in)
# ===========================================================================
GIT_CLI_TIMEOUT = 30                       # per-command timeout for gh/glab
GIT_CLI_PROOF_REPO_PREFIX = "sectest-proof"
GIT_CLI_PROOF_USER_PREFIX = "sectest-proof-bot"
GIT_CLI_MAX_REPOS = 10                     # cap on repos to push marker into


# ===========================================================================
# OWASP / ZAP native scanning (exploits/owasp_scan.py, zap_passive_scan.py)
# ===========================================================================
OWASP_SCAN_TIMEOUT = 8
OWASP_SCAN_MAX_PARAMS = 30
ZAP_PASSIVE_MAX_RESPONSE_BYTES = 262144   # cap on response body parsed for passive checks
ZAP_PASSIVE_TIMEOUT = 6

# OWASP Top 10:2025 CWE mapping (for Finding tagging)
OWASP_2025_MAP = {
    "A01": ("Broken Access Control", "CWE-284"),
    "A02": ("Security Misconfiguration", "CWE-16"),
    "A03": ("Software Supply Chain Failures", "CWE-829"),
    "A04": ("Cryptographic Failures", "CWE-327"),
    "A05": ("Injection", "CWE-74"),
    "A06": ("Insecure Design", "CWE-400"),
    "A07": ("Authentication Failures", "CWE-287"),
    "A08": ("Software or Data Integrity Failures", "CWE-345"),
    "A09": ("Security Logging and Alerting Failures", "CWE-778"),
    "A10": ("Mishandling of Exceptional Conditions", "CWE-460"),
}

# OWASP API Security Top 10:2023 CWE mapping
OWASP_API_2023_MAP = {
    "API1": ("Broken Object Level Authorization", "CWE-639"),
    "API2": ("Broken Authentication", "CWE-287"),
    "API3": ("Broken Object Property Level Authorization", "CWE-915"),
    "API4": ("Unrestricted Resource Consumption", "CWE-770"),
    "API5": ("Broken Function Level Authorization", "CWE-285"),
    "API6": ("Unrestricted Access to Sensitive Business Flows", "CWE-799"),
    "API7": ("Server Side Request Forgery", "CWE-918"),
    "API8": ("Security Misconfiguration", "CWE-16"),
    "API9": ("Improper Inventory Management", "CWE-1059"),
    "API10": ("Unsafe Consumption of APIs", "CWE-346"),
}


# ===========================================================================
# Additional cloud providers (credential discovery + enumeration)
# ===========================================================================
# -- OVH Public Cloud (OpenStack-based)
OVH_API_ENDPOINT = "https://api.ovh.com/1.0"
OVH_CRED_FILES = ("~/.config/openstack/clouds.yaml", "~/.ovh.conf")
OVH_ENV_PREFIXES = ("OS_AUTH_URL", "OS_TOKEN", "OS_USERNAME", "OVH_APPLICATION_KEY")

# -- Scaleway
SCW_API_ENDPOINT = "https://api.scaleway.com"
SCW_CRED_FILES = ("~/.config/scw/config.yaml",)
SCW_ENV_PREFIXES = ("SCW_SECRET_KEY", "SCW_ACCESS_KEY", "SCW_DEFAULT_ORGANIZATION_ID")

# -- Oracle Cloud Infrastructure (OCI)
OCI_CRED_FILES = ("~/.oci/config",)
OCI_ENV_PREFIXES = ("OCI_CLI_TENANCY", "OCI_CLI_USER", "OCI_CLI_KEY_FILE", "OCI_CLI_FINGERPRINT")

# -- Nutanix
NUTANIX_DEFAULT_PORT = 9440
NUTANIX_API_PATH = "/api/nutanix/v3"
NUTANIX_ENV_PREFIXES = ("NUTANIX_USERNAME", "NUTANIX_PASSWORD", "NUTANIX_ENDPOINT")

# -- DigitalOcean
DO_API_ENDPOINT = "https://api.digitalocean.com/v2"
DO_CRED_FILES = ("~/.config/doctl/config.yaml",)
DO_ENV_PREFIXES = ("DIGITALOCEAN_ACCESS_TOKEN", "DIGITALOCEAN_TOKEN")

# -- Hetzner Cloud
HCLOUD_API_ENDPOINT = "https://api.hetzner.cloud/v1"
HCLOUD_ENV_PREFIXES = ("HCLOUD_TOKEN",)

# -- Linode / Akamai
LINODE_API_ENDPOINT = "https://api.linode.com/v4"
LINODE_CRED_FILES = ("~/.config/linode-cli",)
LINODE_ENV_PREFIXES = ("LINODE_TOKEN", "LINODE_CLI_TOKEN")

# -- Vultr
VULTR_API_ENDPOINT = "https://api.vultr.com/v2"
VULTR_ENV_PREFIXES = ("VULTR_API_KEY",)

# -- Alibaba Cloud
ALIBABA_CRED_FILES = ("~/.aliyun/config.json",)
ALIBABA_ENV_PREFIXES = ("ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
                        "ALICLOUD_ACCESS_KEY")

# -- Confluent Cloud (distinct from self-hosted Kafka already probed)
CONFLUENT_CLOUD_API_ENDPOINT = "https://api.confluent.cloud"
CONFLUENT_CLOUD_CRED_FILES = ("~/.confluent/config.json",)
CONFLUENT_CLOUD_ENV_PREFIXES = ("CONFLUENT_CLOUD_API_KEY", "CONFLUENT_CLOUD_API_SECRET")

# All additional providers (used by cloud_creds_extended.py for discovery)
EXTENDED_CLOUD_PROVIDERS = (
    "ovh", "scaleway", "oci", "nutanix", "digitalocean",
    "hetzner", "linode", "vultr", "alibaba", "confluent_cloud",
)


# ===========================================================================
# Scope enforcement v2: target-derived scope + mandatory confirmation
# ===========================================================================
# At intrusive+ intensity, the scope is derived from the target (host, CIDR, URL domain).
# --scope entries are OPTIONAL narrowing. No allow-list is required.
# Mandatory: --yes OR interactive confirmation prompt.
SCOPE_REQUIRE_CONFIRMATION_AT = "intrusive"   # replaces SCOPE_REQUIRE_ALLOWLIST_AT


# ===========================================================================
# v11 web/network coverage modules
# ===========================================================================
# -- cors-probe (exploits/cors_probe.py; active) ----------------------------
CORS_TIMEOUT = _env("CORS_TIMEOUT", 8)
CORS_ATTACKER_ORIGIN = _env("CORS_ATTACKER_ORIGIN", "https://attacker.example")

# -- waf-detect (exploits/waf_detect.py; detective) -------------------------
WAF_DETECT_ACTIVE = _env("WAF_DETECT_ACTIVE", True)   # send challenge payloads
WAF_DETECT_TIMEOUT = _env("WAF_DETECT_TIMEOUT", 5)

# -- ssrf-probe (exploits/ssrf_probe.py; intrusive) -------------------------
SSRF_MAX_PARAMS = _env("SSRF_MAX_PARAMS", 5)
SSRF_TIMEOUT = _env("SSRF_TIMEOUT", 8)
SSRF_CANARY_FILE = _env("SSRF_CANARY_FILE", "/etc/passwd")

# -- nosqli-confirm (exploits/nosqli_confirm.py; intrusive) -----------------
NOSQLI_MAX_PARAMS = _env("NOSQLI_MAX_PARAMS", 5)
NOSQLI_TIMEOUT = _env("NOSQLI_TIMEOUT", 8)

# -- dns-attack-probe (exploits/dns_attack_probe.py; intrusive) -------------
DNS_AXFR_TIMEOUT = _env("DNS_AXFR_TIMEOUT", 10)
DNS_REBINDING_SAMPLES = _env("DNS_REBINDING_SAMPLES", 3)
DNS_REBINDING_DELAY = _env("DNS_REBINDING_DELAY", 1.0)

# -- api-enum (exploits/api_enum.py; active) --------------------------------
API_ENUM_TIMEOUT = _env("API_ENUM_TIMEOUT", 8)
API_ENUM_MAX_PATHS = _env("API_ENUM_MAX_PATHS", 60)

# -- forbidden-bypass (exploits/forbidden_bypass.py; intrusive) -------------
FORBIDDEN_BYPASS_TIMEOUT = _env("FORBIDDEN_BYPASS_TIMEOUT", 8)
FORBIDDEN_BYPASS_MAX_URLS = _env("FORBIDDEN_BYPASS_MAX_URLS", 4)

# -- netutil retry/backoff (exploits/netutil.py) ----------------------------
NETUTIL_MAX_RETRIES = _env("NETUTIL_MAX_RETRIES", 2)
NETUTIL_BACKOFF_BASE = _env("NETUTIL_BACKOFF_BASE", 0.5)
NETUTIL_BACKOFF_FACTOR = _env("NETUTIL_BACKOFF_FACTOR", 2.0)
# Retry only genuinely-transient server errors (502/503/504) by default. 429 is NOT
# retried by default: the lockout-aware credential modules rely on seeing a 429 once and
# aborting immediately — auto-retrying a 429 would keep hammering a rate-limited/locked
# account. Operators who want RFC-7231 Retry-After honoring can opt in via
# SECTEST_NETUTIL_RETRY_ON_429=true.
NETUTIL_RETRY_ON_429 = _env("NETUTIL_RETRY_ON_429", False)


# ===========================================================================
# Runtime config overlay + propagation serialization
# ===========================================================================
# The runtime overlay allows discovery-driven updates (e.g., replacing default
# endpoints with discovered VPC endpoints). On propagation, the overlay is
# serialized alongside governance flags.

_RUNTIME_OVERLAY: dict = {}


def runtime_set(key: str, value) -> None:
    """Set a runtime config override (discovery-driven, e.g. VPC endpoints)."""
    _RUNTIME_OVERLAY[key] = value


def runtime_get(key: str, default=None):
    """Get a config value with runtime overlay > env-var > module-level default.

    The env-var value is coerced to the type of the module-level default (via _env),
    so callers that expect an int/float/bool get one — not the raw string (BUG-17).
    """
    if key in _RUNTIME_OVERLAY:
        return _RUNTIME_OVERLAY[key]
    base = globals().get(key, default)
    if _os.environ.get(f"SECTEST_{key}") is not None:
        # base carries the type used for coercion; if it is None we cannot infer a type,
        # so _env returns the raw string (unchanged behavior for untyped keys).
        return _env(key, base if base is not None else "")
    return base


def export_for_propagation() -> dict:
    """Serialize the active config (overlay + non-default env overrides) for forwarding."""
    export = dict(_RUNTIME_OVERLAY)
    # Include any SECTEST_* env vars so the propagated instance inherits them
    for k, v in _os.environ.items():
        if k.startswith("SECTEST_"):
            export[k[8:]] = v  # strip prefix
    return export


def import_from_propagation(data: dict) -> None:
    """Apply config received from a parent propagation hop."""
    for k, v in (data or {}).items():
        _RUNTIME_OVERLAY[k] = v

