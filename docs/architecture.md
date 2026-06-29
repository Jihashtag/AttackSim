# Architecture

## Project layout

```
security_test/
├── run_all.sh                # bash orchestrator
├── main.py                   # python entrypoint (target resolution + dispatch)
├── config.py                 # central timeouts / limits / identity
├── pyproject.toml            # pytest / ruff / mypy config + optional extras
├── conftest.py               # test path setup + local-server fixture
├── requirements.txt          # OPTIONAL extras only
├── targets/
│   └── model.py              # Target + resolve() (repo/url/creds/hostport/netrange/local/cloud)
├── exploits/                 # one file per attack technique (101 modules)
│   ├── base.py               # Finding / ExploitResult models
│   ├── registry.py           # module catalogue + kind/intensity dispatch
│   ├── util.py               # stdlib file walking + masking
│   ├── netutil.py            # shared stdlib HTTP/TCP/Redis helpers
│   ├── dnsutil.py            # DNS resolution helpers
│   ├── cloudutil.py          # AWS SigV4 signing + cloud HTTP helpers
│   ├── toolrunner.py         # audited subprocess chokepoint (shell=False)
│   ├── attack_chain.py       # post-pass: correlate findings into kill-chains
│   ├── cve_enrich.py         # post-pass: offline CVE/EPSS correlation
│   ├── cve_resolver.py       # library: CVE lookup via NVD (--cve-lookup)
│   ├── exploit_planner.py    # library: CVE test-plan prioritization
│   ├── exploit_generator.py  # library: PoC script generation + sandbox execution
│   ├── ...                   # 101 module files (one per attack technique)
├── sandbox/
│   ├── credential_guard.py   # scrubs ambient credentials before module run
│   ├── scope_guard.py        # scope allow-list enforcement
│   ├── budget.py             # global request budget (anti-DoS ceiling)
│   ├── oob_listener.py       # out-of-band confirmation listener (--oob-listen)
│   ├── cloud_creds.py        # ambient cloud credential discovery
│   ├── cloud_creds_extended.py  # extended cloud provider credential helpers
│   ├── relay.py              # foothold relays (Docker / proxy / kubelet / K8s API)
│   ├── ledger.py             # proof-of-access ledger (per-hop path identification)
│   ├── propagate.py          # self-propagation onto proven footholds
│   ├── propagate_cloud.py    # cloud-specific propagation (EC2/GCE/Azure VMs)
│   ├── propagate_pack.py     # package-up scanner for remote deployment
│   ├── propagate_transport.py  # transport layer for remote propagation
│   └── resources.py          # adaptive parallelism (CPU/memory detection)
├── data/
│   ├── cve/feed.json         # bundled offline CVE feed: 68 records, 18 product families
│   ├── cve/epss.json         # offline EPSS exploit-probability scores
│   ├── cve/attack_map.json   # category→ATT&CK technique mapping
│   ├── cve/cpe_aliases.json  # 86-product CPE alias table (product→vendor)
│   ├── cve/audit_log/        # audit trail of generated exploit scripts
│   ├── cve/cache/            # NVD query cache
│   ├── cve/poc_templates/    # PoC script templates
│   ├── creds/default_creds.json  # curated default-credential database
│   ├── fuzz/payloads.txt     # reviewed benign fuzz corpus
│   ├── iam/privesc_rules.json    # IAM privilege-escalation detection rules
│   ├── payloads/             # additional attack payload resources
│   ├── takeover/fingerprints.json  # subdomain-takeover fingerprints
│   └── wordlists/web_common.txt   # content-discovery wordlist
├── policies/                 # grant-nothing policy documents (AWS/GCP/Azure)
│   ├── aws_iam_grant_nothing.json
│   ├── gcp_iam_grant_nothing.json
│   └── azure_role_grant_nothing.json
├── llm/
│   └── advisor.py            # optional local Ollama briefing (injection-hardened)
├── report/
│   ├── reporter.py           # console / JSON / Markdown / SARIF / HTML rendering
│   └── state.py              # resume-state persistence (--resume)
├── tests/                    # pytest suite (682+ tests)
└── docs/                     # this documentation
```

## Module contract

Every module in `exploits/` is a Python module that exposes:

| Attribute | Type | Description |
|---|---|---|
| `NAME` | `str` | Unique kebab-case identifier (e.g. `"jwt-forger"`) |
| `DESCRIPTION` | `str` | One-line human description |
| `SUPPORTS` | `set[str]` | Target kinds: `repo`, `url`, `creds`, `hostport`, `netrange`, `local`, `cloud` |
| `INTENSITY` | `str` | Minimum tier: `detective`, `active`, `intrusive`, `proof`, `fuzz` |
| `run(target)` | `→ ExploitResult` | The attack logic |

## Data models

### `Finding` (dataclass)

```python
@dataclass
class Finding:
    title: str          # what was found
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    location: str       # where (file path, URL, host:port)
    detail: str         # human explanation (REQUIRED positional)
    evidence: str = ""  # raw proof (masked in output)
    cwe: str = ""       # e.g. "CWE-287"
    references: list[str] = field(default_factory=list)
    category: str = ""  # structural class
    tags: list[str] = field(default_factory=list)
```

### `ExploitResult` (dataclass)

```python
@dataclass
class ExploitResult:
    name: str                            # module NAME constant
    description: str                     # module DESCRIPTION constant
    exploited: bool                      # True = EXPLOITED, False = MITIGATED
    findings: list[Finding] = field(default_factory=list)
    attacker_value: str = ""             # what the attacker gains if exploited
    mitigation: str = ""                 # remediation guidance
    summary: str = ""                    # optional one-line outcome note
    error: Optional[str] = None          # set when the module fails hard
    tool_available: bool = True          # False when an optional binary is absent
```

## Orchestration flow

1. **Parse args** → resolve target kind
2. **Credential guard** runs (scrubs environment)
3. **Cloud credential discovery** (if `--use-discovered-cloud-creds`)
4. **Module selection** — filter by target kind + intensity tier
5. **Concurrent execution** — bounded pool (`--jobs`)
6. **Post-passes** — `cve-enrich`, `attack-chain`, `cve-resolver` (if `--cve-lookup`)
7. **Proof-of-access** (if `--prove-access`) → 360° pivot → relay scanning
8. **Propagation** (if `--propagate-script`) → deploy + re-run from foothold
9. **Reporting** — console + JSON + optional formats

## Safety layers

| Layer | File | Purpose |
|---|---|---|
| Credential guard | `sandbox/credential_guard.py` | Scrubs all credential sources |
| Scope guard | `sandbox/scope_guard.py` | Per-URL authorization at intrusive+ |
| Request budget | `sandbox/budget.py` | Global request ceiling (anti-DoS) |
| Subprocess chokepoint | `exploits/toolrunner.py` | Audited `shell=False` execution |
| Relay validation | `sandbox/relay.py` | Command-injection prevention for relay targets |
| OOB listener | `sandbox/oob_listener.py` | Controlled out-of-band confirmation |
