# AttackSim — Automated Attacker Simulation & CVE Verification Framework

**Open-source Python penetration testing framework** for unauthenticated attacker simulation,
CVE verification, AI-powered exploit generation, and interactive security triage.
No credentials · no agents · pure external-attacker perspective.

AttackSim role-plays a red-team attacker who only has network access — no AWS, EKS,
ArgoCD, or JFrog credentials are used or required. It runs real exploitation where it can
(JWT forgery, password-hash cracking, live service probing, CVE-verified PoC scripts) and
static reachability analysis for the rest, then tells you, per attack:

- **`[ EXPLOITED ]`** — the attack succeeded; a usable weakness exists.
- **`[ MITIGATED ]`** — the attack failed; that risk is mitigated.

If **any** module wins, AttackSim exits `1` with a consolidated *"issues an attacker could
use"* summary. If **all** fail, AttackSim prints *"the assessed risks are MITIGATED"* and
exits `0`.

> Authorised, defensive use only. AttackSim reads files, computes hashes, and probes
> network services — it uses **no credentials**. A runtime credential guard enforces this.

---

## Quick start

```bash
git clone https://github.com/jean-alexandre-bert/attacksim && cd attacksim
./run_all.sh                 # attack the parent workspace
./run_all.sh --url https://api.example.com          # probe a live endpoint
./run_all.sh 10.0.0.5:22,80,6379                    # host:port service probe
./run_all.sh --cidr 10.0.0.0/24                     # network sweep
python3 main.py --no-color                          # direct Python invocation
```

After a scan, replay and triage CVE findings interactively with AttackSim's triage tool:

```bash
# Load a saved JSON report and walk through every CVE finding:
python3 triage.py scan_results.json

# Filter to HIGH+ severity and auto-prompt to re-verify each finding live:
python3 triage.py scan_results.json --severity HIGH --re-verify

# Include all exploited findings (not just CVE-tagged):
python3 triage.py scan_results.json --all
```

See [docs/quickstart.md](docs/quickstart.md) for full examples.

---

## Key features

- **107 registered attack modules** covering repos, URLs, credentials, host:port, network
  ranges, local introspection, on-site/physical (WiFi, Bluetooth, router, Android/iOS),
  cloud, network appliances, and 101-CVE offline feed (OpenSSH, Bash, Linux kernel, Windows,
  macOS, Apache, nginx, OpenSSL, Log4j/Log4Shell, Spring4Shell, Confluence, Jenkins,
  GitLab, Docker, Kubernetes, Elasticsearch, IIS, Jira, Grafana, Keycloak) — plus
  high-impact CVE detection modules for Log4Shell, Apache Struts OGNL RCE, EternalBlue
  (MS17-010), ActiveMQ OpenWire RCE, and Slowloris DoS
- **AI-powered CVE exploit generation** — AttackSim's CVE pipeline uses a local LLM
  (Ollama) to generate and complete PoC verification scripts directly from CVE metadata;
  the interactive `[ri]` triage path auto-detects stub scripts and offers LLM completion
  and post-run output summarization
- **5 intensity tiers** (detective → active → intrusive → proof → fuzz) with mandatory
  confirmation (`--yes` or interactive) at intrusive+
- **Credential guard** — scrubs all ambient credentials before module execution
- **CVE discovery pipeline** — resolve service banners to CVEs via NVD, generate and run
  AI-assisted verification scripts
- **Proof-of-access** — harmless, persistent, labelled artifacts proving exploitability
- **360° lateral movement** — pivot from proven footholds to subnet peers via relays
- **Self-propagation** — deploy AttackSim onto footholds and scan from inside the network
- **Cloud assessment** — read-only IAM analysis and privilege-escalation simulation
  (AWS/GCP/Azure + OVH, Scaleway, OCI, DigitalOcean, Hetzner, Linode, Vultr, Alibaba,
  Nutanix, Confluent Cloud)
- **Network appliance assessment** — F5 BIG-IP, Fortinet FortiGate, Cisco Meraki,
  Cisco ASA/FTD, Cisco ISE, Catalyst Center enumeration
- **Attack-chain correlation** — link individual findings into end-to-end kill-chains
- **Multiple output formats** — console, JSON, Markdown, SARIF, HTML
- **CI gate** with baseline comparison and severity thresholds

---

## Documentation

| Document | Contents |
|---|---|
| [Quick Start](docs/quickstart.md) | Installation, common examples, parallelism, optional extras |
| [Targets](docs/targets.md) | Target kinds, resolution precedence, port specs, batch targets |
| [Modules](docs/modules.md) | All 107 modules by category (repo, active, intrusive, high-impact CVE, on-site, cloud, fuzz, proof) |
| [Intensity & Scope](docs/intensity-and-scope.md) | Tier definitions, scope enforcement, profiles |
| [CLI Reference](docs/cli-reference.md) | Complete flag reference and exit codes |
| [Credential Guard](docs/credential-guard.md) | How credentials are neutralised |
| [Proof-of-Access](docs/proof-of-access.md) | Proof types, 360° sweep, relays, ledger |
| [Cloud Assessment](docs/cloud-assessment.md) | Credentialed cloud path, IAM analysis, grant-nothing proofs |
| [CVE Pipeline](docs/cve-pipeline.md) | CVE resolution, exploit planning, AI-powered PoC generation, interactive triage |
| [Propagation](docs/propagation.md) | Self-deployment onto proven footholds |
| [Local Introspection](docs/local-introspection.md) | Container-escape detection, rootkit IOCs, on-site/physical assessment (WiFi, Bluetooth, router, Android/iOS, privesc) |
| [Output & CI](docs/output-and-ci.md) | Report formats, attack chains, baseline drift, CI gating |
| [Architecture](docs/architecture.md) | Project layout, module contract, data models, orchestration flow |
| [Safety](docs/safety.md) | Design principles, what is forbidden, enforcement layers |
| [Development](docs/development.md) | Setup, testing, adding modules, conventions |

---

## Safety summary

AttackSim is designed for authorised, defensive use. All safety properties are enforced at
runtime, not just by convention:

- **Read-only by default** — only proof-tier modules (opt-in) create artifacts
- **Credential-free** — runtime guard scrubs all credential sources
- **Confirmation-enforced** — mandatory `--yes` or interactive prompt at intrusive+
  intensity (scope = target-derived; optional `--scope` for narrowing)
- **Request-budgeted** — global ceiling prevents DoS
- **Secret-masked** — findings never expose raw secret values
- **Controlled transmission** — git-push-proof and git-cli-proof (opt-in, proof tier)
  may push labelled marker branches as supply-chain access evidence; all other AttackSim
  modules never commit, push, or send externally
