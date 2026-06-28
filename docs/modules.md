# Modules (101 registered)

Run `python3 main.py --list-modules` to print the live catalogue.

## Repository modules (detective)

| Module | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|
| `secret-harvester` | Steal live secrets from tracked files | a non-placeholder CRITICAL/HIGH secret is found |
| `jwt-forger` | Mint an admin JWT from a leaked HS256 secret | a forged token verifies against the leaked secret |
| `bcrypt-cracker` | Crack committed bcrypt hashes (contextual wordlist) | a plaintext password is recovered |
| `ppe-detector` | Poisoned Pipeline Execution via pull request | a PR can run on a privileged self-hosted runner |
| `gitops-analyzer` | ArgoCD wildcard project / auto-sync abuse | a wildcard `AppProject` / `sourceRepos` is present |
| `network-exposure` | Internet-exposed ingress | an inbound `0.0.0.0/0` rule is found |
| `supply-chain` | Tamper with build/deploy artifacts | unpinned actions/images / disabled attestations |
| `dependency-integrity` | Dependency confusion, missing lock-file hashes, HTTP registries, insecure credential transport | a dependency confusion vector or insecure registry transport is found |
| `sbom-scan` | Software-composition vulnerability scan via trivy/grype (optional binary); runs against repo source trees and, under `--local`, the running host's installed packages | a HIGH/CRITICAL dependency vulnerability is found |

## Active modules (live targets)

| Module | Target kind | Tier | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `http-probe` | url | active | Probe a live endpoint | reachable unauthenticated, no TLS, bad cert, or a supplied token is accepted |
| `path-probe` | url | detective | Discover sensitive paths (Spring Actuator `/env` & `/heapdump`, `/.git`, config files, API docs) | a CRITICAL/HIGH path is reachable unauthenticated |
| `jwt-attacker` | url | active | Live JWT bypass: `alg:none`, claim tampering, weak HS256-secret crack | a forged token is accepted or the signing secret is recovered |
| `cred-tester` | creds | active | Validate credentials | an auth attempt succeeds (HTTP 2xx) |
| `port-probe` | host:port | detective | Reach a network service | a TCP connection is accepted |
| `tls-grader` | url / host:port | detective | Grade transport security | deprecated TLS, weak cipher, or invalid/expired certificate |
| `ssh-probe` | host:port | detective | Read-only SSH posture: version banner + `KEXINIT` algorithm proposal — flags weak KEX (SHA-1/1024-bit DH), host-key (`ssh-dss`/SHA-1 `ssh-rsa`), CBC/3DES/arcfour ciphers, MD5/truncated MACs. No authentication attempted | *(reports posture; weak crypto = MEDIUM/LOW)* |
| `smtp-probe` | host:port | active | SMTP **open-relay** test (stops at `RCPT`, issues `RSET`/`QUIT` before `DATA` — no mail sent) + STARTTLS / cleartext-AUTH posture | an external sender+recipient is accepted (open relay) |
| `smtp-enum` | host:port | active | Enumerate valid SMTP users via `VRFY`, `EXPN`, and `RCPT TO` timing | a valid username is confirmed |
| `smtp-inject` | host:port | active | Detect SMTP header injection (CRLF) and command smuggling vulnerabilities | a CRLF or smuggling vector is confirmed |
| `smtp-antispam` | host:port | active | Assess mail-bombing resilience (rate-limit) and spam/spoof filter effectiveness | rate-limit absent or a spoofed mail is accepted |
| `smtp-email-posture` | host:port | active | DNS-based email security posture (SPF/DMARC/DKIM/MX/MTA-STS) for targeted email domains | a critical DNS misconfiguration is found |
| `web-misconfig` | url | active | CORS reflection (Origin+credentials), open redirect, missing security headers / cookie flags | permissive CORS-with-credentials or an open redirect |
| `web-spider` | url | active | Bounded same-origin authenticated crawl; publishes discovered URLs to other modules; inline-secret detection | a MEDIUM+ secret is found inline in a crawled page |
| `llm-probe` | url | active | Detect LLM endpoints and confirm prompt-injection / system-prompt leakage (benign canary only) | an injection echo or system-prompt leak is confirmed |
| `llm-endpoint-enum` | host:port / url | active | Discover accessible LLM/AI API endpoints (Ollama, OpenAI-compatible, vLLM, Hugging Face TGI) | an unprotected inference endpoint is reachable |
| `dns-recon` | url / host:port | detective | DNS hygiene & zone exposure: AXFR, SPF/DMARC/MTA-STS, open resolver, wildcard | a zone transfer is accepted or a critical DNS record is misconfigured |
| `dns-enum` | host:port / url | detective | DNS record enumeration, subdomain brute-force, and certificate-transparency lookup | a hidden subdomain or sensitive DNS record is discovered |
| `reverse-dns` | host:port / netrange | detective | Reverse DNS (PTR) lookup for IPs — maps addresses to hostnames and cloud providers | a hostname or provider mapping is returned |
| `subdomain-takeover` | url / host:port | detective | Detect dangling CNAMEs pointing at unclaimed cloud resources | a takeover-eligible CNAME is found |
| `graphql-probe` | url | detective | Discover GraphQL endpoints and flag introspection / field-suggestion leakage | introspection is enabled or field suggestions leak the schema |
| `api-spec-discovery` | url | detective | Find OpenAPI/Swagger/.well-known specs and unauthenticated sensitive endpoints | an API spec is reachable with unprotected sensitive endpoints |
| `public-storage-enum` | url / cloud | active | Find anonymously-listable public S3/GCS/Azure storage buckets | a public bucket is listable (data leak) |
| `oidc-oauth-misconfig` | url | active | Flag OIDC/OAuth weaknesses: `alg:none`, http endpoints, no PKCE, open registration | a critical misconfiguration is found |
| `cache-poisoning` | url | active | Detect unkeyed-header reflection into cacheable responses | a cache-poisoning vector is confirmed |
| `saml-misconfig` | url | active | SAML/SSO metadata & endpoint misconfiguration posture (detection-only) | `WantAssertionsSigned=false` or SHA-1 signatures are found |
| `http2-rapid-reset` | url / host:port | detective | Detect HTTP/2 support and flag CVE-2023-44487 rapid-reset exposure (detection-only, never opens/resets a stream) | HTTP/2 is supported on an unpatched server |
| `etcd-probe` | host:port | detective | Detect unauthenticated etcd (v2/v3) exposing cluster keys | etcd answers without auth |
| `grpc-reflection` | host:port | detective | Detect exposed gRPC server-reflection (full API surface leak) | reflection is enabled, leaking the full service API |
| `shellshock-probe` | url | active | Detect Bash Shellshock (CVE-2014-6271) on CGI endpoints via a benign echo canary | the canary value is reflected in the response |
| `php-cgi-probe` | url | active | Detect PHP-CGI argument injection (CVE-2012-1823, CVE-2024-4577) | a PHP argument-injection response is returned |
| `pkg-tls-probe` | host:port / url | active | Probe TLS posture: self-signed certs, missing HSTS, STARTTLS strip opportunity, and downgrade exposure | a high-severity TLS weakness is confirmed |
| `passive-discovery` | host:port / local / netrange | active | Harvest ARP/neighbor cache, listen for mDNS/LLMNR/NBT-NS/SSDP broadcasts, enumerate local interfaces | at least one peer or broadcast responder is discovered |

## Network-range discovery & external-tool integrations

`host-sweep` turns a CIDR/IP-range into a list of **live** hosts (unprivileged TCP-connect,
no raw ICMP), then the orchestrator fans the host:port modules out across them. `nmap-probe`
and `nuclei-probe` are **optional**: they auto-detect their binary and degrade to a clean
INFO skip when absent. `cve-enrich` is a post-pass that correlates discovered service
versions with a bundled **offline** CVE feed (no network).

| Module | Target kind | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|
| `host-sweep` | netrange | Liveness sweep across a subnet (TCP-connect on a high-signal probe set) | at least one host answers and is probed further |
| `nmap-probe` | host:port / netrange | Service/version detection via nmap **connect-scan** (`-sT -sV`, never `-sS`); NSE is opt-in and runs only SAFE allow-listed categories | an open service/version is fingerprinted |
| `nuclei-probe` | url / host:port / netrange | Known-vulnerability template scan; always excludes intrusive/dos/fuzz/brute tags, `-no-interactsh`, rate-limited | a non-info template matches |
| `cve-enrich` *(post-pass)* | (all) | Correlate discovered `product+version` banners with a bundled offline CVE feed + EPSS scores + ATT&CK technique tags | a discovered version falls in a known-vulnerable range |

## Cloud-native / infrastructure active modules

Protocol-aware, credential-free probes aimed at the platform stack (Kubernetes,
ingress-nginx, Confluent/Kafka, ArgoCD, service meshes, and common datastores). All are
read-only.

| Module | Target kind | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|
| `k8s-probe` | host:port | Unauthenticated Kubernetes control plane (API server anonymous-auth, kubelet, etcd) plus CVE-2019-11248, CVE-2025-0426, CVE-2024-9042 and anonymous `/configz` | a component answers anonymously |
| `k8s-service-enum` | host:port / url | Enumerate K8s services, ingresses, HTTPRoutes, VirtualServices, ConfigMaps, webhooks, NetworkPolicies for lateral-movement URL discovery | a reachable internal service or pivot URL is discovered |
| `service-mesh-probe` | host:port / url | Detect service-mesh sidecars (Envoy/Istio) via admin ports and enumerate upstream clusters/routes | sidecar admin port is exposed and upstream clusters are enumerable |
| `ingress-nightmare` | url / host:port | IngressNightmare CVE matrix (CVE-2025-1974/1097/1098/24513/24514) + admission-webhook reachability + project-EOL flag | a controller below 1.11.5/1.12.1 is detected, or any version on the archived project |
| `unauth-service-probe` | host:port | Open datastores/daemons (Redis, Memcached, Elasticsearch/OpenSearch, MongoDB, Docker API, registry, Prometheus, Postgres) | a service answers without auth |
| `kafka-probe` | host:port | Open Confluent/Kafka stack (broker `ApiVersions`, Schema Registry, Kafka Connect REST, REST Proxy) | a broker accepts PLAINTEXT or a REST service answers unauthenticated |
| `metadata-ssrf` | url | SSRF → cloud metadata (AWS/GCP/Azure IMDS) credential theft | the endpoint reflects instance-metadata content |
| `argocd-probe` | url | ArgoCD exposure + version advisories (CVE-2024-21652/21661, CVE-2025-55190, CVE-2026-42880) and `/api/webhook` DoS reachability | an old/affected version or unauthenticated API listing |
| `kyverno-probe` | url / host:port | Kyverno admission-controller exposure via `:8000/metrics` + version-advisory map (GHSA-8wfp-579w-6r25, GHSA-qr4g-8hrp-c4rw) | the metrics endpoint answers anonymously or an affected build is fingerprinted |
| `cloud-recon` | cloud | active | Credentialed read-only cloud recon: current identity + IAM inventory (AWS/GCP/Azure) | an identity with sensitive permissions is discovered |
| `cloud-iam-analyzer` | cloud | active | Simulate effective permissions via `iam:SimulatePrincipalPolicy` / `testIamPermissions`, walk role-assumption chains, flag IAM privesc primitives | a sensitive permission or escalation path is reachable |
| `cloud-enum` | cloud | active | Credentialed read-only enumeration of internet-exposed cloud resources (S3, ECS, Lambda, GCS, Functions, Azure Storage, etc.) | an exposed or publicly readable resource is found |
| `cloud-service-exposure` | cloud | active | Credentialed read-only service exposure: AWS Lambda/SNS/SQS/Secrets/SSM/KMS/Transfer + GCP Storage/Functions + Azure Storage/Key Vault | an over-exposed service or leaked secret is found |
| `cloud-posture` | cloud | active | Read-only cloud security-posture review: CloudTrail logging, public AMIs/EBS snapshots, IAM password policy, root access keys, MFA status | a critical posture gap |
| `cloud-lateral` | cloud | active | Walk assume-role/impersonation chains to map cross-account/cross-project lateral movement (simulation only — no AssumeRole executed without `CLOUD_LATERAL_ACTIVE_ASSUME=True`) | a reachable lateral-movement path is mapped |
| `cloud-pivot` | cloud | active | Map SSM-reachable EC2 instances and simulate `ssm:SendCommand`/`StartSession` (NEVER executed) | a simulated SSM path to internal hosts is reachable |

## Intrusive modules (require `--intensity intrusive` + `--scope`)

These do **multi-request** guessing/enumeration. They never run on a default (`active`)
run, always require a scope allow-list, and each is lockout-/rate-aware.

| Module | Target kind | Tier | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `default-creds` | url / host:port | intrusive | Lockout-aware default-credential spraying (≤3 pw/account, aborts on 429). Needs `--spray`. | a default/weak credential authenticates |
| `content-discovery` | url | intrusive | Bounded, rate-aware path brute-forcing with soft-404 calibration | a hidden admin/config/backup/API path is reachable |
| `active-confirm` | url | intrusive | Confirm reflected-parameter injection + canary-only SSRF | a verbatim reflection or confirmed SSRF canary-hit |
| `k8s-enum` | host:port | intrusive | Credentialed read-only k8s enumeration + `SelfSubjectRulesReview` | the token can list Secrets or holds a dangerous verb |
| `proto-auth` | host:port | intrusive | Default-community / anonymous auth on SNMP, FTP, LDAP, SMB, NFS | a default community or anonymous auth is accepted |
| `broker-auth` | host:port | intrusive | Probe MQTT/AMQP brokers for anonymous or default auth | an anonymous/default-cred broker connection is accepted |
| `db-auth` | host:port | intrusive | One non-brute attempt per DB engine (PostgreSQL trust, MySQL blank root, MSSQL fingerprint, Oracle TNS) | a trust/blank-password/anonymous database accepts the connection |
| `api-idor` | url | intrusive | Confirm BOLA/IDOR with read-only cross-identity requests (GET only, CWE-639) | a user can read another user's object |
| `deserialization-probe` | url | intrusive | Detect insecure-deserialization sinks + confirm via benign OOB canary | a deserialization sink is reachable and confirmed |
| `ssti-confirm` | url | intrusive | Confirm SSTI via benign arithmetic evaluation (never executes commands) | a computed arithmetic result confirms template evaluation |
| `sqli-confirm` | url | intrusive | Confirm SQLi via benign error/boolean/time-based signals — never extracts data | a database syntax error, boolean divergence, or bounded delay confirms injection |
| `xxe-confirm` | url | intrusive | Confirm XXE via internal-entity expansion + external entity to operator canary only | the parser expands entities or fetches the OOB canary |
| `path-traversal-confirm` | url | intrusive | Confirm LFI/traversal via non-secret OS-file signatures | a traversal payload returns a known OS-file signature |
| `request-smuggling` | url | intrusive | Timing-only CL.TE/TE.CL desync detection (never poisons a victim request) | an ambiguous request stalls measurably vs baseline |
| `cmd-inject-confirm` | url | intrusive | Confirm OS command injection via a benign arithmetic canary (`expr`) — never executes destructive commands | the computed arithmetic result is returned in the response |
| `ssh-auth` | host:port | intrusive | Lockout-aware SSH credential spraying and discovered-key verification | a credential or key authenticates |
| `smtp-auth-spray` | host:port | intrusive | Lockout-aware SMTP AUTH credential spraying (PLAIN/LOGIN) | a credential authenticates via SMTP AUTH |

## Fuzz module (requires `--intensity fuzz`)

| Module | Target kind | Tier | Attack simulated | Outcome |
|---|---|---|---|---|
| `fuzz-probe` | url | fuzz | Bounded, rate-limited robustness fuzzing from a reviewed benign corpus; reports only fault disclosure (5xx / stack traces). Hard request cap + req/s ceiling; never chains a fault into exploitation | *(reports findings; never marks EXPLOITED)* |

## Proof-of-access modules (opt-in)

| Module | Target kind | What it does | Outcome = EXPLOITED when… |
|---|---|---|---|
| `access-prover` | host:port / cloud | Off unless `--prove-access`. Creates a harmless, clearly-labelled, persistent artifact proving access. | a benign marker file / datastore key / container execution / grant-nothing principal succeeds |
| `git-push-proof` | repo | Pushes a labelled marker branch to prove write access | marker branch appears on remote |
| `git-cli-proof` | cloud / repo | Detects `gh`/`glab` CLI, creates proof repos, pushes markers to all accessible repos | at least one proof repo created or marker branch pushed |
| `db-cred-access` | host:port | Prove discovered database credentials are live with a read-only authenticated call | the connection authenticates and a safe query succeeds |
| `waf-firewall-proof` | cloud / host:port | Creates non-destructive lowest-priority allow rule (private CIDR 10.0.0.0/8) with proof label on discovered WAFs/firewalls (AWS WAFv2, GCP Cloud Armor, Azure NSG, F5 BIG-IP, FortiGate, Cisco Meraki, DigitalOcean, Hetzner, Scaleway, Vultr, OCI, Nutanix Flow, iptables) | rule successfully added |
| `datastore-access` | cloud | Writes a labelled, time-stamped proof item in discovered datastores | item persisted in at least one datastore |

See [proof-of-access.md](proof-of-access.md) for full details.

## OWASP / ZAP scan modules

| Module | Target kind | Tier | Attack simulated | Outcome |
|---|---|---|---|---|
| `owasp-scan` | url | active | OWASP Top 10:2025 + API Top 10:2023 active checks (verb tampering, forced browsing, error disclosure, crypto/HSTS, CRLF injection, CSP/SRI gaps, rate limiting, deprecated APIs) | findings generated per CWE |
| `zap-passive-scan` | url | detective | ZAP-style passive response analysis (security headers, info leakage, cookie flags, PII/IP/stack traces in body, CORS, clickjacking, session-in-URL, mixed content) | findings generated per detected issue |

## Extended cloud providers

| Module | Target kind | Tier | Attack simulated | Outcome |
|---|---|---|---|---|
| `cloud-multicloud-enum` | cloud | active | Resource enumeration on Scaleway, DigitalOcean, Hetzner, Linode, Vultr, Confluent Cloud, OCI, Nutanix, Alibaba Cloud, OVH Public Cloud using discovered credentials | finding per accessible resource |

## Network appliance modules

| Module | Target kind | Tier | Attack simulated | Outcome |
|---|---|---|---|---|
| `cisco-probe` | hostport / cloud | active | Cisco infrastructure enumeration: Meraki (organizations/networks/devices/firewall rules), ASA/FTD (interfaces/ACLs/routes), ISE (network devices/endpoint groups), Catalyst Center (devices/topology) | finding per enumerated resource |
| `network-device-enum` | hostport / cloud | active | F5 BIG-IP enumeration (virtual servers/pools/nodes/iRules/ASM policies/firewall policies) and Fortinet FortiGate enumeration (policies/interfaces/routes/VPN tunnels/SSL-VPN) | finding per enumerated resource |

## Local introspection modules (`--local`)

Read-only modules that inspect **the host the scanner runs on**. Never modify files, never
open outbound connections beyond what the specific module needs.

| Module | Target kind | Tier | What it detects | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `container-escape-detector` | local / host:port | detective | Container-escape preconditions (dangerous caps, mounted Docker/CRI sockets, writable host bind-mounts, shared PID namespace, vulnerable runc CVEs); remotely: unauthenticated Docker/kubelet API | a CRITICAL/HIGH escape precondition or exposed runtime API |
| `rootkit-ioc-detector` | local | detective | Linux rootkit/eBPF-implant IOCs: `LD_PRELOAD` hooking, LKM rootkit modules (Diamorphine/Reptile/Suterusu/KoviD/…), hidden modules, rootkit symbols in `/proc/kallsyms`, pinned eBPF implants | a CRITICAL/HIGH rootkit IOC is present |
| `linux-privesc` | host:port / local | detective | Detect Linux privilege-escalation preconditions: kernel CVEs, SUID binaries, sudo misconfig, Docker group, writable cron (local + SSH fingerprint) | a HIGH/CRITICAL escalation vector is found |
| `sbom-scan` | local / repo | detective | Software-composition vulnerability scan via trivy/grype against installed packages (local) or the repo source tree | a HIGH/CRITICAL dependency vulnerability is found |

See [local-introspection.md](local-introspection.md) for full details.

## On-site / physical assessment modules

Modules for **physical penetration tests** and **on-site network assessments**. All require
`--local` (or being deployed via propagation onto a foothold). WiFi/Bluetooth/router modules
gate active scans behind `is_local or is_propagated`.

| Module | Target kind | Tier | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `wifi-probe` | local | active | WiFi network discovery: SSID enumeration, encryption posture (open/WEP/WPS/WPA2/WPA3). On exploitation, adds gateway IP and local subnet to `pivot_targets` for downstream sweep. | an open, WEP, or WPS-enabled network is found |
| `bluetooth-probe` | local | active | Bluetooth device discovery: discoverable devices, pairing mode, exposed RFCOMM/SPP services, GATT service enumeration (Nordic UART, vendor serial UUIDs → pivot relay) | a discoverable device exposes an RFCOMM/BLE shell service |
| `router-probe` | host:port / local / netrange | active | Router/gateway fingerprint, admin panel exposure, Telnet/TR-069 open ports, UPnP IGD, default-firmware CVE hints | a management interface is reachable unauthenticated |
| `android-probe` | host:port / local / netrange | active | Android device discovery via ADB (port 5555), developer debug-mode detection, mDNS `_adb._tcp` | an ADB-exposed device is reachable |
| `ios-probe` | host:port / local / netrange | active | iOS device discovery via iTunes sync (port 62078), Bonjour/mDNS, and jailbreak SSH indicators | an accessible iOS device is fingerprinted |
| `device-posture` | local | detective | Post-propagation device assessment: privilege level, sandbox detection, local services on `127.0.0.1` (`ss`/`netstat`/`/proc/net/tcp`), WiFi/BT adapter presence, ARP peer discovery → `pivot_targets`, OS fingerprint | *(posture report; HIGH/CRITICAL if privileged services exposed)* |
| `privesc-exploit` | local | intrusive | Attempt local privilege escalation: SUID GTFOBins, sudo NOPASSWD, password spray (≤5 attempts), CVE detection (DirtyPipe/DirtyCow/PwnKit/Baron Samedit/OverlayFS), misconfiguration checks. Verification-only (`id`); writes a single labelled proof marker. | root is obtained by any method |
| `router-auth` | host:port / netrange | intrusive | Firmware-specific default credential testing on router/firewall admin panels (OpenWRT, DD-WRT, MikroTik, pfSense, ASUS, TP-Link, D-Link, Netgear, Zyxel, …). ≤6 attempts per host, 1 s delay | a default credential authenticates |
