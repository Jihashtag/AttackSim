# Modules (107 registered)

Run `python3 main.py --list-modules` to print the live catalogue.

## Repository modules (detective)

| Module | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|
| `secret-harvester` | Steal live secrets from tracked files | a non-placeholder CRITICAL/HIGH secret is found |
| `jwt-forger` | Mint an admin JWT from a leaked HS256 secret | a forged token verifies against the leaked secret |
| `bcrypt-cracker` | Crack committed bcrypt hashes (contextual wordlist); at intrusive+ (if target URL provided) attempts HTTP Basic auth with cracked passwords against common admin paths to confirm live account access | a plaintext password is recovered; at intrusive+ CRITICAL if cracked password authenticates |
| `ppe-detector` | Poisoned Pipeline Execution via pull request; at intrusive+ queries the GitHub API (using git remote origin) to confirm the repository is public, escalating static findings to CRITICAL | a PR can run on a privileged self-hosted runner; at intrusive+ CRITICAL if repo confirmed public on GitHub |
| `gitops-analyzer` | ArgoCD wildcard project / auto-sync abuse | a wildcard `AppProject` / `sourceRepos` is present |
| `network-exposure` | Internet-exposed ingress; at intrusive+ parses `.tfstate` files for public IPs and TCP-probes them on port 22/80/443 to confirm live internet exposure | an inbound `0.0.0.0/0` rule is found; at intrusive+ CRITICAL if public IP confirmed reachable |
| `supply-chain` | Tamper with build/deploy artifacts | unpinned actions/images / disabled attestations |
| `dependency-integrity` | Dependency confusion, missing lock-file hashes, HTTP registries, insecure credential transport; at intrusive+ queries PyPI JSON API to confirm confusion-risk package names are claimed publicly | a dependency confusion vector or insecure registry transport is found; at intrusive+ CRITICAL if package confirmed claimed in PyPI |
| `sbom-scan` | Software-composition vulnerability scan via trivy/grype (optional binary); runs against repo source trees and, under `--local`, the running host's installed packages | a HIGH/CRITICAL dependency vulnerability is found |

## Active modules (live targets)

| Module | Target kind | Tier | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `http-probe` | url | active | Probe a live endpoint; at intrusive+ sends `X-Forwarded-Host`/`X-Host`/`Host` injection headers and detects reflection in responses or downstream redirects (Host header injection, CWE-644) | reachable unauthenticated, no TLS, bad cert, or a supplied token is accepted; at intrusive+ HIGH if host header reflected |
| `path-probe` | url | detective | Discover sensitive paths (Spring Actuator `/env` & `/heapdump`, `/.git`, config files, API docs); at intrusive+ re-fetches confirmed credential-bearing paths and extracts live credentials (passwords, API keys, JDBC URLs) | a CRITICAL/HIGH path is reachable unauthenticated |
| `jwt-attacker` | url | active | Live JWT bypass: `alg:none`, claim tampering, weak HS256-secret crack; at intrusive+ probes common admin paths with the accepted token to confirm breadth of access | a forged token is accepted or the signing secret is recovered |
| `cred-tester` | creds | active | Validate credentials; at intrusive+ probes sensitive paths (`/api/users`, `/api/admin`, `/api/me`, `/api/v1/secrets`) with the validated credential to confirm scope of privileged data access | an auth attempt succeeds; at intrusive+ CRITICAL if privileged path returns 2xx |
| `port-probe` | host:port | detective | Reach a network service and fingerprint version/TLS; at intrusive+ sends service-specific probes: Redis `PING` (confirms unauthenticated access, CVE-2022-0543), Memcached `stats`, and Elasticsearch unauthenticated `GET /` (CVE-2015-1427) | a TCP connection is accepted; at intrusive+ CRITICAL if Redis/Elasticsearch/Memcached responds without auth |
| `tls-grader` | url / host:port | detective | Grade transport security | deprecated TLS, weak cipher, or invalid/expired certificate |
| `ssh-probe` | host:port | detective | SSH posture: version banner + `KEXINIT` algorithm proposal — flags weak KEX (SHA-1/1024-bit DH), host-key (`ssh-dss`/SHA-1 `ssh-rsa`), CBC/3DES/arcfour ciphers, MD5/truncated MACs; at intrusive+ (requires `sshpass`) attempts common default credentials (root/root, pi/raspberry, ubuntu/ubuntu, etc.) | *(posture: MEDIUM/LOW; intrusive+: CRITICAL if default cred accepted)* |
| `smtp-probe` | host:port | active | SMTP **open-relay** test (stops at `RCPT`, issues `RSET`/`QUIT` before `DATA` — no mail sent) + STARTTLS / cleartext-AUTH posture; at intrusive+ completes a full `DATA` relay to confirm end-to-end delivery | an external sender+recipient is accepted (open relay) |
| `smtp-enum` | host:port | active | Enumerate valid SMTP users via `VRFY`, `EXPN`, and `RCPT TO` timing | a valid username is confirmed |
| `smtp-inject` | host:port | active | Detect SMTP header injection (CRLF) and command smuggling vulnerabilities | a CRLF or smuggling vector is confirmed |
| `smtp-antispam` | host:port | active | Assess mail-bombing resilience (rate-limit) and spam/spoof filter effectiveness | rate-limit absent or a spoofed mail is accepted |
| `smtp-email-posture` | host:port | active | DNS-based email security posture (SPF/DMARC/DKIM/MX/MTA-STS) for targeted email domains | a critical DNS misconfiguration is found |
| `web-misconfig` | url | active | CORS reflection (Origin+credentials), open redirect, missing security headers / cookie flags; at intrusive+ sends a POST with the evil Origin to confirm CORS bypass on state-changing requests | permissive CORS-with-credentials or an open redirect |
| `web-spider` | url | active | Bounded same-origin authenticated crawl; publishes discovered URLs to other modules; inline-secret detection; at intrusive+ confirms discovered sensitive endpoints are accessible anonymously (no auth token) | a MEDIUM+ secret is found inline in a crawled page; at intrusive+ HIGH if sensitive endpoint accessible unauthenticated |
| `llm-probe` | url | active | Detect LLM endpoints and confirm prompt-injection / system-prompt leakage (benign canary only); at intrusive+ sends a tool-call chain targeting AWS IMDS to detect SSRF via function-calling (OWASP LLM06) | an injection echo or system-prompt leak is confirmed |
| `llm-endpoint-enum` | host:port / url | active | Discover accessible LLM/AI API endpoints (Ollama, OpenAI-compatible, vLLM, Hugging Face TGI) | an unprotected inference endpoint is reachable |
| `dns-recon` | url / host:port | detective | DNS hygiene & zone exposure: AXFR, SPF/DMARC/MTA-STS, open resolver, wildcard; at intrusive+ performs subdomain brute-force (admin, api, dev, staging, vpn, k8s, grafana, etc.) | a zone transfer is accepted, a critical DNS record is misconfigured, or an internal subdomain is discovered |
| `dns-enum` | host:port / url | detective | DNS record enumeration, subdomain brute-force, and certificate-transparency lookup | a hidden subdomain or sensitive DNS record is discovered |
| `reverse-dns` | host:port / netrange | detective | Reverse DNS (PTR) lookup for IPs — maps addresses to hostnames and cloud providers; at intrusive+ TCP-probes resolved hosts on port 22/80/443 to confirm they are live | a hostname or provider mapping is returned; or reachable hosts confirmed |
| `subdomain-takeover` | url / host:port | detective | Detect dangling CNAMEs pointing at unclaimed cloud resources; at intrusive+ queries the provider API (S3/GitHub) to confirm the resource does not exist (no claiming is ever performed) | a takeover-eligible CNAME is found |
| `graphql-probe` | url | detective | Discover GraphQL endpoints; flag introspection, suggestion leakage, batch amplification, depth limit; at intrusive+ invokes safe mutations (non-destructive names only) without auth to confirm missing access controls | introspection enabled, schema leaked, or an unauthenticated mutation executes |
| `api-spec-discovery` | url | detective | Find OpenAPI/Swagger/.well-known specs and unauthenticated sensitive endpoints | an API spec is reachable with unprotected sensitive endpoints |
| `public-storage-enum` | url / cloud | active | Find anonymously-listable public S3/GCS/Azure storage buckets; at intrusive+ downloads the first object from each confirmed bucket to prove anonymous read-access | a public bucket is listable (data leak) |
| `oidc-oauth-misconfig` | url | active | Flag OIDC/OAuth weaknesses: `alg:none`, http endpoints, no PKCE, open registration; at intrusive+ submits an unsigned JWT to the userinfo endpoint to confirm the server actually accepts alg:none | a critical misconfiguration is found; or unsigned JWT bypass confirmed |
| `cache-poisoning` | url | active | Detect unkeyed-header reflection into cacheable responses; at intrusive+ confirms actual poisoning via a unique canary URL (two-step prime+follow-up) without affecting real traffic | a cache-poisoning precondition is detected; or poisoning confirmed on canary URL |
| `saml-misconfig` | url | active | SAML/SSO metadata & endpoint misconfiguration posture; at intrusive+ crafts and POSTs a minimal unsigned assertion to the ACS endpoint to confirm authentication bypass | `WantAssertionsSigned=false` or SHA-1 signatures are found |
| `http2-rapid-reset` | url / host:port | detective | Detect HTTP/2 support and flag CVE-2023-44487 rapid-reset exposure; at intrusive+ establishes an actual h2 TLS connection (ALPN negotiation + CLIENT_PREFACE + SETTINGS frame) to confirm CVE-2023-44487 is reachable — detection only, never sends RST_STREAM flood | HTTP/2 is supported on an unpatched server; at intrusive+ HIGH if h2 connection established |
| `etcd-probe` | host:port | detective | Detect unauthenticated etcd (v2/v3) exposing cluster keys; at intrusive+ reads up to 5 key-value pairs (truncated) to confirm actual data access | etcd answers without auth; or kv values confirmed readable |
| `grpc-reflection` | host:port | detective | Detect exposed gRPC server-reflection, enumerate services and methods; at intrusive+ invokes public-looking methods with empty payload to confirm unauthenticated access | reflection is enabled, leaking the full service API; or method callable without auth |
| `php-cgi-probe` | url | active | Detect PHP-CGI argument injection (CVE-2012-1823, CVE-2024-4577); at intrusive+ sends POST RCE body for CVE-2024-4577 | a PHP argument-injection response is returned or POST RCE body executes |
| `pkg-tls-probe` | host:port / url | active | Probe TLS posture: self-signed certs, missing HSTS, STARTTLS strip opportunity, and downgrade exposure | a high-severity TLS weakness is confirmed |
| `passive-discovery` | host:port / local / netrange | active | Harvest ARP/neighbor cache, listen for mDNS/LLMNR/NBT-NS/SSDP broadcasts, enumerate local interfaces; at intrusive+ TCP-probes discovered hosts on common service ports (22, 80, 443, 8080, 3389, 3306, 5432) to confirm they are reachable | at least one peer or broadcast responder is discovered; at intrusive+ HIGH if services confirmed reachable |

## Network-range discovery & external-tool integrations

`host-sweep` turns a CIDR/IP-range into a list of **live** hosts (unprivileged TCP-connect,
no raw ICMP), then the orchestrator fans the host:port modules out across them. `nmap-probe`
and `nuclei-probe` are **optional**: they auto-detect their binary and degrade to a clean
INFO skip when absent. `cve-enrich` is a post-pass that correlates discovered service
versions with a bundled **offline** CVE feed (no network).

| Module | Target kind | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|
| `host-sweep` | netrange | Liveness sweep across a subnet (TCP-connect on a high-signal probe set); at intrusive+ extends the port sweep to include Redis (6379), MySQL (3306), PostgreSQL (5432), MongoDB (27017), Memcached (11211), Elasticsearch (9200), and other common services | at least one host answers and is probed further |
| `nmap-probe` | host:port / netrange | Service/version detection via nmap **connect-scan** (`-sT -sV`, never `-sS`); NSE is opt-in and runs only SAFE allow-listed categories; at intrusive+ queries the OSV database for CVEs matching discovered product+version banners | an open service/version is fingerprinted; or a live CVE match is confirmed |
| `nuclei-probe` | url / host:port / netrange | Known-vulnerability template scan; always excludes intrusive/dos/fuzz/brute tags, `-no-interactsh`, rate-limited; at intrusive+ makes a live HTTP GET to CRITICAL/HIGH matched endpoints to confirm reachability | a non-info template matches; or a matched endpoint is confirmed reachable |
| `cve-enrich` *(post-pass)* | (all) | Correlate discovered `product+version` banners with a bundled offline CVE feed + EPSS scores + ATT&CK technique tags | a discovered version falls in a known-vulnerable range |

## Cloud-native / infrastructure active modules

Protocol-aware, credential-free probes aimed at the platform stack (Kubernetes,
ingress-nginx, Confluent/Kafka, ArgoCD, service meshes, and common datastores). All are
read-only.

| Module | Target kind | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|
| `k8s-probe` | host:port | Unauthenticated Kubernetes control plane (API server anonymous-auth, kubelet, etcd) plus CVE-2019-11248, CVE-2025-0426, CVE-2024-9042 and anonymous `/configz`; at intrusive+ creates a labelled ConfigMap then immediately deletes it to confirm anonymous write access | a component answers anonymously; or anonymous write confirmed |
| `k8s-service-enum` | host:port / url | Enumerate K8s services, ingresses, HTTPRoutes, VirtualServices, ConfigMaps, webhooks, NetworkPolicies for lateral-movement URL discovery; at intrusive+ probes up to 3 discovered service URLs directly to confirm cross-cluster access | a reachable internal service or pivot URL is discovered |
| `service-mesh-probe` | host:port / url | Detect service-mesh sidecars (Envoy/Istio) via admin ports and enumerate upstream clusters/routes; at intrusive+ re-fetches `/config_dump` and extracts embedded secrets (inline_string, PEM certificates) | sidecar admin port is exposed and upstream clusters are enumerable |
| `ingress-nightmare` | url / host:port | IngressNightmare CVE matrix (CVE-2025-1974/1097/1098/24513/24514) + admission-webhook reachability + project-EOL flag; at intrusive+ sends a benign `AdmissionReview` POST to confirm webhook reachability | a controller below 1.11.5/1.12.1 is detected, or any version on the archived project |
| `unauth-service-probe` | host:port | Open datastores/daemons (Redis, Memcached, Elasticsearch/OpenSearch, MongoDB, Docker API, registry, Prometheus, Postgres); at intrusive+ confirms write access via SET+DEL on Redis or PUT+DELETE doc on Elasticsearch | a service answers without auth; or write confirmed |
| `kafka-probe` | host:port | active | Detect open Confluent/Kafka stack (broker, Schema Registry, Connect, REST Proxy); at intrusive+ consumes first offset-0 message from REST Proxy to confirm data access | a broker or REST service answers unauthenticated; or message consumed |
| `metadata-ssrf` | url | active | SSRF → cloud metadata (AWS/GCP/Azure IMDS) credential theft; at intrusive+ reads the full AWS IAM role credential JSON (AccessKeyId + Expiration only — SecretAccessKey redacted) | IMDS content reflected; or full AWS role credential confirmed |
| `argocd-probe` | url | ArgoCD exposure + version advisories (CVE-2024-21652/21661, CVE-2025-55190, CVE-2026-42880) and `/api/webhook` DoS reachability; at intrusive+ fetches the first app's manifests and `/api/v1/repositories` for credential leakage (CVE-2025-55190 surface) | an old/affected version or unauthenticated API listing |
| `kyverno-probe` | url / host:port | Kyverno admission-controller exposure via `:8000/metrics` + version-advisory map (GHSA-8wfp-579w-6r25, GHSA-qr4g-8hrp-c4rw) | the metrics endpoint answers anonymously or an affected build is fingerprinted |
| `cloud-recon` | cloud | active | Credentialed read-only cloud recon: current identity + IAM inventory (AWS/GCP/Azure); at intrusive+ fetches public S3 bucket contents to confirm anonymous data access | an identity with sensitive permissions is discovered; or a public bucket is confirmed readable |
| `cloud-iam-analyzer` | cloud | active | Simulate effective permissions via `iam:SimulatePrincipalPolicy` / `testIamPermissions`, walk role-assumption chains, flag IAM privesc primitives; at intrusive+ calls `sts:GetCallerIdentity` to confirm the credential is live (ARN verified) | a sensitive permission or escalation path is reachable; or live credential ARN confirmed |
| `cloud-enum` | cloud | active | Credentialed read-only enumeration of internet-exposed cloud resources (S3, ECS, Lambda, GCS, Functions, Azure Storage, etc.) | an exposed or publicly readable resource is found |
| `cloud-service-exposure` | cloud | active | Credentialed read-only service exposure: AWS Lambda/SNS/SQS/Secrets/SSM/KMS/Transfer + GCP Storage/Functions + Azure Storage/Key Vault | an over-exposed service or leaked secret is found |
| `cloud-posture` | cloud | active | Read-only cloud security-posture review: CloudTrail logging, public AMIs/EBS snapshots, IAM password policy, root access keys, MFA status | a critical posture gap |
| `cloud-lateral` | cloud | active | Walk assume-role/impersonation chains to map cross-account/cross-project lateral movement (simulation only — no AssumeRole executed without `CLOUD_LATERAL_ACTIVE_ASSUME=True`); at intrusive+ confirms the lateral movement surface with a summary finding and, if `CLOUD_LATERAL_ACTIVE_ASSUME=True`, marks active AssumeRole candidates | a reachable lateral-movement path is mapped |
| `cloud-pivot` | cloud | active | Map SSM-reachable EC2 instances and simulate `ssm:SendCommand`/`StartSession` (NEVER executed); at intrusive+ TCP-probes discovered instance IPs to confirm they are network-reachable from the scanner | a simulated SSM path to internal hosts is reachable; or host TCP-confirmed at intrusive+ |

## Intrusive modules (require `--intensity intrusive` + `--scope`)

These do **multi-request** guessing/enumeration. They never run on a default (`active`)
run, always require a scope allow-list, and each is lockout-/rate-aware.

| Module | Target kind | Tier | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `default-creds` | url / host:port | intrusive | Lockout-aware default-credential spraying (≤3 pw/account, aborts on 429). Needs `--spray`. At proof+ fetches a privileged endpoint using the won credential to demonstrate post-auth data access. | a default/weak credential authenticates |
| `content-discovery` | url | intrusive | Bounded, rate-aware path brute-forcing with soft-404 calibration | a hidden admin/config/backup/API path is reachable |
| `active-confirm` | url | intrusive | Confirm reflected-parameter injection + canary-only SSRF | a verbatim reflection or confirmed SSRF canary-hit |
| `k8s-enum` | host:port | intrusive | Credentialed read-only k8s enumeration + `SelfSubjectRulesReview`; at proof+ reads the first Secret's values to confirm credential theft capability | the token can list Secrets or holds a dangerous verb |
| `proto-auth` | host:port | intrusive | Default-community / anonymous auth on SNMP, FTP, LDAP, SMB, NFS; at proof+ does a MIB walk with accepted community (sysContact/sysName/sysLocation) for richer device identity disclosure | a default community or anonymous auth is accepted |
| `broker-auth` | host:port | intrusive | Probe MQTT/AMQP brokers for anonymous or default auth; at proof+ sends a wildcard `SUBSCRIBE #` to the confirmed anonymous MQTT broker to capture all published messages | an anonymous/default-cred broker connection is accepted |
| `db-auth` | host:port | intrusive | One non-brute attempt per DB engine (PostgreSQL trust, MySQL blank root, MSSQL fingerprint, Oracle TNS) | a trust/blank-password/anonymous database accepts the connection |
| `api-idor` | url | intrusive | Confirm BOLA/IDOR with read-only cross-identity requests (GET only, CWE-639) | a user can read another user's object |
| `deserialization-probe` | url | intrusive | Detect insecure-deserialization sinks + confirm via benign OOB canary; at intrusive+ (no canary) uses error-differential on truncated serialized objects to confirm live deserializer | a deserialization sink is reachable and confirmed |
| `shellshock-probe` | url | intrusive | Confirm Bash Shellshock (CVE-2014-6271/CVE-2014-7169) RCE via HTTP header injection in CGI endpoints; runs proof marker (echo + id) on confirmation | the canary is reflected and `id` output is captured |
| `ssti-confirm` | url | intrusive | Confirm SSTI via arithmetic evaluation; at intrusive+ attempts engine-specific `id` RCE confirmation | arithmetic result confirms template evaluation; or RCE confirmed |
| `sqli-confirm` | url | intrusive | Confirm SQLi via error/boolean/time-based signals; at intrusive+ attempts UNION SELECT canary for data-extraction proof | injection confirmed; or canary reflected in UNION SELECT |
| `xxe-confirm` | url | intrusive | Confirm XXE via internal-entity expansion + OOB canary; at intrusive+ reads `/etc/hostname` to confirm file-read capability | entity expansion or OOB canary hit; or file-read confirmed |
| `path-traversal-confirm` | url | intrusive | Confirm LFI/traversal via non-secret OS-file signatures (/etc/passwd, win.ini); at proof+ attempts /proc/self/environ to expose process environment variables | a traversal returns a known OS-file signature; or env vars confirmed |
| `request-smuggling` | url | intrusive | Timing-only CL.TE/TE.CL desync detection (never poisons a victim request) | an ambiguous request stalls measurably vs baseline |
| `cmd-inject-confirm` | url | intrusive | Confirm OS command injection via a benign arithmetic canary (`expr`) — never executes destructive commands | the computed arithmetic result is returned in the response |
| `ssh-auth` | host:port | intrusive | Lockout-aware SSH credential spraying and discovered-key verification | a credential or key authenticates |
| `smtp-auth-spray` | host:port | intrusive | Lockout-aware SMTP AUTH credential spraying (PLAIN/LOGIN) | a credential authenticates via SMTP AUTH |

## High-impact CVE RCE/DoS detection modules

Targeted probes for critical named vulnerabilities. Four are `intrusive` (require
`--intensity intrusive` + `--scope`); `slowloris-probe` is `active`.

When a finding from any of these modules is confirmed via `[ri]` in `triage.py`, the
exploitation menu automatically routes to the appropriate live-exploitation path —
reverse shell listener, module re-run with OOB canary, or bounded DoS demonstration.
Every live action requires typing `yes` in full before it fires.

| Module | Target kind | Tier | CVE / CWE | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|---|---|
| `log4shell-probe` | url / host:port | intrusive | CVE-2021-44228, CVE-2021-45046 | JNDI injection via 10 HTTP headers (User-Agent, X-Forwarded-For, X-Api-Version, …); WAF-bypass obfuscation variants; timing differential + optional OOB canary | JNDI callback received on OOB canary; or >2500 ms timing differential with JNDI error string match |
| `struts-rce-probe` | url | intrusive | CVE-2017-5638 (S2-045), CVE-2020-17530 (S2-061), CVE-2018-11776 (S2-057) | OGNL expression injection via Content-Type header; arithmetic canary (A×B) confirms evaluation; 20 common Struts action paths probed | computed arithmetic product reflected in HTTP response |
| `ms17010-probe` | host:port | intrusive | CVE-2017-0144 (EternalBlue / MS17-010) | Raw SMBv1 negotiate + Transaction2 STATUS differential to detect unpatched MS17-010; OS version fingerprint from negotiate response | Transaction2 response indicates unpatched Windows kernel |
| `activemq-rce-probe` | host:port | intrusive | CVE-2023-46604 | OpenWire WIREFORMAT_INFO banner parsed for version; optional ClassInfo frame sent to OOB canary to confirm broker-initiated URL fetch | vulnerable version in range (5.x before 5.15.16/5.16.7/5.17.6/5.18.3); or OOB canary receives ClassInfo fetch |
| `slowloris-probe` | url / host:port | active | CWE-400 / CWE-770 | Bounded incomplete HTTP connection hold test: 5 connections, 3 s hold, keep-alive partial headers sent every 1.5 s; counts connections surviving the hold period | ≥3 of 5 partial connections survive the hold period (server lacks per-client connection timeout) |

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
| `zap-passive-scan` | url | detective | ZAP-style passive response analysis (security headers, info leakage, cookie flags, PII/IP/stack traces in body, CORS, clickjacking, session-in-URL, mixed content); at intrusive+ sends an active CORS probe with `Origin: https://evil.sectest.internal` to confirm reflection | findings generated per detected issue; at intrusive+ CORS bypass CONFIRMED if origin is reflected |

## Extended cloud providers

| Module | Target kind | Tier | Attack simulated | Outcome |
|---|---|---|---|---|
| `cloud-multicloud-enum` | cloud | active | Resource enumeration on Scaleway, DigitalOcean, Hetzner, Linode, Vultr, Confluent Cloud, OCI, Nutanix, Alibaba Cloud, OVH Public Cloud using discovered credentials | finding per accessible resource |

## Network appliance modules

| Module | Target kind | Tier | Attack simulated | Outcome |
|---|---|---|---|---|
| `cisco-probe` | hostport / cloud | active | Cisco infrastructure enumeration: Meraki, ASA/FTD (interfaces/ACLs/routes), ISE (network devices/endpoint groups), Catalyst Center; at intrusive+ pulls ASA full running config via `/api/v1/cli?command=show+running-config` | finding per enumerated resource |
| `network-device-enum` | hostport / cloud | active | F5 BIG-IP enumeration (virtual servers/pools/nodes/iRules/ASM policies) and Fortinet FortiGate enumeration (policies/interfaces/routes/VPN tunnels/SSL-VPN); at intrusive+ pulls F5 `/mgmt/tm/sys/config` or FortiGate `system/global` config | finding per enumerated resource |

## Local introspection modules (`--local`)

Read-only modules that inspect **the host the scanner runs on**. Never modify files, never
open outbound connections beyond what the specific module needs.

| Module | Target kind | Tier | What it detects | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `container-escape-detector` | local / host:port | detective | Container-escape preconditions (dangerous caps, mounted Docker/CRI sockets, writable host bind-mounts, shared PID namespace, vulnerable runc CVEs); remotely: unauthenticated Docker/kubelet API; at intrusive+ creates and immediately deletes a benign `hello-world` container via the Docker API to confirm escape capability | a CRITICAL/HIGH escape precondition or exposed runtime API |
| `rootkit-ioc-detector` | local | detective | Linux rootkit/eBPF-implant IOCs: `LD_PRELOAD` hooking, LKM rootkit modules (Diamorphine/Reptile/Suterusu/KoviD/…), hidden modules, rootkit symbols in `/proc/kallsyms`, pinned eBPF implants; at intrusive+ runs `lsmod` and checks for additional known bad module names | a CRITICAL/HIGH rootkit IOC is present; at intrusive+ CRITICAL if lsmod confirms a known rootkit module name |
| `linux-privesc` | host:port / local | detective | Detect Linux privilege-escalation preconditions: kernel CVEs, SUID binaries, sudo misconfig, Docker group, writable cron (local + SSH fingerprint); at intrusive+ with SSH credentials uses nmap `ssh-run` NSE to remotely enumerate SUID binaries and match against GTFOBins | a HIGH/CRITICAL escalation vector is found |
| `sbom-scan` | local / repo | detective | Software-composition vulnerability scan via trivy/grype against installed packages (local) or the repo source tree | a HIGH/CRITICAL dependency vulnerability is found |

See [local-introspection.md](local-introspection.md) for full details.

## On-site / physical assessment modules

Modules for **physical penetration tests** and **on-site network assessments**. All require
`--local` (or being deployed via propagation onto a foothold). WiFi/Bluetooth/router modules
gate active scans behind `is_local or is_propagated`.

| Module | Target kind | Tier | Attack simulated | Outcome = EXPLOITED when… |
|---|---|---|---|---|
| `wifi-probe` | local | active | WiFi network discovery: SSID enumeration, encryption posture (open/WEP/WPS/WPA2/WPA3); at intrusive+ attempts to connect to open networks via `nmcli` or runs `wash` to confirm WPS-enabled networks. On exploitation, adds gateway IP and local subnet to `pivot_targets` for downstream sweep. | an open, WEP, or WPS-enabled network is found; at intrusive+ CRITICAL if nmcli connect succeeds |
| `bluetooth-probe` | local | active | Bluetooth device discovery: discoverable devices, pairing mode, exposed RFCOMM/SPP services, GATT service enumeration (Nordic UART, vendor serial UUIDs → pivot relay); at intrusive+ runs `l2ping` to confirm L2CAP reachability of RFCOMM devices | a discoverable device exposes an RFCOMM/BLE shell service; at intrusive+ HIGH if L2CAP ping confirmed |
| `router-probe` | host:port / local / netrange | active | Router/gateway fingerprint, admin panel exposure, Telnet/TR-069 open ports, UPnP IGD, default-firmware CVE hints; at intrusive+ attempts common default credentials (admin/admin, admin/password, etc.) against detected admin panels | a management interface is reachable unauthenticated |
| `android-probe` | host:port / local / netrange | active | Android device discovery via ADB (port 5555), developer debug-mode detection, mDNS `_adb._tcp`; at intrusive+ runs `pm list packages` via ADB shell to enumerate installed apps including sensitive banking/MDM apps | an ADB-exposed device is reachable |
| `ios-probe` | host:port / local / netrange | active | iOS device discovery via iTunes sync (port 62078), Bonjour/mDNS, and jailbreak SSH indicators; at intrusive+ attempts SSH login with common jailbreak default credentials (root/alpine, mobile/alpine, root/dottie) | an accessible iOS device is fingerprinted |
| `device-posture` | local | detective | Post-propagation device assessment: privilege level, sandbox detection, local services on `127.0.0.1` (`ss`/`netstat`/`/proc/net/tcp`), WiFi/BT adapter presence, ARP peer discovery → `pivot_targets`, OS fingerprint; at intrusive+ if running as root reads `/etc/shadow` header (5 lines), or if `CAP_SYS_PTRACE` is present reads `/proc/1/environ` to confirm privileged access | *(posture report; HIGH/CRITICAL if privileged services exposed; CRITICAL at intrusive+ if shadow readable or PTRACE abusable)* |
| `privesc-exploit` | local | intrusive | Attempt local privilege escalation: SUID GTFOBins, sudo NOPASSWD, password spray (≤5 attempts), CVE detection (DirtyPipe/DirtyCow/PwnKit/Baron Samedit/OverlayFS), misconfiguration checks. Verification-only (`id`); writes a single labelled proof marker. | root is obtained by any method |
| `router-auth` | host:port / netrange | intrusive | Firmware-specific default credential testing on router/firewall admin panels (OpenWRT, DD-WRT, MikroTik, pfSense, ASUS, TP-Link, D-Link, Netgear, Zyxel, …). ≤6 attempts per host, 1 s delay | a default credential authenticates |
| `cve-autopwn` | host:port | intrusive | CVE-driven automated exploit verification: banner-grab to fingerprint service+version, resolve matching CVEs from offline feed (101 records, 32 product families) + NVD cache, prioritise with EPSS×CVSS score, execute verification plans (nuclei_template, banner_match auto; script_poc/llm_generated require confirmation). Safe-mode only — no destructive actions. | a CVE plan is confirmed: version-in-range (banner_match), template match (nuclei_template), or script PoC returns `RESULT:True` |
