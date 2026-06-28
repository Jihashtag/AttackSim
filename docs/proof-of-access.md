# Proof-of-Access

The `access-prover` module turns a *detected* exposure into an *undeniable* one. It is
**off by default** and requires explicit opt-in via `--prove-access`.

## Safety contract (enforced in code)

- **Allowed:** create a **harmless, clearly-labelled artifact** — a marker file on any
  writable/compromised filesystem, a benign datastore key/doc, or a throwaway container —
  and/or hand an interactive shell handle back to the operator.
- **Artifacts PERSIST by design.** They are not self-expiring and not auto-cleaned, so the
  blue team can independently discover and verify them. Every artifact is inert and labelled
  `AUTHORIZED-ASSESSMENT … safe to delete`.
- **Forbidden, always:** configuration changes, data destruction/modification, encryption,
  DoS, privilege escalation, rootkits/implants/backdoors.

## Opt-in flags

| Flag | Effect |
|---|---|
| `--prove-access` | Enable all proof types (writes + shell) |
| `--prove-access-writes` | Enable write-proof only (marker files, datastore keys) |
| `--prove-access-shell` | Enable shell-proof only (persistent container) |

## Centralized post-exploit hook

Every module that returns `exploited=True` at `intrusive+` intensity automatically
triggers a **post-exploit hook** in the orchestrator (`exploits/post_exploit.py`). The
hook does two things without requiring any module-specific code:

1. **Propagation**: registers the foothold in `target.pivot_targets` so the orchestrator
   re-runs the scanner from or alongside the compromised host. Idempotent — modules that
   already manage their own pivot entries (e.g. `ssh-auth`) are skipped.
2. **Local proof receipt**: when `--prove-access` is active, writes a labelled
   `SECTEST_PROOF_<module>_<host>_<port>_<ts>.txt` file to `/tmp` (or `$SECTEST_PROOF_DIR`)
   as a scanner-side audit trail of the confirmed exploitation.

Modules with actual **command execution** on the target (cmd-inject-confirm, shellshock-probe,
ssh-auth, ssti-confirm at intrusive+, php-cgi-probe at intrusive+) additionally write the
shared proof marker (`echo "..." && id && /tmp marker file`) **on the target system** via
their respective execution channel when `--prove-access` is set.

## Implemented proofs

### Docker Engine API (`:2375`/`:2376`)

Spawns a throwaway container that bind-mounts the host's `/tmp` and writes one harmless,
labelled marker file onto the **real Docker host** at `/tmp/sectest_proof_*.txt`, reads it
back, and leaves it in place. The marker persists as durable evidence of host-root-equivalent
control; no existing host data is read, changed, or deleted.

### Redis (`:6379`, no-auth)

`SET` one harmless, labelled marker key and `GET` it back. The key has no TTL and is not
deleted — it persists as evidence (no `CONFIG`/`SAVE`/module commands).

### Elasticsearch/OpenSearch (`:9200`, no-auth)

Index one harmless, labelled doc into a dedicated `sectest-canary` index. The index and doc
persist as evidence.

### Interactive shell-handle (Docker)

Spawns a **persistent** (`AutoRemove=False`) container running an idle TTY shell (with the
host `/tmp` bind-mounted so a marker is written immediately), and hands the operator the
exact `attach` command. This proves live code execution and hands control to the authorised
operator. Both the container and the host marker persist.

### Cloud (AWS / GCP / Azure)

Creates one clearly-labelled principal that **grants nothing and holds no usable credential**:

- **AWS**: IAM user with explicit deny-all inline policy, no access key
- **GCP**: service account with no keys and no role bindings
- **Azure**: custom role definition with empty permissions and no assignment

See [cloud-assessment.md](cloud-assessment.md) for full cloud proof details.

### Local privilege escalation (`privesc-exploit`)

When `privesc-exploit` (intrusive tier) gains root on a local target, it writes:

```
/tmp/SECTEST_PRIVESC_PROOF_<pid>_<ts>.txt
```

Content: labelled marker (`AUTHORIZED-ASSESSMENT`) plus the escalation method (SUID,
sudo, CVE ID, or password spray) and the output of `id` confirming root. No persistent
shell is left open, no data is exfiltrated, no config is changed. The file persists so
the blue team can verify the escalation path.

## 360° lateral sweep from proven footholds

When `access-prover` **proves** access to a device (CRITICAL/HIGH proof), the toolkit
treats that device as a foothold and **broadens the audit to its subnet** — exactly what a
real attacker who lands on a box does next.

The prover derives the device's subnet (default `/24`) and publishes it as a `pivot_targets`
entry; the orchestrator then runs an unprivileged TCP-connect liveness sweep over that
subnet and re-runs the standard host:port modules against every live peer.

### Guardrails

- **Scope-gated.** Every candidate host is `scope_guard.authorize`d before being touched.
  The target-derived scope naturally includes the foothold's subnet.
- **Bounded.** Expansion is capped by `PIVOT_SUBNET_MAX_HOSTS`, `PIVOT_MAX_DEPTH`, and
  `PIVOT_WALL_BUDGET`.
- **Read-only discovery.** The sweep is TCP-connect liveness only; no host data is touched
  until the normal host:port modules run.

## Foothold-relayed scanning (multi-hop)

A scanner-side sweep only sees what the *scanner* can route to. To reach genuinely
segmented next hops, the probe must run **from the foothold's network position** —
that is what a *relay* does ([`sandbox/relay.py`](../sandbox/relay.py)).

### Relay types

- **Docker relay** — a throwaway, auto-removed, connect-only `busybox` container that
  TCP-tests the next-hop hosts from inside the foothold. No bind mounts, no writes.
- **Proxy relay** — an operator/relay-positioned HTTP-CONNECT or SOCKS5 tunnel
  (`--pivot-proxy`, e.g. `ssh -D` SOCKS proxy through the foothold).
- **Named cross-cloud next hops** — a module can publish a URL next hop (Cloud Run /
  internal HTTPS endpoint), probed through the relay proxy.

This makes chains like `scanner → ECS (proven) → EKS (reachable) → Cloud Run (reachable)`
detectable and provable hop-by-hop.

> SSM-managed EC2 footholds remain simulate-only: `ssm:SendCommand`/`StartSession` are
> never executed, so that hop is recorded as *simulated* rather than relayed through.

## Proof-of-access ledger

The shared **proof-of-access ledger** ([`sandbox/ledger.py`](../sandbox/ledger.py)) records
one entry per reached resource — which resource, the foothold it was reached from, the relay
used, the proof, and its scope status. It reconstructs end-to-end paths:

```
Lateral-movement path (3 hops): scanner -> 10.0.0.5:2375 (proven) -> 10.0.0.10:6443 (reachable) -> https://cr.run.app (reachable)
```

The `attack-chain` pass adds a *Proven foothold → lateral movement to internal resource*
chain when a proven foothold is followed by recorded movement.

## Examples

```bash
# Detect first (default, purely read-only):
python3 main.py 10.0.0.5:2375,6379,9200

# Prove confirmed exposures (enables 360° lateral sweep):
python3 main.py 10.0.0.5:2375,6379,9200 --prove-access --yes

# Single proof type:
python3 main.py 10.0.0.5:9200 --prove-access-writes --yes
python3 main.py 10.0.0.5:2375 --prove-access-shell --yes
```

## WAF / Firewall proof (`waf-firewall-proof`)

Proves write-access to network-layer security controls by inserting the **lowest-priority,
non-destructive allow rule** using a private CIDR (`10.0.0.0/8`). This avoids disruption
because all default deny/block rules take precedence.

### Supported targets

| Platform | Resource type | API used |
|---|---|---|
| AWS WAFv2 | WebACL (Regional & CloudFront) | `wafv2:UpdateWebACL` |
| AWS Security Group | VPC SG ingress | `ec2:AuthorizeSecurityGroupIngress` |
| GCP Cloud Armor | Security policy | `compute.securityPolicies.patchRule` |
| GCP VPC Firewall | Firewall rule | `compute.firewalls.insert` |
| Azure NSG | Network security group | `networkSecurityGroups/securityRules` PUT |
| F5 BIG-IP | AFM firewall policy | `POST /mgmt/tm/security/firewall/policy/{name}/rules` |
| Fortinet FortiGate | Firewall policy | `POST /api/v2/cmdb/firewall/policy` |
| Cisco Meraki | L3 firewall rules | `PUT /networks/{id}/appliance/firewall/l3FirewallRules` |
| Cisco ASA/FTD | Access rules (ACL) | `POST /api/access/in/{interface}/rules` |
| DigitalOcean | Cloud firewall | `POST /v2/firewalls/{id}/rules` |
| Hetzner Cloud | Firewall rules | `POST /v1/firewalls/{id}/actions/set_rules` |
| Scaleway | Security group rules | `POST /instance/v1/zones/{zone}/security_groups/{id}/rules` |
| Vultr | Firewall rules | `POST /v2/firewalls/{group_id}/rules` |
| OCI | Security lists | `PUT /20160918/securityLists/{id}` |
| Nutanix Flow | Network security rules | `POST /api/nutanix/v3/network_security_rules` |
| Host-level | iptables / nftables / ufw | `iptables -I` / `nft add rule` / `ufw insert` |

### Safety guarantees

- **Private CIDR only** — `10.0.0.0/8` (RFC 1918) is used exclusively
- **Lowest priority** — priority 99999 (or equivalent highest-number/lowest-precedence)
- **Allow direction** — avoids disrupting existing deny rules
- **Labelled** — description/comment/tag: `sectest-proof-of-access`
- **Simulate first** — dry-run API where available (AWS WAFv2, GCP) before real insert
- **Single rule** — only one rule created per WAF/firewall resource

## Git CLI proof (`git-cli-proof`)

Detects GitHub CLI (`gh`) or GitLab CLI (`glab`) on the target/foothold and exercises
supply-chain write access:

1. **Create a proof repository** — new private repo clearly labelled
   `AUTHORIZED-ASSESSMENT-PROOF-<timestamp>`
2. **Push markers to accessible repos** — iterates all repos the authenticated identity
   can push to, creates branch `sectest-proof-<timestamp>`, pushes a single marker file

### Safety guarantees

- Proof branches never overwrite existing branches (unique timestamp suffix)
- Marker files are small, clearly labelled, inert text
- Never touches main/master/develop branches
- Proof repos are created as private
