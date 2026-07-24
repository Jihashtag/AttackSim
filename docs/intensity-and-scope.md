# Intensity Tiers & Scope

Every active module declares a minimum **intensity** and the orchestrator only runs it
when the run is at least that aggressive (`--intensity`, default `active`). Two controls
are enforced **in code**, not merely documented.

## Tiers

| Tier | What it permits | Example modules |
|---|---|---|
| `detective` | read-only fingerprinting | `path-probe`, `k8s-probe`, `tls-grader`, `port-probe`, `ssh-probe`, `dns-recon`, `graphql-probe`, `etcd-probe`, `http2-rapid-reset`, `sbom-scan`, `zap-passive-scan` |
| `active` | bounded single-shot interactions (one auth attempt, one redirect, one CORS probe) | `http-probe`, `web-misconfig`, `smtp-probe`, `web-spider`, `llm-probe`, `cloud-enum`, `cloud-service-exposure`, `cloud-posture`, `cloud-pivot`, `nmap-probe`, `nuclei-probe`, `owasp-scan`, `cloud-multicloud-enum` |
| `intrusive` | multi-request guessing/enumeration | `default-creds`, `content-discovery`, `active-confirm`, `db-auth`, `sqli-confirm`, `xxe-confirm`, `path-traversal-confirm`, `request-smuggling`, `k8s-enum`, `proto-auth`, `broker-auth`, `api-idor`, `ssti-confirm`, `deserialization-probe` |
| `proof` *(peak)* | creates a harmless, persistent, labelled artifact | `access-prover`, `git-push-proof`, `git-cli-proof`, `waf-firewall-proof`, `datastore-access` |
| `fuzz` *(peak)* | bounded, rate-limited mutational input testing (never a DoS) | `fuzz-probe` |

## Scope enforcement (v2 — confirmation-based)

**The previous mandatory allow-list model has been replaced.** The new scope model:

- **Scope = target-derived.** The initial target (host, CIDR, URL domain) IS the scope.
  On propagation hops, the scope widens to include the proven foothold's subnet.
- **Mandatory confirmation at `intrusive` and above.** Either:
  - Pass `--yes` in CLI args (non-interactive acknowledgement), OR
  - Answer the interactive `[y/N]` prompt at runtime.
- **Optional narrowing.** `--scope` entries (hosts, CIDRs, domains) can still be passed
  to RESTRICT what the scanner touches. They are no longer mandatory.
- Every intrusive/fuzz request is additionally `authorize`-checked, so an explicitly-scoped
  host that falls outside the narrowing is skipped.

**Empty allow-list is permissive by design.** When no `--scope` narrowing is supplied,
`authorize()` returns true at intrusive+ on the strength of the operator's confirmation —
the confirmed target *is* the scope, and there is no per-host allow-list gate. A
**propagated** instance inherits this same model: a scanner deployed on a foothold operates
under the operator's original global confirmation and may sweep the foothold's own subnet.
When matching a hostname against CIDR scope entries, the guard may perform a DNS
resolution. Operators who require a hard per-host boundary (e.g. to keep a foothold from
reaching neighbouring production subnets) must pass an explicit `--scope` allow-list; this
is the intended control for that case.

## Peak tiers

`proof` and `fuzz` are peaks, not "more dangerous than intrusive". Each is unlocked
only when `--intensity` equals that peak *and* its own opt-in is present:

- `--prove-access` for proof
- `--intensity fuzz` for fuzz

A peak run still includes the full `detective..intrusive` base first.

## Examples

```bash
# intrusive run (--yes confirms; no --scope needed):
python3 main.py https://target.example --intensity intrusive --yes --spray

# intrusive with optional scope narrowing:
python3 main.py https://target.example --intensity intrusive --scope target.example --yes

# fuzz peak (confirmation required):
python3 main.py https://target.example --intensity fuzz --yes

# proof with WAF/firewall + git CLI exploitation:
python3 main.py --use-discovered-cloud-creds --prove-access --yes

# interactive mode (will prompt):
python3 main.py 10.0.0.5:6443 --intensity intrusive
```

## Configuration via environment variables

All config constants can be overridden via `SECTEST_<CONSTANT_NAME>` env vars:

```bash
export SECTEST_HTTP_TIMEOUT=12
export SECTEST_GLOBAL_RATE_LIMIT=100
python3 main.py https://target.example --yes
```

The config is also discovery-updatable (e.g., VPC endpoints found during enumeration
replace defaults) and forwardable on propagation.

## Profiles

Profiles are presets that combine intensity, parallelism, and rate settings:

| Profile | Intensity | Jobs | Notes |
|---|---|---|---|
| `quick` | detective | high | Fast fingerprinting only |
| `standard` | active | default | The default behavior |
| `deep` | intrusive | default | Requires confirmation |
| `stealth` | active | low | Low parallelism + low rate |

Explicit `--intensity` and `--jobs` always override profile settings.
