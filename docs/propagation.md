# Self-Propagation

When access to a foothold is **proven** (via `--prove-access`), the toolkit can **deploy
itself onto the foothold and run a scan from inside** — reaching network segments invisible
to the scanner. This is the deepest form of lateral-movement assessment.

## Discovery-driven chaining (intrusive+)

Propagation is the deepest hop of a broader rule: **at `intrusive` intensity and above,
any discovery becomes a follow-on attempt.** Two mechanisms implement this, both gated to
intrusive+ (nothing chains on a `detective`/`active` run):

- **Auto host pivot.** The orchestrator's post-exploit hook registers *every* module result
  with `exploited=True` as a pivot on the target host — so a confirmed weakness is always
  re-probed and escalated.
- **Discovered-other-host / URL publication.** Discovery modules that surface hosts,
  services, or URLs *other than the run's own target* publish them via the shared
  `exploits.post_exploit.publish_pivot()` / `publish_url()` helpers (scope-checked, deduped).
  Examples: `dns-enum` (resolved records/subdomains), `cloud-enum` (public EC2 IPs),
  `cloud-pivot` (SSM subnet peers), `reverse-dns`/`passive-discovery`/`port-probe` (peers),
  `forbidden-bypass` (a now-reachable endpoint), and the on-site probes (gateway/subnet).

Queued pivots are drained by `_fanout_pivots()`, which runs the full host:port module set
against each — so discovery → chain → escalate → (with `--prove-access`) propagate is a
single continuous flow once the run is at intrusive+.

## Usage

```bash
# Prove access, then propagate the scanner INTO the proven foothold:
python3 main.py 10.0.0.5:2375 --prove-access --propagate-script --scope 10.0.0.0/24 --yes

# Limit propagation depth (decremented each hop; 0 = no further propagation):
python3 main.py 10.0.0.5:2375 --prove-access --propagate-script --propagate-depth 1 \
  --scope 10.0.0.0/24 --yes

# Provide explicit subnet context for the propagated scan:
python3 main.py 10.0.0.5:2375 --prove-access --propagate-script --host-subnet 10.0.0.0/24 \
  --scope 10.0.0.0/24 --yes
```

## Safety model

| Guardrail | Enforcement |
|---|---|
| Requires `--prove-access` | Propagation only happens onto already-proven footholds |
| Requires explicit confirmation | Interactive prompt or `--yes` |
| Depth-bounded | `--propagate-depth` (default: 2) decremented each hop; at 0 no further propagation |
| Cleanup | Deployed payloads removed after execution (`PROPAGATE_CLEANUP=True`) |
| Scope-gated | All targets on the propagated hop pass through `authorize()`. The propagated instance inherits the parent's **target-derived** scope model: with no explicit `--scope` allow-list it operates under the operator's original confirmation and may sweep the foothold's subnet (see [intensity-and-scope.md](intensity-and-scope.md)). Pass an explicit `--scope` to impose a hard per-host boundary on propagated hops. |

## Behavior

1. **Packing** — the scanner is packed into a self-contained deployment payload
   ([`sandbox/propagate.py`](../sandbox/propagate.py))
2. **Deployment** — the payload is deployed onto the proven foothold (Docker container,
   SSH, etc.)
3. **Execution** — the propagated instance runs from inside the foothold's network position
4. **Result collection** — findings from the propagated scan are merged back into the
   parent run
5. **Cleanup** — the deployed payload is removed

## Arg inheritance

Propagated instances inherit governance flags from the parent:

- `--prove-access`, `--intensity`, `--scope`, `--spray`
- `--cve-lookup`, `--cve-test`, `--cve-max`
- `--propagate-depth` (decremented by 1)
- `--yes` (non-interactive acknowledgement)

## Adaptive parallelism

The propagated instance auto-detects available CPU/memory on the foothold
([`sandbox/resources.py`](../sandbox/resources.py)) and adjusts `--jobs` accordingly.

## LLM auto-detection

The deploy script auto-detects Ollama availability on the foothold (localhost,
`host.docker.internal`) to enable LLM briefings on propagated hops.

## Related: relay scanning (`--propagate`)

The `--propagate` flag enables relay-through-foothold scanning — routing traffic through
the foothold without deploying the full scanner. See [proof-of-access.md](proof-of-access.md)
for relay details.

## Git CLI propagation (`git-cli-proof`)

When `gh` (GitHub CLI) or `glab` (GitLab CLI) is discovered on a foothold, the
`git-cli-proof` module exercises supply-chain write access:

- **Creates a new proof repository** clearly labelled `AUTHORIZED-ASSESSMENT-PROOF-<ts>`
- **Creates a new proof user/identity** if the platform supports it (GitLab)
- **Pushes a marker branch** into all accessible repositories

This demonstrates the blast radius of a compromised CI/CD runner or developer workstation.

## Configuration forwarding

Propagated instances inherit not just CLI flags but also runtime configuration state:

- **Environment variables** — all `SECTEST_*` env vars are forwarded to the propagated
  instance (via `export_for_propagation()`). This is intentional so that the child inherits
  the operator's full runtime configuration. Note that this forwards *every* `SECTEST_*`
  value, including any that hold secrets (e.g. `SECTEST_NVD_API_KEY`,
  `SECTEST_SLACK_WEBHOOK`); on propagation these are serialized into the payload delivered
  to the foothold. Operators should avoid setting secret-bearing `SECTEST_*` variables when
  propagating onto hosts they do not fully trust. The child applies imported configuration
  through `import_from_propagation()` without an allow-list filter — the parent is trusted
  to define the propagated configuration.
- **Discovery-driven updates** — if the parent discovers VPC endpoints, API gateways,
  or service-mesh sidecars, these are serialized via `export_for_propagation()` and
  injected into the child via `import_from_propagation()`
- **Extended cloud credentials** — discovered credentials (Scaleway, OCI, DigitalOcean,
  etc.) are forwarded so the propagated instance can enumerate from the foothold's position

The propagation payload sets `SECTEST_PROPAGATION_CONTEXT` containing the serialized
runtime overlay, which the child imports at startup.
