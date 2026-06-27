# CLI Reference

Complete list of all command-line flags.

## Positional argument

| Argument | Description |
|---|---|
| `target` | Auto-detected as repo path, git URL, CIDR range, host:port, or URL |

## Target selection

| Flag | Description |
|---|---|
| `--repo PATH_OR_URL` | Repository to scan (local path or git URL) |
| `--url URL` | Live endpoint to probe |
| `--host-port HOST:PORT` | Explicit host:port target |
| `--cidr RANGE` | Network range (CIDR, last-octet range, or full-IP range) |
| `--local` | Read-only host introspection |
| `--use-discovered-cloud-creds` | Activate credentialed cloud assessment |
| `--targets-file PATH` | Batch-scan multiple targets from file (one per line, max 256) |

## Authentication & credentials

| Flag | Description |
|---|---|
| `--jwt TOKEN` | Present a JWT for validation or endpoint probing |
| `--bearer TOKEN` | Alias for `--jwt` |
| `--api-key KEY` | Present an API key |
| `--username USER` | Username for credential testing |
| `--password PASS` | Password for credential testing |
| `--header NAME` | Header name carrying the token (default: `Authorization` / `X-API-Key`) |
| `--auth-scheme SCHEME` | Value prefix (default: `Bearer` for JWT, none for API key; `''` for raw) |
| `--cookie VALUE` | Include a Cookie header on all HTTP requests |
| `--request-header H:V` | Add an arbitrary header to all HTTP requests (repeatable) |

## Scanning control

| Flag | Description |
|---|---|
| `--intensity TIER` | Minimum intensity: `detective`, `active` (default), `intrusive`, `proof`, `fuzz` |
| `--scope HOST\|CIDR\|.DOMAIN` | Optional scope narrowing (repeatable; restricts scanning to listed entries) |
| `--scope-file PATH` | File with scope entries (one per line) |
| `--yes` | Non-interactive confirmation for intrusive+ intensity (skips the `[y/N]` prompt) |
| `--profile NAME` | Preset: `quick`, `standard`, `deep`, `stealth` |
| `--jobs N` | Max concurrent modules (default: adaptive based on CPU/memory) |
| `--only MODULE[,MODULE]` | Run only the listed modules |
| `--ports SPEC` | Port spec for host:port targets (single, range, or comma list) |
| `--max-hosts N` | Cap range expansion for CIDR targets |
| `--spray` | Enable default-credential spraying (required for `default-creds` module) |
| `--resume PATH` | Resume an interrupted sweep from state file |
| `--no-cve-enrich` | Disable the offline CVE correlation post-pass |

## CVE pipeline

| Flag | Description |
|---|---|
| `--cve-lookup` | Resolve discovered service banners to CVEs via NVD (hybrid online+offline) |
| `--cve-test` | Generate and execute PoC verification scripts (requires `--cve-lookup`) |
| `--cve-max N` | Cap on CVE exploit plans generated (default: 10) |
| `--cve-api-key KEY` | NVD API key for higher rate limits |

## Proof & propagation

| Flag | Description |
|---|---|
| `--prove-access` | Enable all proof types (writes + shell) |
| `--prove-access-writes` | Enable write-proof only (marker files, datastore keys) |
| `--prove-access-shell` | Enable shell-proof only (persistent container) |
| `--propagate-script` | Deploy scanner onto proven footholds and run from inside |
| `--propagate-depth N` | Max propagation hops (default: 2; decremented each hop) |
| `--propagate` | Enable relay-through-foothold scanning |
| `--host-subnet CIDR` | Explicit /24 subnet context for propagated scans |

## Network & proxy

| Flag | Description |
|---|---|
| `--proxy URL` | Route all HTTP/TCP traffic through HTTP-CONNECT or SOCKS5 proxy |
| `--pivot-proxy URL` | Proxy for pivot/relay traffic only (overrides `--proxy` for relays) |
| `--nse-scripts CATEGORIES` | Opt-in NSE script categories (only SAFE allowed) |
| `--no-imds` | Skip link-local metadata probe (env vars + on-disk profiles only) |

## Confirmation & safety

| Flag | Description |
|---|---|
| `--canary-url URL` | Operator-owned canary for SSRF confirmation |
| `--oob-listen` | Start an out-of-band confirmation listener |
| `--keep-credentials` | Opt out of the credential guard (not recommended) |
| `--yes` | Acknowledge pre-scan safety check non-interactively |

## Output

| Flag | Description |
|---|---|
| `--markdown PATH` | Write Markdown report |
| `--json PATH` | Write machine-readable JSON report |
| `--sarif PATH` | Write SARIF 2.1.0 report (for code-scanning dashboards) |
| `--html PATH` | Write standalone HTML report |
| `--no-color` | Disable ANSI colors in console output |
| `--baseline PATH` | Compare against a previous JSON report (new/fixed/unchanged) |
| `--fail-on SEVERITY` | Exit 1 only when a finding meets this severity threshold |
| `--fail-on-new-only` | Fail only on NEW findings (ignore pre-existing) |

## LLM briefing

| Flag | Description |
|---|---|
| `--llm` | Enable local-LLM attacker briefing (Ollama) |
| `--model NAME` | Ollama model name (default: auto-detected) |
| `--allow-remote-llm` | Allow non-loopback Ollama host |

## Utility

| Flag | Description |
|---|---|
| `--list-modules` | Print the live module catalogue and exit |
| `--install` | Best-effort install optional extras |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All assessed risks are mitigated (or below `--fail-on` threshold) |
| `1` | Exploitable issues found (per `--fail-on`) |
| `2` | Usage or runtime error (including declined pre-scan safety check) |
