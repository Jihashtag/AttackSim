# AttackSim — Development Guide

This guide covers setting up a local AttackSim development environment, running the test
suite, adding new exploit modules, and the project's coding conventions.

## Setup

```bash
cd attacksim
pip install -e ".[dev]"     # pytest + ruff + mypy (optional)
```

## Running tests

```bash
pytest                       # unit + local-server integration tests (682+ tests)
ruff check .                 # lint
mypy .                       # type-check (optional)
```

The suite (`tests/`) covers:

- Port-spec parsing and target-resolution precedence
- Auth-header construction
- Exit-code gate logic
- Module registry dispatch
- Live network modules against throwaway local HTTP and raw-TCP fixture servers
- Cloud-native infrastructure modules (Kubernetes, ingress-nginx, Kafka, datastores,
  SSRF→IMDS, ArgoCD)
- CVE pipeline (resolution, planning, generation)
- Attack-chain correlation
- Proof-of-access and lateral movement
- Cloud assessment modules (all three providers)

No external network is required — all tests use local fixture servers.

## Adding a module

1. Create `exploits/your_module.py` with the module contract:

```python
from exploits.base import Finding, ExploitResult

NAME = "your-module"
DESCRIPTION = "One-line description of what the module does"
SUPPORTS = {"url"}          # target kinds: repo, url, creds, hostport, netrange, local, cloud
INTENSITY = "active"        # detective, active, intrusive, proof, fuzz

def run(target) -> ExploitResult:
    findings = []
    # ... attack logic ...
    return ExploitResult(
        name=NAME,
        description=DESCRIPTION,
        exploited=bool(findings),
        findings=findings,
        attacker_value="what the attacker can do with this" if findings else "",
        mitigation="how to fix it",
    )
```

1. Register it in `exploits/registry.py` (import + add to `ALL_MODULES`).

2. Add tests in `tests/test_*.py`.

## Module guidelines

- Use only the Python standard library (no pip dependencies in module code)
- Use `exploits/netutil.py` for HTTP/TCP/Redis helpers
- Use `exploits/toolrunner.py` for subprocess execution (never `shell=True`)
- Respect the intensity tier contract — don't exceed your declared tier's permissions
- At `intrusive`+, use `sandbox/scope_guard.py` to authorize every request
- The `Finding.detail` field is **required** (positional argument)

## Safety rules for modules

- **detective**: read-only fingerprinting only (no auth attempts, no writes)
- **active**: one-shot bounded interaction (one auth attempt, one redirect follow)
- **intrusive**: multi-request, but must be lockout-/rate-aware and scope-checked
- **proof**: only harmless, labelled, persistent artifacts
- **fuzz**: bounded corpus, rate-limited, never chains into exploitation

## Project conventions

- Module files: `exploits/<name>.py` (NAME uses kebab-case, file uses snake_case)
- One module per file
- Tests use local fixture servers (no mocking of network — real TCP/HTTP)
- No `shell=True` subprocess calls
- All credential access goes through `sandbox/credential_guard.py`
