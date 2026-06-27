# Safety & Design Principles

## Credential-free by design

The toolkit runs on an unauthenticated shell: it never uses AWS / EKS / ArgoCD /
JFrog / GitHub / Docker credentials. The runtime credential guard enforces this
property. See [credential-guard.md](credential-guard.md).

## Read-only by default

All active modules are **read-only** except `access-prover` and (under `--prove-access`)
`container-escape-detector`, which are **off by default**. When explicitly enabled they
only ever **create** harmless, clearly-labelled artifacts.

## What is forbidden (always)

- Configuration changes on target systems
- Data destruction or modification
- Encryption / ransomware
- Denial of service
- Privilege escalation
- Rootkits / implants / backdoors
- Credential minting (no `CreateAccessKey`, `CreateLoginProfile`, etc.)

## Artifact persistence

Proof-of-access artifacts are **persistent by design** so the blue team can independently
discover and verify them. They are inert and labelled `AUTHORIZED-ASSESSMENT … safe to
delete`.

## Secret masking

- Secret values are **masked** in output
- Forged JWT signatures are truncated
- Cloud credentials discovered in-memory are never written to reports
- The toolkit does not transmit, commit, or modify anything in the target repo
- It excludes its own directory from scanning to avoid self-flagging

## Scope enforcement

At `intrusive` intensity and above, mandatory confirmation is required: either `--yes`
(non-interactive) or an interactive `[y/N]` prompt. The scope is derived from the target
itself (host, CIDR, URL domain). Optional `--scope` entries provide narrowing if needed.
Every request at the intrusive tier is individually authorized. See
[intensity-and-scope.md](intensity-and-scope.md).

## Controlled transmission (proof tier only)

The `git-push-proof` and `git-cli-proof` modules (opt-in, proof tier only) may push
labelled marker branches to accessible repositories as supply-chain access evidence.
These are clearly labelled `AUTHORIZED-ASSESSMENT`, use throwaway branches, and never
touch main/master. All other modules never commit, push, or send externally.

## Pre-scan safety check

Before scanning any live target, the toolkit requires operator acknowledgement that the
target is not production and is within authorized scope. Non-interactive shells are
refused unless `--yes` is passed.

## Request budget

A global request budget ([`sandbox/budget.py`](../sandbox/budget.py)) caps total outbound
volume so parallelism never exceeds a configurable ceiling.

## Subprocess safety

All external process execution goes through `exploits/toolrunner.py` which enforces
`shell=False` and audits every invocation.

## Relay command-injection prevention

Any host/port placed into relay scripts (Docker `nc`, etc.) is strictly validated
(`sandbox/relay._safe_targets`) and non-literal values are dropped.
