# AttackSim — Safety & Design Principles

AttackSim is designed for authorised penetration testing and red-team attacker simulation.
Every safety property is enforced at runtime by independent layers — not by convention alone.

## Credential-free by default

AttackSim runs on an unauthenticated shell: it never uses AWS / EKS / ArgoCD /
JFrog / GitHub / Docker credentials. The runtime credential guard enforces this
property. See [credential-guard.md](credential-guard.md).

**Exception — `--keep-credentials` (by design).** For legitimate red-team use on an
already-compromised foothold, `--keep-credentials` intentionally disables the credential
guard so the scanner can use the ambient credentials of the host it runs on
(`~/.aws/credentials`, `KUBECONFIG`, `ARGOCD_AUTH_TOKEN`, …). This is an opt-in inversion
of the credential-free model and is announced on `stderr` (`[*] credential guard
DISABLED`). It is meant for operators who *want* the scanner to inherit a foothold's
identity; on a clean workstation it should never be used. The guard state is not currently
embedded in the report artifact — operators are responsible for recording that a run was
credentialed.

## Read-only below the intrusive tier

Read-only is a property of the **intensity tier**, not of the toolkit as a whole:

- At **`detective`** and **`active`** intensity, all modules are read-only: they
  fingerprint, enumerate, and observe. No writes, no authenticated mutation, no
  command execution on targets.
- At **`intrusive`**, **`proof`**, and **`fuzz`** intensity (opt-in via `--intensity`
  plus mandatory confirmation), modules perform **active exploitation**: authenticated
  writes with immediate rollback (e.g. Redis `SET`+`DEL`, K8s ConfigMap create+delete),
  sensitive-file reads (`/etc/hostname`, `/proc/self/environ`), verification commands
  (`id`), forged-token replay, and proof-of-access artifact creation.

The intensity tier is the switch between "observe only" and "exploit". A module's
per-tier behavior is listed in [modules.md](modules.md) (look for "at intrusive+ …").
`access-prover` and (under `--prove-access`) `container-escape-detector` are additionally
off by default even at intrusive+.

## What is forbidden (always)

- Configuration changes on target systems (beyond immediately-reverted proof writes)
- Data destruction or modification
- Encryption / ransomware
- Denial of service
- Unauthorized privilege escalation (persistent backdoors, shell left open, data exfiltration); the `privesc-exploit` module at `--intensity intrusive` only runs `id` for verification on explicitly authorized local targets and writes a single labelled marker file — no persistent access
- Destructive filesystem operations: the proof-of-access marker command (`exploits/proof_marker.py`) runs `echo` + `id` + a `/tmp/SECTEST_PROOF_*.txt` write — never `chmod`, `rm`, or any destructive operation
- Rootkits / implants / backdoors
- Credential minting (no `CreateAccessKey`, `CreateLoginProfile`, etc.)

## Artifact persistence

Proof-of-access artifacts are **persistent by design** so the blue team can independently
discover and verify them. They are inert and labelled `AUTHORIZED-ASSESSMENT … safe to
delete`. There is intentionally **no automatic cleanup** — a proof that deletes itself
cannot be independently verified. As a consequence, a proof run against the *wrong* target
(operator typo, staging-vs-prod mistake) leaves its markers in place (a Redis key, an ES
`sectest-canary` index, a Memcached key, a `/tmp/sectest_proof_*.txt` file, a K8s
ConfigMap, or a proof container). Operators are responsible for confirming the target
before enabling `--prove-access`. Cloud proofs (AWS/GCP/Azure) include an inverse delete
command in the report; other backends do not. See [proof-of-access.md](proof-of-access.md).

## Reports contain full evidence (treat as sensitive)

Findings record raw `evidence`, `detail`, and `location` verbatim so that a report is a
faithful, independently-verifiable record of what was observed. There is intentionally
**no report-wide secret-redaction layer**: if a module observes a credential, token, or
key while exploiting a finding, that value may appear in the report evidence. Module-level
courtesies exist where practical (forged JWT signatures are truncated, cloud credentials
discovered in-memory are not echoed back), but reports must be treated as **sensitive
artifacts** — store, transmit, and archive them accordingly. The toolkit does not transmit,
commit, or modify anything in the target repo, and excludes its own directory from scanning
to avoid self-flagging.

## Scope enforcement (target-derived)

At `intrusive` intensity and above, mandatory confirmation is required: either `--yes`
(non-interactive) or an interactive `[y/N]` prompt. The scope is **target-derived** —
derived from the target itself (host, CIDR, URL domain). Optional `--scope` entries provide
narrowing if needed.

By design, when no explicit `--scope` allow-list is supplied, `authorize()` returns true at
intrusive+ on the strength of the operator's global `--yes`/prompt confirmation: the
"scope" is the conceptual target the operator confirmed, and there is no per-request
allow-list check. This applies equally to a **propagated** instance running on a foothold —
it inherits the parent's governance model (same confirmation semantics), and a foothold that
sweeps its own `/24` does so under the operator's original authorization. The scope check
may resolve a hostname via DNS when matching against CIDR entries. Operators who need a hard
per-host boundary must pass an explicit `--scope` allow-list. See
[intensity-and-scope.md](intensity-and-scope.md).

## LLM-assisted PoC completion (operator-driven)

When Ollama-assisted triage completes or generates a proof-of-concept script, that script
runs under **operator control**: it is presented for review/edit and executed with
`python -S` in a restricted environment. AttackSim intentionally does **not** impose an AST
allow-list or a `resource.setrlimit`/namespace sandbox on operator-run PoC scripts — the
operator is the trust boundary and is expected to read the script before running it. Do not
feed untrusted findings into LLM completion on a host you are unwilling to run code on.

## Controlled transmission (proof tier only)

The `git-push-proof` and `git-cli-proof` modules (opt-in, proof tier only) may push
labelled marker branches to accessible repositories as supply-chain access evidence.
These are clearly labelled `AUTHORIZED-ASSESSMENT`, use throwaway branches, and never
touch main/master. All other modules never commit, push, or send externally.

## SMTP testing (envelope vs. delivery)

At **`active`** intensity the SMTP modules stop at `RCPT TO` and issue `RSET`/`QUIT` before
`DATA` — no message body is transmitted. The anti-spam rate-limit probe issues up to
`SMTP_BOMB_TEST_COUNT` (default 10) rapid envelopes at active tier to detect throttling;
this is intentional and bounded, but on a production MTA it may trip SIEM alerts or
temporary greylisting.

At **`intrusive`** intensity and above, `smtp-antispam` will additionally complete a `DATA`
transaction to **confirm** an open-relay/spoofing finding — it sends a single, clearly
labelled probe message (`Subject: sectest-antispam-probe`, body `Authorized security
assessment.`) and only raises the CRITICAL finding if the server accepts it for delivery.
On a real MTA this message is delivered/queued. This delivery is **by design** at
intrusive+ (the tier where exploitation is authorized); it does not occur at active tier.

## Pre-scan safety check

Before scanning any live target, the toolkit requires operator acknowledgement that the
target is not production and is within authorized scope. Non-interactive shells are refused unless `--yes` is passed.

## Request budget

A global request budget ([`sandbox/budget.py`](../sandbox/budget.py)) caps total outbound
volume so parallelism never exceeds a configurable ceiling. The budget is a **global**
ceiling; subnet-discovery sweeps perform TCP-connect liveness probes that are intentionally
not metered against it (they are bounded by the sweep's own host cap).

## Subprocess safety

All external process execution goes through `exploits/toolrunner.py` which enforces `shell=False` and audits every invocation.

## Relay command-injection prevention

Any host/port placed into relay scripts (Docker `nc`, etc.) is strictly validated (`sandbox/relay._safe_targets`) and non-literal values are dropped. Hostnames and URLs passed to relay `resolve()`/`http_probe()` are likewise validated against strict allow-lists (`_safe_host`/`_safe_url`) before being interpolated into any `/bin/sh -c` script — values containing shell metacharacters are rejected outright.
