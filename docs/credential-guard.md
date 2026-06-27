# Credential Guard

The toolkit runs on an **unauthenticated shell**: it must never use AWS / EKS /
ArgoCD / JFrog / GitHub / Docker credentials. This is not just a claim — a runtime
**credential guard** ([`sandbox/credential_guard.py`](../sandbox/credential_guard.py))
scrubs every credential source from the process **before any module runs**.

## What it neutralises

| What | Action |
|---|---|
| credential env vars (`AWS_*`, `ARGOCD_*`, `JF_*`, `GITHUB_TOKEN`, `KUBECONFIG`, …) | removed from the environment |
| credential files (`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, …) | lookups redirected to an empty path |
| EC2 instance metadata (IMDS) role pickup | disabled (`AWS_EC2_METADATA_DISABLED=true`) |

## Behavior

Network access itself is **not** blocked — only credentials are. On startup the
guard runs a self-test (no credential env var may remain) and refuses to run if it
fails. It transparently reports what it neutralised:

```
[*] credential guard: credential-free (no AWS/EKS/ArgoCD/JFrog/GitHub creds in use)
[*] neutralised 3 credential env var(s) and 1 on-disk credential file(s); none were used.
```

## Opt out

Use `--keep-credentials` to disable the guard (not recommended). The core modules
never read credentials anyway — the guard makes that property **enforceable and
auditable**.

## Interaction with cloud assessment

The credentialed cloud path (`--use-discovered-cloud-creds`) is the one deliberate,
opt-in exception. Cloud credential **discovery** runs *before* the guard scrubs the
environment; the in-memory inventory is then handed **only** to the cloud modules —
every other module still runs credential-free, and the credentials are never written
to the report. See [cloud-assessment.md](cloud-assessment.md) for details.
