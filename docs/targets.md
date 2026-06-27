# Targets

A **target is optional**. If you pass nothing, the toolkit scans the workspace
repository that contains it. Otherwise it accepts any one of the kinds below.

## Target kinds

| Target kind | How to supply it | What runs |
|---|---|---|
| **repo (local)** | a directory path (positional or `--repo`) | `secret-harvester`, `jwt-forger`, `bcrypt-cracker`, `ppe-detector`, `gitops-analyzer`, `network-exposure`, `supply-chain`, `dependency-integrity`, `sbom-scan` |
| **repo (remote)** | a git URL (positional or `--repo`; shallow-cloned to a temp dir) | *(same as repo-local)* |
| **url** | `--url URL` (`+ --jwt` / `--api-key`, `+ --header` / `--auth-scheme`) | `http-probe`, `path-probe`, `jwt-attacker`, `tls-grader`, `web-misconfig`, `web-spider`, `llm-probe`, `saml-misconfig`, `dns-recon`, `subdomain-takeover`, `graphql-probe`, `api-spec-discovery`, `public-storage-enum`, `oidc-oauth-misconfig`, `cache-poisoning`, `http2-rapid-reset`, `metadata-ssrf`, `argocd-probe`, `kyverno-probe`, `ingress-nightmare`, `k8s-service-enum`, `service-mesh-probe`, `nuclei-probe` (+ at `intrusive`: `default-creds`, `content-discovery`, `active-confirm`, `api-idor`, `deserialization-probe`, `ssti-confirm`, `sqli-confirm`, `xxe-confirm`, `path-traversal-confirm`, `request-smuggling`; + at `fuzz`: `fuzz-probe`) |
| **creds** | `--username/--password` and/or `--jwt`/`--api-key` (`+ --url` to validate) | `cred-tester` |
| **host:port** | `host:port`, `host:1-1024`, `host:22,80,443` positional, or `--host-port` (`+ --ports`) | `port-probe`, `tls-grader`, `ssh-probe`, `smtp-probe`, `dns-recon`, `subdomain-takeover`, `etcd-probe`, `grpc-reflection`, `http2-rapid-reset`, `k8s-probe`, `ingress-nightmare`, `unauth-service-probe`, `kafka-probe`, `kyverno-probe`, `k8s-service-enum`, `service-mesh-probe`, `container-escape-detector`, `nmap-probe`/`nuclei-probe` (optional) (+ at `intrusive`: `default-creds`, `k8s-enum`, `proto-auth`, `broker-auth`, `db-auth`; + at `proof`: `access-prover`) |
| **netrange** | `--cidr` (CIDR `10.0.0.0/24`, last-octet range `10.0.0.10-40`, full-IP range `10.0.0.250-10.0.1.10`; optional inline `:ports`), or positional; `+ --ports`, `--max-hosts` | `host-sweep`, `nmap-probe`, `nuclei-probe`, then a fan-out of the host:port modules across every **live** host |
| **local** | `--local` (read-only host introspection) | `sbom-scan`, `container-escape-detector`, `rootkit-ioc-detector` |
| **cloud** | `--use-discovered-cloud-creds` (activates only if ambient cloud creds are discovered) | `public-storage-enum`, `cloud-recon`, `cloud-iam-analyzer`, `cloud-enum`, `cloud-service-exposure`, `cloud-posture`, `cloud-pivot`, `access-prover` (opt-in) |

## Resolution precedence

First match wins:

1. `--use-discovered-cloud-creds` (when creds are discovered)
2. `--local`
3. `--cidr` (network range)
4. `--repo`
5. `--username/--password` (creds)
6. `--url`
7. `--jwt`/`--api-key` (token)
8. `--host-port`
9. positional auto-detect (repo / CIDR-range / host:port / URL)
10. default workspace repo

The toolkit runs only the modules that support the resolved target kind. Remote clones
use **no credentials** (only public/authorised remotes succeed) and the temp dir is
removed afterwards.

## Port specs

Port specs accept:

- A single port: `443`
- A range: `1-1024`
- A comma list: `22,80,443`
- Capped at 2048 ports per run; multiple ports are scanned concurrently.

## Custom auth

- `--header NAME` sets the header carrying the token (default `Authorization` for
  `--jwt`, `X-API-Key` for `--api-key`).
- `--auth-scheme` sets the value prefix (default `Bearer` for JWTs, none for API keys;
  pass `''` for a raw value).

## Batch targets

Use `--targets-file PATH` to scan multiple targets from a file (one per line,
max 256 entries).
