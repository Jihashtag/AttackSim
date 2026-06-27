# Local Introspection & Container Escape

With `--local` the toolkit inspects **the host it is running on**. Detection is read-only
— it reads `/proc`, mount tables, capability bits and on-disk runtime versions.

## Modules

| Module | Target kind | What it detects | Outcome = EXPLOITED when… |
|---|---|---|---|
| `container-escape-detector` | local / host:port | Container-escape preconditions — dangerous capabilities (`CAP_SYS_ADMIN`/`SYS_MODULE`/`SYS_PTRACE`/`DAC_READ_SEARCH`), mounted Docker/containerd/CRI-O socket, writable host bind mounts, writable `/sys`, shared host PID namespace, vulnerable runc (Leaky Vessels CVE-2024-21626; CVE-2025-31133/52565/52881) — plus, remotely, an unauthenticated Docker/kubelet API | a CRITICAL/HIGH escape precondition or exposed runtime API |
| `rootkit-ioc-detector` | local | Linux rootkit/implant IOCs — non-empty `/etc/ld.so.preload`, PID-1 `LD_PRELOAD` (Azazel/Jynx/BEURK/vlany/bdvl/Symbiote), kernel taint, known LKM rootkit modules (Diamorphine/Reptile/Suterusu/KoviD/…), hidden modules, rootkit symbols in `/proc/kallsyms`, pinned eBPF implants (TripleCross/ebpfkit/Boopkit/pamspy), promiscuous interfaces | a CRITICAL/HIGH rootkit IOC is present |
| `sbom-scan` | local / repo | Software-composition vulnerability scan (trivy/grype) | a HIGH/CRITICAL dependency vulnerability is found |

## Behavior

The detector first confirms it is inside a container; on a bare host it reports an
INFO skip. Detection identifies what would let an attacker with in-container code
execution break out to the node.

## Proof-of-access (opt-in)

With `--prove-access`, `container-escape-detector` does *not* perform a destructive
escape. Instead it drops one harmless, clearly-labelled, persistent marker file:

- **In a detected container:** a marker on the container's `/tmp` (proving in-container
  code execution) and, if the host filesystem is bind-mounted read-write, a marker on the
  **host** (proving the escape).
- **Against an exposed Docker API (`host:port`):** a marker on the Docker host via a
  bind-mounted throwaway container.

Marker files only ever *create* new, inert files (`O_CREAT|O_EXCL`) — nothing is
overwritten, modified, or deleted.

## Rootkit detection (defensive)

`rootkit-ioc-detector` is the *defensive* realisation of rootkit capability: rather
than installing an implant (categorically forbidden), it proves — read-only — whether
the host has *already* been implanted. It covers:

- Userland `LD_PRELOAD` hooking
- LKM (loadable kernel module) rootkits
- Modern eBPF rootkit families

## Examples

```bash
# Read-only container-escape posture:
python3 main.py --local
python3 main.py --local --only container-escape-detector
python3 main.py --local --only rootkit-ioc-detector

# Prove access on a detected container or exposed Docker API:
python3 main.py --local --prove-access --only container-escape-detector
python3 main.py 10.0.0.5:2375 --prove-access --only container-escape-detector
```

## LLM briefing

The optional `--llm` briefing runs against a **local** Ollama daemon only. Findings
are sent local-only by default: a non-loopback `OLLAMA_HOST` is refused unless you
pass `--allow-remote-llm`. Untrusted finding text is sanitised against prompt injection
(raw `evidence` is never forwarded), and the daemon is checked for CVE-2024-37032
("Probllama", Ollama < 0.1.34) before use.
