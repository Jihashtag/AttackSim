# Local Introspection, Container Escape & On-Site Assessment

With `--local` the toolkit inspects **the host it is running on**. Pure introspection
modules are read-only — they read `/proc`, mount tables, capability bits and on-disk
runtime versions. On-site modules (WiFi, Bluetooth, router, Android/iOS) activate
active scanning on the local host or when deployed via propagation onto a foothold.

## Introspection & escape-detection modules

| Module | Target kind | What it detects | Outcome = EXPLOITED when… |
|---|---|---|---|
| `container-escape-detector` | local / host:port | Container-escape preconditions — dangerous capabilities (`CAP_SYS_ADMIN`/`SYS_MODULE`/`SYS_PTRACE`/`DAC_READ_SEARCH`), mounted Docker/containerd/CRI-O socket, writable host bind mounts, writable `/sys`, shared host PID namespace, vulnerable runc (Leaky Vessels CVE-2024-21626; CVE-2025-31133/52565/52881) — plus, remotely, an unauthenticated Docker/kubelet API | a CRITICAL/HIGH escape precondition or exposed runtime API |
| `rootkit-ioc-detector` | local | Linux rootkit/implant IOCs — non-empty `/etc/ld.so.preload`, PID-1 `LD_PRELOAD` (Azazel/Jynx/BEURK/vlany/bdvl/Symbiote), kernel taint, known LKM rootkit modules (Diamorphine/Reptile/Suterusu/KoviD/…), hidden modules, rootkit symbols in `/proc/kallsyms`, pinned eBPF implants (TripleCross/ebpfkit/Boopkit/pamspy), promiscuous interfaces | a CRITICAL/HIGH rootkit IOC is present |
| `linux-privesc` | local / host:port | detective | Detect Linux privilege-escalation preconditions: kernel CVEs, SUID binaries, sudo misconfig, Docker group, writable cron (local + SSH fingerprint) | a HIGH/CRITICAL escalation vector is found |
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

## On-site / physical assessment modules

These modules run on a **local machine at the assessment site** (or on a proven foothold
reached via propagation). They enumerate the physical environment — wireless networks,
nearby Bluetooth devices, routers, and mobile devices — and feed discovered hosts back
into the orchestrator as pivot targets.

| Module | Tier | What it does |
|---|---|---|
| `wifi-probe` | active | Enumerate nearby SSIDs via `nmcli`/`iwlist`/`iw`. Reports encryption posture (open/WEP/WPS/WPA2/WPA3). On a vulnerable finding, adds the default gateway IP and local subnet CIDR to `pivot_targets` so downstream modules sweep the LAN. |
| `bluetooth-probe` | active | Discover nearby Bluetooth devices via `bluetoothctl`/`hcitool`. Browse SDP records for RFCOMM/SPP services. Enumerate GATT services via `gatttool`. High-risk UUIDs (Nordic UART `6e400001`, vendor serial `00001234`/`49535343`) generate HIGH findings and `ble-uart`/`bt-rfcomm` pivot relays. |
| `router-probe` | active | Fingerprint default gateway and discovered routers: admin panel on HTTP/HTTPS, Telnet (23), TR-069 (7547), UPnP IGD (`/rootDesc.xml`), default-firmware CVE hints. |
| `android-probe` | active | Discover Android devices on the LAN via ADB port 5555 and mDNS `_adb._tcp`. Developer debug mode exposed over ADB = CRITICAL. |
| `ios-probe` | active | Discover iOS devices on the LAN via iTunes sync port 62078 and Bonjour/mDNS. Jailbreak SSH indicators (Cydia repo, OpenSSH banner) = HIGH. |
| `device-posture` | detective | Post-propagation device assessment: privilege level (`id`/`whoami`), sandbox/container detection, local services on `127.0.0.1` (`ss -tlnp` → `netstat` → `/proc/net/tcp` fallback chain), WiFi/BT adapter presence, ARP peer discovery via `/proc/net/arp` → pivot targets. |
| `privesc-exploit` | intrusive | Attempt local privilege escalation — SUID GTFOBins, sudo NOPASSWD, default-password spray (≤5 attempts, `_SPRAY_MAX`), kernel CVE detection (DirtyPipe/DirtyCow/OverlayFS/PwnKit/Baron Samedit). On success: runs `id` only (verification), writes one labelled marker file to `/tmp/SECTEST_PRIVESC_PROOF_<pid>_<ts>.txt`, adds `shell-exec` relay to `pivot_targets`. No persistent shell, no data exfil. |
| `router-auth` | intrusive | Firmware-specific default credential testing on router/firewall admin panels (OpenWRT, DD-WRT, MikroTik, pfSense, ASUS, TP-Link, D-Link, Netgear, Zyxel, …). HTTP Basic Auth + form POST. ≤6 attempts per host, 1 s delay between attempts. |

### Pivot propagation from on-site footholds

When `wifi-probe` finds a vulnerable network, it appends:
- `{"host": <gateway_ip>, "port": 80, "via": "wifi-probe:gateway"}` — router scan
- `{"kind": "netrange", "cidr": <local_cidr>, "via": "wifi-probe:local-subnet"}` — LAN sweep

When `bluetooth-probe` finds a shell-capable BLE device, it appends:
- `{"relay": {"type": "ble-uart", "addr": <bt_addr>}}` — BLE UART relay

When `privesc-exploit` gains root, it appends:
- `{"relay": {"type": "shell-exec"}}` — root shell relay for further pivot

All pivot entries are processed by `_fanout_pivots()` in the orchestrator, which
scope-checks every candidate host before dispatching modules.

## LLM briefing

The optional `--llm` briefing runs against a **local** Ollama daemon only. Findings
are sent local-only by default: a non-loopback `OLLAMA_HOST` is refused unless you
pass `--allow-remote-llm`. Untrusted finding text is sanitised against prompt injection
(raw `evidence` is never forwarded), and the daemon is checked for CVE-2024-37032
("Probllama", Ollama < 0.1.34) before use.
