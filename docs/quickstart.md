# AttackSim — Quick Start

AttackSim is a Python-based attacker simulation framework that requires no external
dependencies for its core functionality. All exploit modules, CVE verification scripts,
and the interactive triage tool run on the Python standard library alone.

## Prerequisites

- Python 3.10+ (tested on 3.12)
- No external packages required — the core depends only on the Python standard library

## Run

```bash
cd attacksim
./run_all.sh                 # attack the parent workspace, pretty console output
```

Or invoke Python directly:

```bash
python3 main.py --no-color
```

## Pre-scan safety check

Before AttackSim scans any *live* target (URL, host:port, network range, or cloud),
the toolkit shows you the resolved target, intensity and scope and asks you to confirm
it is **not a production environment** and is **within your authorised scope**. An
interactive terminal prompts `[y/N]`; a non-interactive shell (e.g. CI) is **refused**
unless you pass `--yes` to acknowledge explicitly. Static repo / `--local` introspection
reads local files only and is never gated.

## Common examples

```bash
# Repository targets (repo is OPTIONAL; default = the parent workspace)
./run_all.sh /home/user/dev/applications            # a local sub-tree
./run_all.sh --repo https://github.com/org/repo.git # clone a git URL, then scan
./run_all.sh https://github.com/org/repo.git        # auto-detected as a repo

# Non-repository targets
./run_all.sh --url https://api.example.com          # live endpoint probe
./run_all.sh --url https://api.example.com --jwt eyJ...   # + present a JWT
./run_all.sh --url https://api.example.com --api-key KEY  # + present an API key
./run_all.sh --username admin --password s3cret --url https://app.example.com
./run_all.sh --jwt eyJ...                            # validate a token (no URL = classify only)
./run_all.sh example.com:8443                        # host:port service probe
./run_all.sh --host-port 10.0.0.5:6443               # explicit host:port
./run_all.sh 10.0.0.5:1-1024                          # port RANGE scan (positional)
./run_all.sh --host-port 10.0.0.5 --ports 22,80,443,6443  # port LIST scan

# Network-range sweep (discover live hosts, then probe each)
./run_all.sh --cidr 10.0.0.0/24                       # CIDR sweep
./run_all.sh --cidr 10.0.0.10-40 --ports 22,6443     # last-octet range + explicit ports
./run_all.sh 10.0.0.0/27:6379                          # positional CIDR with inline ports
./run_all.sh --cidr 10.0.0.0/24 --max-hosts 64        # cap range expansion

# Optional external-tool integrations (auto-detected; skipped if absent)
./run_all.sh --host-port 10.0.0.5 --ports 22,80,6379 # nmap -sV + nuclei if installed
./run_all.sh --host-port 10.0.0.5 --nse-scripts safe,version
./run_all.sh --cidr 10.0.0.0/24 --no-cve-enrich      # disable offline CVE correlation

# Custom auth header / scheme
./run_all.sh --url https://api.example.com --jwt eyJ... --header X-Auth-Token
./run_all.sh --url https://api.example.com --api-key KEY --header X-Api-Key --auth-scheme ''
./run_all.sh --url https://api.example.com --jwt eyJ... --auth-scheme Token

# Performance, profiles & resume
./run_all.sh --profile quick                         # detective intensity, more parallelism
./run_all.sh --profile deep --scope target.example   # intrusive + scoped
./run_all.sh --profile stealth --scope target.example # low parallelism + low rate
./run_all.sh --jobs 16                                # up to 16 modules concurrently
./run_all.sh --cidr 10.0.0.0/24 --resume report/run.state  # resume an interrupted sweep

# Output
./run_all.sh --markdown report/report.md
./run_all.sh --json report/out.json
./run_all.sh --sarif report/out.sarif
./run_all.sh --html report/out.html
./run_all.sh --llm --model gemma2                    # local-LLM attacker briefing
./run_all.sh --only jwt-forger,secret-harvester      # run selected modules
```

## Parallelism

Modules are independent and run **concurrently** by default (bounded pool; `--jobs`,
default from the profile or adaptive detection). The shared global request budget still
paces total outbound volume, so parallelism never raises the request ceiling.

Profiles: `quick` / `standard` / `deep` / `stealth`; explicit `--intensity` and
`--jobs` always override a profile. `--resume <file>` records each completed
`(target, module)` pair so an interrupted large sweep can continue where it left off.

## Optional enhancements

The core depends only on the Python standard library. Two optional extras are
auto-detected at runtime:

| Optional | Enables | If missing |
|---|---|---|
| `bcrypt` (or `passlib`) | offline password-hash cracking | hash *exposure* still reported; crack step skipped |
| local **Ollama** model | AI-powered attacker briefing and CVE PoC generation (`--llm`) | deterministic report still produced |

If the interpreter has no `pip`:

```bash
python3 -m ensurepip --upgrade
# or: uv pip install -r requirements.txt
# PEP 668 envs: pip install --user --break-system-packages -r requirements.txt
```
