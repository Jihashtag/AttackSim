#!/usr/bin/env python3
"""security_test — unauthenticated attacker simulation entrypoint.

Runs a set of exploit modules against infrastructure-as-code repositories from
the perspective of an attacker who has ONLY repository read access (no AWS / EKS
/ ArgoCD / JFrog credentials). It attempts real exploitation where possible
(JWT forgery, bcrypt cracking) and static reachability analysis otherwise.

Exit codes:
    0  -> no module succeeded; assessed risks are mitigated.
    1  -> at least one exploit succeeded; see the summary.
    2  -> usage / runtime error.
"""
from __future__ import annotations

import argparse
import os
import sys

# Make the toolkit importable when invoked as `python main.py` from anywhere.
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOL_DIR)

from exploits import registry  # noqa: E402
from report import reporter  # noqa: E402
import targets as targetmod  # noqa: E402

MODULES = registry.ALL_MODULES


def default_target() -> str:
    # Intentionally returns empty string — callers that need a local fallback must
    # request it explicitly. Scanning the local toolkit directory by default is unsafe.
    return ""


def _print_modules() -> None:
    rows = registry.catalogue()
    name_w = max((len(r["name"]) for r in rows), default=4)
    kind_w = max((len(r["supports"]) for r in rows), default=8)
    int_w = max((len(r.get("intensity", "")) for r in rows), default=9)
    print(f"{'MODULE':<{name_w}}  {'SUPPORTS':<{kind_w}}  {'INTENSITY':<{int_w}}  DESCRIPTION")
    for r in rows:
        print(f"{r['name']:<{name_w}}  {r['supports']:<{kind_w}}  "
              f"{r.get('intensity', ''):<{int_w}}  {r['description']}")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="security_test",
        description="Attacker simulation against a repository, live URL, credentials, or host:port.",
        epilog=(
            "TARGET resolution (first match wins): --repo > --username/--password (creds) > "
            "--url > --jwt/--api-key (token) > --host-port > positional auto-detect > "
            "default workspace repo. A repository is OPTIONAL and may be a local path or a "
            "clonable git URL. Use --list-modules to see every module and the target kinds it "
            "supports. Exit codes: 0=mitigated/below --fail-on, 1=exploited, 2=error."
        ),
    )
    p.add_argument("target", nargs="?", default=None,
                   help="Optional target: a local dir, git URL, http(s) URL, or host:port (auto-detected).")
    p.add_argument("--repo", default=None,
                   help="Repository to attack: local path or clonable git URL (cloned to a temp dir).")
    p.add_argument("--url", default=None, help="Live HTTP(S) endpoint to probe.")
    p.add_argument("--jwt", default=None, help="JWT to present (with --url) or validate (creds).")
    p.add_argument("--api-key", dest="api_key", default=None, help="API key to present/validate.")
    p.add_argument("--username", default=None, help="Username for credential validation.")
    p.add_argument("--password", default=None, help="Password for credential validation.")
    p.add_argument("--host-port", dest="host_port", default=None, help="Network service as host:port (or host with --ports).")
    p.add_argument("--ports", default=None,
                   help="Port spec to scan: N, N-M, or comma list (e.g. '1-1024', '22,80,443').")
    p.add_argument("--cidr", default=None,
                   help="Network range to sweep: CIDR (10.0.0.0/24), last-octet range "
                        "(10.0.0.5-20), or full-IP range (10.0.0.250-10.0.1.10); optional "
                        "':ports' suffix. Live hosts are discovered then probed.")
    p.add_argument("--max-hosts", dest="max_hosts", type=int, default=None,
                   help="Cap the number of hosts a --cidr range may expand to (default from config).")
    p.add_argument("--nse-scripts", dest="nse_scripts", default=None,
                   help="Opt-in nmap NSE scripts/categories (comma list). Only SAFE categories "
                        "(safe,default,discovery,version) are permitted; intrusive/exploit/dos/"
                        "brute/vuln selectors are rejected before nmap runs.")
    p.add_argument("--no-cve-enrich", dest="no_cve_enrich", action="store_true",
                   help="Disable the offline CVE enrichment post-pass (correlates discovered "
                        "service versions with a bundled offline CVE feed; no network).")
    p.add_argument("--cve-lookup", dest="cve_lookup", action="store_true",
                   help="Enable live CVE resolution: query NVD 2.0 + OSV.dev + EPSS for "
                        "HIGH/CRITICAL CVEs affecting discovered service versions (last 5 years). "
                        "Results are cached locally for 24h. No API key required.")
    p.add_argument("--cve-test", dest="cve_test", action="store_true",
                   help="After CVE lookup, generate and run verification scripts. Nuclei templates "
                        "auto-execute; Python PoC scripts require --yes or interactive confirmation.")
    p.add_argument("--cve-max", dest="cve_max", type=int, default=10,
                   help="Maximum CVEs to test per target (default: 10).")
    p.add_argument("--cve-api-key", dest="cve_api_key", default=None,
                   help="NVD API key for higher rate limits (optional; 50 req/30s vs 5 req/30s).")
    p.add_argument("--intensity", default=None,
                   choices=["detective", "active", "intrusive", "proof", "fuzz"],
                   help="How aggressive the run may be (default 'active'). 'intrusive' and above "
                        "REQUIRE a --scope allow-list. 'proof' is implied by --prove-access; "
                        "'fuzz' enables the bounded, rate-limited fuzzing tier.")
    p.add_argument("--scope", action="append", default=None,
                   help="Authorised target host, CIDR, or .domain suffix (repeatable). Mandatory "
                        "for intrusive/proof/fuzz runs; active modules refuse out-of-scope hosts.")
    p.add_argument("--scope-file", dest="scope_file", default=None,
                   help="File with one --scope token per line (# comments allowed).")
    p.add_argument("--spray", action="store_true",
                   help="Enable lockout-aware default-credential spraying against discovered "
                        "services (requires --intensity intrusive + --scope).")
    p.add_argument("--canary-url", dest="canary_url", default=None,
                   help="Operator-controlled callback URL for active SSRF confirmation; the only "
                        "thing fetched back is the toolkit's own labelled canary token.")
    p.add_argument("--cookie", default=None,
                   help="Raw Cookie header value presented by active web modules so they can test "
                        "authenticated surface (read-only, operator-supplied).")
    p.add_argument("--bearer", default=None,
                   help="Bearer token presented by active modules (sets Authorization: Bearer ...).")
    p.add_argument("--request-header", dest="request_header", action="append", default=None,
                   help="Extra request header as 'Name: Value' (repeatable) for authenticated "
                        "testing (e.g. 'X-CSRF-Token: abc').")
    p.add_argument("--email", default=None,
                   help="Email address or domain to probe: resolves MX host, probes SMTP "
                        "ports (25, 587, 465), and runs DNS posture checks. "
                        "Also accepted as a bare positional argument (auto-detected by '@').")
    p.add_argument("--proxy", default=None,
                   help="Route active HTTP(S) traffic through this proxy (http://host:port or "
                        "socks5://host:port) for auditability/positioning.")
    p.add_argument("--proxy-list", dest="proxy_list", default=None,
                   help="Comma-separated list of proxies to rotate through, or @/path/to/file "
                        "with one proxy per line (http://host:port or socks5://host:port). "
                        "Overrides --proxy when set; each request cycles to the next entry.")
    p.add_argument("--pivot-proxy", dest="pivot_proxy", default=None,
                   help="Relay tunnel positioned through a proven foothold (http://host:port or "
                        "socks5://host:port, e.g. an 'ssh -D' SOCKS proxy). Foothold-relayed "
                        "reachability sweeps AND the host:port/url modules for pivot hops route "
                        "through it, so lateral movement is performed FROM the foothold.")
    p.add_argument("--propagate", action="store_true",
                   help="Route ALL pivot sub-target traffic through the foothold's relay/proxy. "
                        "When a foothold is proven (Docker, kubelet, proxy), the toolkit "
                        "automatically tunnels subsequent module traffic through it — running "
                        "scans AS IF from the compromised device. Requires --prove-access.")
    p.add_argument("--propagate-script", dest="propagate_script", action="store_true",
                   help="Deploy the scanner itself onto proven footholds (as a self-extracting "
                        "archive) and execute a full network scan from inside. This is "
                        "the red-team 'full autonomy' mode: each proven device becomes a new "
                        "scanner vantage point. Requires --prove-access AND either --yes or "
                        "interactive confirmation. The deployed payload is auto-cleaned.")
    p.add_argument("--propagate-depth", dest="propagate_depth", type=int, default=None,
                   help="Remaining propagation depth (decremented each hop). When 0, the "
                        "propagated instance does not propagate further. Default from config "
                        "(PROPAGATE_MAX_DEPTH=2).")
    p.add_argument("--propagate-strategy", dest="propagate_strategy", default=None,
                   choices=["auto", "native", "zipapp", "source"],
                   help="Force a specific propagation payload strategy. Default: auto "
                        "(tries native binary > zipapp > source tar.gz).")
    p.add_argument("--host-subnet", dest="host_subnet", default=None,
                   help="CIDR of the current host's subnet (auto-populated during propagation "
                        "to scan the hop's local network). Equivalent to --cidr but named for "
                        "clarity in propagated context.  Example: 10.0.1.0/24")
    p.add_argument("--propagated-instance", dest="propagated_instance",
                   action="store_true", default=False,
                   help=argparse.SUPPRESS)  # internal: set by parent propagator only
    p.add_argument("--oob-listen", dest="oob_listen", nargs="?", const="127.0.0.1:0",
                   default=None,
                   help="Start a built-in out-of-band canary listener (default 127.0.0.1:0) and "
                        "use it as the --canary-url for blind SSRF/injection confirmation.")
    p.add_argument("--targets-file", dest="targets_file", default=None,
                   help="File with targets: either one spec per line (host:port, URL, CIDR) or a "
                        "JSON file (object or array) with fields: url, host, port, email, cidr, "
                        "repo, jwt, api_key, username, password. Each entry is resolved and "
                        "scanned with the same intensity/scope governor.")
    p.add_argument("--profile", default=None,
                   choices=["quick", "standard", "deep", "stealth"],
                   help="Scan profile preset bundling intensity + parallelism + rate "
                        "(quick/standard/deep/stealth). Explicit --intensity/--jobs override it.")
    p.add_argument("--jobs", type=int, default=None,
                   help="Max modules to run concurrently (default from the profile/config; the "
                        "global request budget still paces total volume). Use 1 for sequential.")
    p.add_argument("--resume", default=None,
                   help="Path to a resume-state file; modules already completed for a target "
                        "(per this file) are skipped and newly-completed ones recorded.")
    p.add_argument("--sarif", default=None, help="Also write a SARIF 2.1.0 report to this path.")
    p.add_argument("--html", default=None, help="Also write a standalone HTML report to this path.")
    p.add_argument("--baseline", default=None,
                   help="Compare findings against a prior JSON artifact; marks new/fixed findings.")
    p.add_argument("--fail-on-new-only", dest="fail_on_new_only", action="store_true",
                   help="With --baseline, only fail the run (exit 1) on findings new vs the baseline.")
    p.add_argument("--local", action="store_true",
                   help="Introspect THIS host (container-escape preconditions, cloud-IMDS posture, "
                        "rootkit IOCs). Read-only; runs only the local-introspection modules.")
    p.add_argument("--header", dest="auth_header", default=None,
                   help="Custom header NAME to carry the token/api-key (e.g. X-Auth-Token).")
    p.add_argument("--auth-scheme", dest="auth_scheme", default=None,
                   help="Value prefix/scheme for the token (default 'Bearer' for --jwt, none for --api-key; "
                        "pass '' for a raw value).")
    p.add_argument("--json", default=os.path.join(TOOL_DIR, "report", "last_run.json"),
                   help="Path to write the JSON artifact.")
    p.add_argument("--markdown", default=None, help="Optional path to write a Markdown report.")
    p.add_argument("--llm", action="store_true", help="Use a local Ollama model to summarise findings.")
    p.add_argument("--model", default=None, help="Preferred Ollama model (e.g. llama3, gemma2).")
    p.add_argument("--allow-remote-llm", dest="allow_remote_llm", action="store_true",
                   help="Permit a non-loopback OLLAMA_HOST (sends findings off-box). Off by default.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("--yes", "-y", dest="assume_yes", action="store_true",
                   help="Acknowledge the pre-scan safety check (the target is non-production "
                        "and within your authorised scope) without the interactive prompt. "
                        "An interactive run is otherwise prompted before the first scan.")
    p.add_argument("--only", default=None,
                   help="Comma-separated module names to run (default: all applicable).")
    p.add_argument("--list-modules", action="store_true",
                   help="List every available module (name, supported target kinds, description) and exit.")
    p.add_argument("--fail-on", dest="fail_on", default=None,
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                   help="Exit non-zero only if an exploited module's worst finding is at least "
                        "this severity (default: any exploited module fails the run).")
    p.add_argument("--keep-credentials", action="store_true",
                   help="Disable the credential guard (NOT recommended). By default ambient "
                        "AWS/EKS/ArgoCD/JFrog/GitHub/Docker credentials are scrubbed so the "
                        "run is guaranteed credential-free.")
    p.add_argument("--prove-access", dest="prove_access", action="store_true",
                   help="Enable the opt-in access-prover. Against an already-confirmed "
                        "unauthenticated service (or a reachable/compromised filesystem) it creates "
                        "a HARMLESS, clearly-labelled proof artifact (a marker file, a benign "
                        "datastore key/doc, or a throwaway container). Artifacts PERSIST so the blue "
                        "team can verify them. Never changes config, never destroys data. This flag "
                        "turns on ALL proof types (writes + shell) by default. Off by default.")
    p.add_argument("--prove-access-writes", dest="prove_access_writes", action="store_true",
                   help="(Implied by --prove-access.) Permit the write proofs that create a "
                        "dedicated, persistent harmless canary (e.g. an Elasticsearch index/doc).")
    p.add_argument("--prove-access-shell", dest="prove_access_shell", action="store_true",
                   help="(Implied by --prove-access.) Against an exposed Docker Engine API, spawn a "
                        "persistent throwaway container with an interactive shell and hand the "
                        "operator the attach command (proves code execution). Never touches the host "
                        "filesystem destructively.")
    p.add_argument("--use-discovered-cloud-creds", dest="use_discovered_cloud_creds",
                   action="store_true",
                   help="Enable the credentialed cloud path. The toolkit NEVER accepts cloud keys "
                        "from you; instead it discovers ambient credentials already on the host (an "
                        "instance/VM metadata role, ~/.aws/credentials, ~/.config/gcloud, an AWS_* "
                        "env var) exactly as an attacker on a compromised host would. The cloud "
                        "modules activate ONLY if something is discovered; otherwise the path stays "
                        "dormant. Credentials are held in memory, never written to the report.")
    p.add_argument("--no-imds", dest="no_imds", action="store_true",
                   help="During cloud-credential discovery, do not probe link-local instance "
                        "metadata (169.254.169.254); only inspect env vars and on-disk profiles.")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    # --list-modules is informational and needs no target or credential guard.
    if args.list_modules:
        _print_modules()
        return 0

    # --- discovery-driven cloud credentials (BEFORE the guard scrubs them) ----
    # A real attacker inherits whatever cloud credentials the host already holds. We
    # discover them here, BEFORE the credential guard scrubs env/files/IMDS, then hand
    # the in-memory inventory ONLY to the opt-in cloud modules. Everything else still
    # runs credential-free. With nothing discovered, the cloud path stays dormant.
    cloud_inventory = None
    if args.use_discovered_cloud_creds:
        from sandbox import cloud_creds
        cloud_inventory = cloud_creds.discover(probe_imds=not args.no_imds)
        if cloud_inventory:
            masked = "; ".join(c.masked() for c in cloud_inventory.credentials[:6])
            print(f"[!] cloud-creds discovery: found {len(cloud_inventory.credentials)} ambient "
                  f"credential(s) [{masked}]. The credentialed cloud path is ACTIVE; these creds "
                  "are used only by the cloud modules and are never written to the report.",
                  file=sys.stderr)
        else:
            print("[*] cloud-creds discovery: no ambient cloud credentials found; the "
                  "credentialed cloud path stays dormant.", file=sys.stderr)

    # --- enforce "runs without ambient credentials" before anything else -----
    # Scrubs AWS/EKS/ArgoCD/JFrog/GitHub/Docker creds from the environment.
    # Target credentials the user explicitly passes (--username/--jwt/...) are
    # carried in the Target object, NOT the environment, so they are unaffected.
    if not args.keep_credentials:
        from sandbox import credential_guard
        pre = credential_guard.scrub()
        if not credential_guard.self_test():
            print("error: credential guard self-test failed; refusing to run.", file=sys.stderr)
            return 2
        print(f"[*] credential guard: {credential_guard.status()}", file=sys.stderr)
        if pre["env"] or pre["files"]:
            neutralised = ", ".join(pre["env"][:6]) + (" ..." if len(pre["env"]) > 6 else "")
            print(f"[*] neutralised {len(pre['env'])} credential env var(s) and "
                  f"{len(pre['files'])} on-disk credential file(s); none were used."
                  + (f" [{neutralised}]" if neutralised.strip() else ""), file=sys.stderr)
    else:
        print("[!] credential guard DISABLED via --keep-credentials.", file=sys.stderr)

    # --- resolve the target --------------------------------------------------
    # If cloud creds were discovered, the credentialed cloud assessment takes
    # precedence (it is the most specific, opt-in intent the operator expressed).
    if cloud_inventory:
        target = targetmod.Target(kind=targetmod.CLOUD, raw="cloud",
                                  cloud_inventory=cloud_inventory)
    else:
        if args.use_discovered_cloud_creds:
            print("error: --use-discovered-cloud-creds was set but no cloud credentials were "
                  "discovered on this host; nothing to assess.", file=sys.stderr)
            return 2
        # Detect when --targets-file is the only meaningful target spec so we
        # don't silently fall back to the workspace repo as the primary target.
        _targets_file_only = bool(
            args.targets_file and not (
                args.target or args.repo or args.url or args.jwt or args.api_key
                or args.username or args.host_port or args.cidr or args.local
                or getattr(args, "email", None)
            )
        )
        if _targets_file_only:
            target = None
        else:
            try:
                target = targetmod.resolve(
                    positional=args.target, repo=args.repo, url=args.url,
                    jwt=args.jwt, api_key=args.api_key,
                    username=args.username, password=args.password,
                    email=getattr(args, "email", None),
                    host_port=args.host_port, ports=args.ports,
                    auth_header=args.auth_header, auth_scheme=args.auth_scheme,
                    default_repo=None,
                    local=args.local,
                    cidr=args.cidr or args.host_subnet, max_hosts=args.max_hosts,
                )
            except targetmod.TargetError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
    if target is not None:
        print(f"[*] target: {target.describe()} (kind={target.kind})", file=sys.stderr)
    else:
        print(f"[*] target: (none — loading all targets from --targets-file)", file=sys.stderr)

    # --- opt-in proof-of-access (computed once; depends only on args) ---------
    # --prove-access is the master switch: it turns on ALL proof types. The
    # finer-grained flags also work on their own for operators who want just one.
    prove = bool(args.prove_access or args.prove_access_writes or args.prove_access_shell)
    if prove:
        print("[!] access-prover ENABLED: will create HARMLESS, clearly-labelled proof artifacts "
              "(a marker file on any writable/compromised filesystem, a benign datastore key/doc, "
              "and/or a throwaway container) against confirmed exposures. Artifacts PERSIST for "
              "blue-team verification. No configuration changes, no data destruction.",
              file=sys.stderr)

    # --- scan profile preset (intensity + parallelism + rate) ----------------
    # A profile only fills values the operator did not set explicitly, so --intensity /
    # --jobs always win over the preset.
    _cfg = __import__("config")
    profile = getattr(_cfg, "SCAN_PROFILES", {}).get(args.profile or "", {})
    if profile:
        print(f"[*] scan profile: {args.profile} -> {profile}", file=sys.stderr)
    if args.jobs is not None:
        jobs = args.jobs
    elif profile.get("jobs"):
        jobs = profile["jobs"]
    else:
        from sandbox import resources
        jobs = resources.detect_optimal_jobs()
        print(f"[*] adaptive parallelism: {jobs} concurrent modules "
              f"({resources.describe()})", file=sys.stderr)
    jobs = max(1, int(jobs))
    rate_limit = profile.get("rate_limit")  # None => config default

    # --- intensity tier + scope allow-list (the outbound-aggressiveness guard) ----
    from sandbox import scope_guard
    intensity = scope_guard.normalise(
        args.intensity or profile.get("intensity")
        or getattr(_cfg, "DEFAULT_INTENSITY", "active"))
    # --prove-access is the explicit opt-in for the proof tier; it implies it.
    if prove:
        intensity = scope_guard.PROOF
    scope_specs = list(args.scope or [])
    if args.scope_file:
        scope_specs += scope_guard.load_scope_file(args.scope_file)
    guard = scope_guard.ScopeGuard.from_specs(scope_specs, intensity=intensity)
    # v2 scope model: at intrusive+ intensity, require --yes or interactive confirmation
    # (allow-list is optional narrowing, not mandatory).
    if guard.requires_confirmation and not args.assume_yes:
        # Interactive confirmation required
        if not sys.stdin.isatty():
            print(f"error: --intensity {intensity} requires explicit confirmation. "
                  "Pass --yes in non-interactive shells, or run interactively.",
                  file=sys.stderr)
            if target is not None:
                target.cleanup()
            return 2
        _t_desc = target.describe() if target is not None else "(targets-file)"
        scope_desc = guard.summary() if not guard.empty else f"target-derived ({_t_desc})"
        print(f"\n[!] INTRUSIVE+ SCAN — intensity={intensity}, scope={scope_desc}\n"
              f"    This will perform multi-request enumeration/guessing against the target.\n"
              f"    Confirm the target is non-production and within your authorized scope.",
              file=sys.stderr)
        answer = input("    Proceed? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted by operator.", file=sys.stderr)
            if target is not None:
                target.cleanup()
            return 2
    print(f"[*] scope guard: {guard.summary()}", file=sys.stderr)
    if args.spray and scope_guard.rank(intensity) < scope_guard.rank(scope_guard.INTRUSIVE):
        print("[!] --spray ignored: it requires --intensity intrusive (or higher).",
              file=sys.stderr)

    # --propagate implies --propagate-script: once we route all pivot traffic through a
    # foothold relay, we should also deploy the scanner there for a full vantage-point scan.
    if getattr(args, "propagate", False) and not getattr(args, "propagate_script", False):
        args.propagate_script = True
        print("[*] --propagate implies --propagate-script: scanner will be deployed "
              "onto proven footholds for a full vantage-point scan.", file=sys.stderr)

    # Operator-supplied authenticated-session headers (shared across all targets).
    session_headers = {}
    for raw in (args.request_header or []):
        if ":" in raw:
            name, value = raw.split(":", 1)
            if name.strip():
                session_headers[name.strip()] = value.strip()

    # Global egress proxy: route ALL active HTTP(S) traffic through it for auditability.
    from exploits import netutil as _netutil
    _netutil.set_default_proxy(args.proxy)
    if args.proxy:
        print(f"[*] egress proxy: all HTTP(S) traffic routed via {args.proxy}", file=sys.stderr)

    # Proxy rotation list: --proxy-list takes precedence over --proxy.
    if getattr(args, "proxy_list", None):
        _proxy_entries = _parse_proxy_list(args.proxy_list)
        if _proxy_entries:
            _netutil.set_proxy_list(_proxy_entries)
            print(f"[*] proxy rotation: {len(_proxy_entries)} proxies configured "
                  f"({_proxy_entries[0]}...)", file=sys.stderr)
        else:
            print("[!] --proxy-list: no valid proxy entries found; using --proxy if set.",
                  file=sys.stderr)

    from sandbox import budget as _budget

    # Optional built-in out-of-band canary listener (created once; shared by all targets).
    oob = None
    canary_url = args.canary_url
    if args.oob_listen is not None:
        from sandbox import oob_listener
        host, port = oob_listener.parse_listen_spec(args.oob_listen)
        oob = oob_listener.OOBListener(host, port).start()
        canary_url = oob.base_url()
        print(f"[*] OOB canary listener: {oob.base_url()} (used as --canary-url)",
              file=sys.stderr)

    # --- assemble the target list (D5: --targets-file fans out additional specs) ---
    targets = [target] if target is not None else []
    if args.targets_file:
        extra = _load_targets_file(args, None)
        if extra:
            print(f"[*] targets-file: loaded {len(extra)} target(s) from "
                  f"{args.targets_file}", file=sys.stderr)
        else:
            print(f"[!] targets-file: no targets loaded from {args.targets_file}",
                  file=sys.stderr)
        targets += extra
    if not targets:
        print("error: no targets to scan. Supply a target or a non-empty --targets-file.",
              file=sys.stderr)
        return 2

    # Optional resume-state store (skip modules already completed for a target).
    resume = None
    if args.resume:
        from report import state as _state
        resume = _state.ResumeState.load(args.resume)
        print(f"[*] resume state: {args.resume} ({resume.count} completed entry/ies loaded)",
              file=sys.stderr)

    # --- pre-scan safety confirmation (before ANY traffic is sent) -----------
    # Show the operator exactly what is about to be scanned and require confirmation that
    # the target is non-production and within the authorised scope. This also covers the
    # subnet-broadening that proven access triggers (each peer is still scope-checked).
    if not _confirm_scan(targets, args, guard, intensity):
        for t in targets:
            t.cleanup()
        if oob is not None:
            oob.stop()
        return 2

    # --- validate propagation flags ------------------------------------------
    if getattr(args, "propagate", False) and not prove:
        print("error: --propagate requires --prove-access (propagation uses proven footholds "
              "as relay vantage points).", file=sys.stderr)
        return 2
    if getattr(args, "propagate_script", False):
        # Depth exhaustion: if --propagate-depth is 0, silently disable propagation
        if getattr(args, "propagate_depth", None) == 0:
            args.propagate_script = False
            print("[*] propagation depth exhausted (--propagate-depth 0); propagation disabled.",
                  file=sys.stderr)
        elif not prove:
            print("error: --propagate-script requires --prove-access.", file=sys.stderr)
            return 2
        elif not _confirm_propagate(args, out=sys.stderr):
            for t in targets:
                t.cleanup()
            if oob is not None:
                oob.stop()
            return 2

    try:
        exit_code = 0
        for t in targets:
            _configure_target(t, args, prove, intensity, guard, session_headers,
                              canary_url, _budget, scope_guard, rate_limit)
            selected = _select_modules(t, args, intensity)
            if selected is None:
                exit_code = max(exit_code, 2)
                continue
            rc = _run(t, selected, args, jobs=jobs, resume=resume)
            exit_code = max(exit_code, rc)
    finally:
        for t in targets:
            t.cleanup()
        if oob is not None:
            oob.stop()
    return exit_code


def _configure_target(target, args, prove, intensity, guard, session_headers,
                      canary_url, budget_mod, scope_guard, rate_limit=None) -> None:
    """Apply the shared governance/session settings onto a single target."""
    target.prove_access = prove
    target.prove_access_writes = bool(args.prove_access or args.prove_access_writes)
    target.prove_access_shell = bool(args.prove_access or args.prove_access_shell)
    target.nse_scripts = args.nse_scripts
    target.scope_guard = guard
    target.intensity = intensity
    spray = bool(args.spray)
    if spray and scope_guard.rank(intensity) < scope_guard.rank(scope_guard.INTRUSIVE):
        spray = False
    target.spray = spray
    target.canary_url = canary_url
    target.cookies = args.cookie
    if args.bearer:
        target.jwt = args.bearer
        if getattr(target, "auth_scheme", None) is None:
            target.auth_scheme = "Bearer"
    target.session_headers = dict(session_headers)
    target.proxy = args.proxy
    target.pivot_proxy = getattr(args, "pivot_proxy", None)
    target.propagate = getattr(args, "propagate", False)
    target.propagate_script = getattr(args, "propagate_script", False)
    target.propagate_depth = (args.propagate_depth if getattr(args, "propagate_depth", None) is not None
                              else getattr(__import__("config"), "PROPAGATE_MAX_DEPTH", 2))
    # True only when this scanner instance was deployed by a parent propagator via
    # --propagated-instance (injected by _build_propagation_args; never set by end users).
    target.is_propagated = bool(getattr(args, "propagated_instance", False))
    target._propagate_strategy = getattr(args, "propagate_strategy", None)
    target.reached_via = "scanner"
    # CVE flags (forwarded during propagation)
    target._cve_lookup = getattr(args, "cve_lookup", False)
    target._cve_test = getattr(args, "cve_test", False)
    target._cve_max = getattr(args, "cve_max", 10)
    target._cve_api_key = getattr(args, "cve_api_key", None)
    # Shared proof-of-access ledger: every hop reached from this root target (including deep
    # pivots) records into this one object so the identification path is consolidated.
    from sandbox import ledger as _ledger
    target.proof_ledger = _ledger.ProofLedger()
    target.budget = (budget_mod.RequestBudget(rate_limit=rate_limit)
                     if rate_limit is not None else budget_mod.from_config())


def _select_modules(target, args, intensity):
    """Pick the modules for a target; returns a list, or None on a fatal selection error."""
    applicable = registry.modules_for(target.kind, intensity)
    selected = applicable
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        selected = registry.by_names(wanted, applicable)
        if not selected:
            print(f"error: no applicable modules matched --only={args.only} "
                  f"for kind={target.kind} at intensity={intensity}.", file=sys.stderr)
            return None
    if not selected:
        print(f"error: no modules support target kind '{target.kind}' "
              f"at intensity '{intensity}'.", file=sys.stderr)
        return None
    return selected


def _load_targets_file(args, default_repo) -> list:
    """Resolve targets from ``args.targets_file``.

    Supports two formats:
    * **Line-per-target** (legacy): one host:port, URL, or CIDR per line.
    * **JSON**: a dict or list of dicts with structured fields (url, host, port,
      email, cidr, repo, jwt, api_key, username, password, etc.).
    """
    path = args.targets_file
    max_targets = getattr(__import__("config"), "TARGETS_FILE_MAX", 256)
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as exc:
        print(f"[!] could not read --targets-file '{path}': {exc!r}", file=sys.stderr)
        return out

    # Detect JSON format
    stripped = content.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return _load_json_targets(stripped, args, max_targets)

    # Legacy line-per-target format
    lines = [ln.strip() for ln in content.splitlines()]
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if len(out) >= max_targets:
            print(f"[!] --targets-file capped at {max_targets} targets; ignoring the rest.",
                  file=sys.stderr)
            break
        try:
            t = targetmod.resolve(
                positional=line, repo=None, url=None,
                jwt=args.jwt, api_key=args.api_key,
                username=None, password=None, email=None,
                host_port=None, ports=args.ports,
                auth_header=args.auth_header, auth_scheme=args.auth_scheme,
                default_repo=default_repo, local=False,
                cidr=None, max_hosts=args.max_hosts,
            )
        except targetmod.TargetError as exc:
            print(f"[!] targets-file: skipping {line!r} ({exc})", file=sys.stderr)
            continue
        out.append(t)
    return out


def _load_json_targets(content: str, args, max_targets: int) -> list:
    """Parse a JSON targets file (single object or array of objects)."""
    import json
    out = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        print(f"[!] --targets-file: invalid JSON: {exc}", file=sys.stderr)
        return out

    # Normalise: single object → list of one
    if isinstance(data, dict):
        entries = [data]
    elif isinstance(data, list):
        entries = data
    else:
        print("[!] --targets-file: JSON must be an object or array of objects.", file=sys.stderr)
        return out

    for entry in entries:
        if not isinstance(entry, dict):
            print(f"[!] targets-file: skipping non-object entry: {entry!r}", file=sys.stderr)
            continue
        if len(out) >= max_targets:
            print(f"[!] --targets-file capped at {max_targets} targets; ignoring the rest.",
                  file=sys.stderr)
            break
        try:
            targets = targetmod.resolve_from_dict(entry, max_hosts=args.max_hosts)
        except targetmod.TargetError as exc:
            print(f"[!] targets-file: skipping entry ({exc})", file=sys.stderr)
            continue
        out.extend(targets)
    return out



def _parse_proxy_list(spec: str) -> list:
    """Parse a proxy list from a comma-separated string or an @/path/to/file spec."""
    proxies = []
    if spec.startswith("@"):
        path = spec[1:]
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxies.append(line)
        except OSError as exc:
            print(f"[!] --proxy-list: cannot read file {path!r}: {exc}", file=sys.stderr)
    else:
        for part in spec.split(","):
            part = part.strip()
            if part:
                proxies.append(part)
    return [p for p in proxies if "://" in p]


def _confirm_scan(targets, args, guard, intensity, *, isatty=None,
                  input_fn=None, out=None) -> bool:
    """Show the operator what is about to be scanned and confirm it is safe to proceed.

    Before ANY traffic is sent, the toolkit lists the live targets, the intensity and the
    scope allow-list, and notes that devices with proven access will have their subnet
    swept (within scope). It then requires the operator to confirm the target is NOT a
    production environment and is within the authorised scope.

    Returns True to proceed, False to abort. Static targets (repo/local introspection read
    local files only) never need the gate. The interactive prompt fires only on a TTY; a
    non-interactive shell (e.g. CI) must pass ``--yes`` to acknowledge explicitly, otherwise
    a live scan is refused (fail-closed). ``isatty``/``input_fn`` are injectable for testing.
    """
    out = out or sys.stderr
    input_fn = input_fn or input
    if isatty is None:
        try:
            isatty = sys.stdin.isatty()
        except Exception:
            isatty = False
    live_kinds = {targetmod.URL, targetmod.HOSTPORT, targetmod.NETRANGE, targetmod.CLOUD}
    live = [t for t in targets if getattr(t, "kind", None) in live_kinds]
    if not live:
        return True  # repo / local introspection: read-only, nothing to confirm.

    print("\n[!] PRE-SCAN CONFIRMATION — review the target before any traffic is sent:",
          file=out)
    for t in live:
        print(f"      - {t.describe()} (kind={t.kind})", file=out)
    print(f"    intensity: {intensity}", file=out)
    if guard is not None:
        print(f"    scope:     {guard.summary()}", file=out)
    print("    note: any device with PROVEN access will have its subnet swept for live hosts "
          "and re-probed — every peer is checked against the scope allow-list first.", file=out)

    if getattr(args, "assume_yes", False):
        print("[*] --yes supplied: target acknowledged as non-production / in-scope; proceeding.",
              file=out)
        return True
    if not isatty:
        print("[!] non-interactive shell and --yes not supplied: REFUSING to scan a live target "
              "without confirmation. Re-run interactively to be prompted, or pass --yes to "
              "acknowledge the target is non-production and within your authorised scope.",
              file=out)
        return False
    try:
        answer = input_fn("    Confirm this is NOT a production environment and is within your "
                          "authorised scope? [y/N]: ")
    except (EOFError, KeyboardInterrupt):
        print("\n[!] confirmation aborted; no scan was performed.", file=out)
        return False
    if str(answer).strip().lower() in ("y", "yes"):
        print("[*] confirmed; starting the scan.", file=out)
        return True
    print("[!] not confirmed; aborting before any scan traffic was sent. Re-run against a "
          "non-production, in-scope target (or pass --scope/--yes).", file=out)
    return False


def _confirm_propagate(args, *, isatty=None, input_fn=None, out=None) -> bool:
    """Require explicit acknowledgement for --propagate-script (deploys code onto footholds).

    This is more aggressive than a normal scan: the toolkit will deploy itself into proven
    footholds and execute autonomously from there. It requires either --yes or interactive
    confirmation. Non-interactive without --yes is refused (fail-closed).
    """
    out = out or sys.stderr
    input_fn = input_fn or input
    if isatty is None:
        try:
            isatty = sys.stdin.isatty()
        except Exception:
            isatty = False

    print("\n[!] --propagate-script CONFIRMATION — the toolkit will deploy itself onto proven "
          "footholds and run a scan from inside each compromised device. This is the red-team "
          "'full autonomy' mode. The deployed payload is auto-cleaned after execution.",
          file=out)

    if getattr(args, "assume_yes", False):
        print("[*] --yes supplied: propagation acknowledged; proceeding.", file=out)
        return True
    if not isatty:
        print("[!] non-interactive shell and --yes not supplied: REFUSING --propagate-script "
              "without confirmation. Pass --yes to acknowledge.", file=out)
        return False
    try:
        answer = input_fn("    Confirm you authorise deploying the scanner onto proven footholds? "
                          "[y/N]: ")
    except (EOFError, KeyboardInterrupt):
        print("\n[!] propagation aborted.", file=out)
        return False
    if str(answer).strip().lower() in ("y", "yes"):
        print("[*] propagation confirmed.", file=out)
        return True
    print("[!] propagation not confirmed; --propagate-script disabled for this run.", file=out)
    return False



def _safe_run(mod, target):
    """Run one module, converting any crash into a non-fatal error result."""
    try:
        return mod.run(target)
    except Exception as exc:  # a module must never crash the whole run
        from exploits.base import ExploitResult
        return ExploitResult(
            name=getattr(mod, "NAME", mod.__name__),
            description=getattr(mod, "DESCRIPTION", ""),
            exploited=False, error=f"module crashed: {exc!r}", tool_available=False,
        )


def _run_modules(mods, target, jobs: int = 1, resume=None) -> list:
    """Run ``mods`` against ``target`` (optionally concurrently), preserving input order.

    Modules are independent, so a bounded thread pool runs them in parallel; the shared
    global request budget still paces total outbound volume, so concurrency never raises
    the request ceiling. With ``--resume`` a module already completed for this target is
    skipped, and each completed module is recorded so an interrupted run can continue.
    """
    label = target.describe()
    pending = [m for m in mods
               if resume is None or not resume.is_done(label, registry.name_of(m))]
    if not pending:
        return []
    results = [None] * len(pending)
    if jobs <= 1 or len(pending) == 1:
        for i, m in enumerate(pending):
            results[i] = _safe_run(m, target)
            if resume is not None:
                resume.mark(label, registry.name_of(m))
        return [r for r in results if r is not None]

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(jobs, len(pending))) as ex:
        futmap = {ex.submit(_safe_run, m, target): i for i, m in enumerate(pending)}
        for fut in concurrent.futures.as_completed(futmap):
            i = futmap[fut]
            try:
                results[i] = fut.result(timeout=600)
                if resume is not None:
                    resume.mark(label, registry.name_of(pending[i]))
            except concurrent.futures.TimeoutError:
                results[i] = None
    return [r for r in results if r is not None]


def _fanout_hostport(target, selected, args, jobs: int = 1, resume=None) -> list:
    """After a netrange sweep, probe each discovered live host with hostport modules.

    The netrange-native modules (host-sweep, and optionally nmap/nuclei) discover the
    live hosts; here we reuse the existing per-service modules against each of them by
    synthesising a transient ``hostport`` target. Modules already run at the netrange
    level (they support both kinds) are skipped to avoid double-scanning. Bounded by
    NETRANGE_WALL_BUDGET.
    """
    import time
    live = list(getattr(target, "live_hosts", []) or [])
    if not live:
        return []
    already = {registry.name_of(m) for m in selected}
    run_intensity = getattr(target, "intensity", None)
    hostport_mods = [m for m in registry.modules_for(targetmod.HOSTPORT, run_intensity)
                     if registry.name_of(m) not in already]
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        hostport_mods = registry.by_names(wanted, hostport_mods)
    if not hostport_mods:
        return []

    try:
        budget = __import__("config").NETRANGE_WALL_BUDGET
    except Exception:
        budget = 600
    ports = list(target.ports or [])
    deadline = time.monotonic() + budget
    results = []
    for host in live:
        if time.monotonic() > deadline:
            print(f"[!] netrange fan-out hit the {budget}s budget; "
                  f"stopped before finishing all live hosts.", file=sys.stderr)
            break
        sub = targetmod.Target(
            kind=targetmod.HOSTPORT, raw=str(host), host=host,
            port=(ports[0] if ports else None), ports=ports,
        )
        sub.prove_access = getattr(target, "prove_access", False)
        sub.prove_access_writes = getattr(target, "prove_access_writes", False)
        sub.prove_access_shell = getattr(target, "prove_access_shell", False)
        sub.nse_scripts = getattr(target, "nse_scripts", None)
        sub.scope_guard = getattr(target, "scope_guard", None)
        sub.intensity = getattr(target, "intensity", None)
        sub.spray = getattr(target, "spray", False)
        sub.canary_url = getattr(target, "canary_url", None)
        sub.cookies = getattr(target, "cookies", None)
        sub.session_headers = getattr(target, "session_headers", {}) or {}
        sub.proxy = getattr(target, "proxy", None)
        sub.budget = getattr(target, "budget", None)
        results.extend(_run_modules(hostport_mods, sub, jobs=jobs, resume=resume))
    return results


def _inherit_governance(sub, parent) -> None:
    """Copy the shared governance/session settings from ``parent`` onto a synthesized target."""
    sub.prove_access = getattr(parent, "prove_access", False)
    sub.prove_access_writes = getattr(parent, "prove_access_writes", False)
    sub.prove_access_shell = getattr(parent, "prove_access_shell", False)
    sub.nse_scripts = getattr(parent, "nse_scripts", None)
    sub.scope_guard = getattr(parent, "scope_guard", None)
    sub.intensity = getattr(parent, "intensity", None)
    sub.spray = getattr(parent, "spray", False)
    sub.canary_url = getattr(parent, "canary_url", None)
    sub.cookies = getattr(parent, "cookies", None)
    sub.session_headers = getattr(parent, "session_headers", {}) or {}
    sub.proxy = getattr(parent, "proxy", None)
    sub.budget = getattr(parent, "budget", None)
    # Lateral-movement plumbing: share the one proof-of-access ledger and the operator relay
    # tunnel so every hop is identified in the same place and reached from the foothold.
    sub.pivot_proxy = getattr(parent, "pivot_proxy", None)
    sub.proof_ledger = getattr(parent, "proof_ledger", None)


# Service ports probed when a URL target's host is scanned alongside HTTP/HTTPS.
# Mirrors _NETRANGE_DEFAULT_PORTS so the hostport companion covers the same surface
# a network sweep would — SSH, DBs, Redis, container/k8s control planes, admin panels.
_URL_COMPANION_PORTS = (
    22,     # SSH
    25,     # SMTP
    80,     # HTTP
    443,    # HTTPS
    587,    # SMTP submission
    2375,   # Docker daemon (unauthenticated)
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5672,   # AMQP (RabbitMQ)
    6379,   # Redis
    6443,   # Kubernetes API
    8080,   # HTTP-alt (Jenkins/Tomcat/admin panels)
    8443,   # HTTPS-alt
    9090,   # Prometheus / gRPC / Cockpit
    9093,   # Kafka / Alertmanager
    9200,   # Elasticsearch
    10250,  # Kubernetes kubelet
    10255,  # Kubernetes kubelet readonly
    15672,  # RabbitMQ management UI
    27017,  # MongoDB
    50051,  # gRPC standard port
)


def _push_url_hostport_companion(target) -> None:
    """Queue a hostport pivot for the URL target's host so service-level modules run against it.

    URL modules probe HTTP/HTTPS application logic; they don't do banner grabs, database
    probes, SSH checks, Redis/Elasticsearch reconnaissance, etc. Pushing the host as a
    hostport pivot ensures non-web services on the same IP are covered without duplicating
    the HTTP surface (the pivot fan-out deduplicates by host).

    Skipped when:
    - target has no URL
    - the host is already pushed (idempotent flag ``_url_companion_pushed``)
    - the host is out of scope
    - target.pivot_targets is not initialised
    """
    if getattr(target, "_url_companion_pushed", False):
        return
    target._url_companion_pushed = True
    url = getattr(target, "url", None)
    if not url:
        return
    from urllib.parse import urlparse as _urlparse
    host = _urlparse(url).hostname
    if not host:
        return
    guard = getattr(target, "scope_guard", None)
    if guard is not None and not guard.authorize(host)[0]:
        return
    pivot_targets = getattr(target, "pivot_targets", None)
    if pivot_targets is None:
        return
    pivot_targets.append({
        "kind": "hostport",
        "host": host,
        "ports": list(_URL_COMPANION_PORTS),
        "via": f"url-companion:{host}",
        "note": f"service port scan of {host} alongside HTTP/HTTPS",
    })


def _expand_subnet_spec(spec, guard, deadline, target=None) -> list:
    """Expand a proven-foothold *subnet* pivot into live, in-scope ``host:port`` specs.

    Realises "use the accessible device to broaden the audit": the subnet of a device with
    proven access is expanded to candidate hosts, out-of-scope hosts are dropped up front,
    then a TCP-connect liveness sweep keeps only responsive peers. When the foothold offers a
    relay (an exposed Docker daemon, or an operator ``--pivot-proxy`` tunnel), the sweep is
    performed FROM the foothold's network position so privately-segmented peers are reached,
    not missed. Each live peer is returned as a host:port pivot spec — carrying its foothold
    provenance and any relay proxy — so the standard modules run against it through the relay.
    """
    import time
    from sandbox import relay as relay_mod
    from sandbox import ledger as ledger_mod
    _cfg = __import__("config")
    cidr = spec.get("cidr")
    via = spec.get("via", "?")
    reached_from = spec.get("reached_from") or via
    ports = list(spec.get("ports") or getattr(_cfg, "PIVOT_DEFAULT_PORTS", (22, 80, 443)))
    max_hosts = getattr(_cfg, "PIVOT_SUBNET_MAX_HOSTS", 256)
    # Build the relay: an explicit foothold relay on the spec wins; else an operator pivot
    # tunnel; else the scanner-side direct vantage (legacy behaviour).
    relay = relay_mod.build_relay(spec.get("relay"),
                                  fallback_proxy=getattr(target, "pivot_proxy", None))
    try:
        candidates = targetmod.parse_hosts(cidr, max_hosts=max_hosts)
    except targetmod.TargetError as exc:
        print(f"[!] subnet pivot {cidr} skipped ({exc}).", file=sys.stderr)
        return []
    # Scope-filter BEFORE touching any host (defence in depth + efficiency): an out-of-scope
    # subnet is mapped but never swept.
    if guard is not None:
        in_scope = [h for h in candidates if guard.authorize(h)[0]]
    else:
        in_scope = candidates
    skipped = len(candidates) - len(in_scope)
    if not in_scope:
        print(f"[*] subnet pivot {cidr} via {via}: all {len(candidates)} candidate host(s) "
              "out of scope; nothing swept.", file=sys.stderr)
        return []
    if time.monotonic() > deadline:
        return []
    timeout = getattr(_cfg, "PIVOT_SWEEP_TIMEOUT", 1.0)
    live = relay.sweep(in_scope, tuple(ports), timeout=timeout, deadline=deadline)
    proxy_url = relay.proxy_url()
    print(f"[*] broadening audit from proven foothold: subnet {cidr} via {relay.describe()} -> "
          f"{len(live)} live host(s) of {len(in_scope)} in-scope "
          f"({skipped} out-of-scope skipped)", file=sys.stderr)
    # Record each reachable peer in the ledger: identified, attributed to the foothold, with
    # the relay that proved reachability from the foothold's vantage.
    led = ledger_mod.get_or_create(target) if target is not None else None
    out = []
    for host, open_port in live:
        if led is not None:
            led.record(relay_mod.classify_resource_kind(targetmod.HOSTPORT, port=open_port),
                       f"{host}:{open_port}", reached_from=reached_from, via=relay.type,
                       proof=f"reachable from foothold via {relay.type}",
                       proof_kind=ledger_mod.REACHABILITY,
                       scope_status="in-scope", severity="MEDIUM",
                       note=f"live peer in {cidr} reached from {reached_from}")
        out.append({"kind": "hostport", "host": host, "ports": ports, "via": via,
                    "reached_from": reached_from, "via_proxy": proxy_url,
                    "note": f"live peer in {cidr} (proven-foothold subnet)"})
    return out



def _fanout_pivots(target, args, jobs: int = 1, resume=None) -> list:
    """Iterate the host:port / url modules across pivot targets published by other modules.

    A module that discovers further reachable surface — ``cloud-pivot`` mapping the subnet
    peers of an SSM-reachable instance, ``access-prover`` handing back the subnet of a proven
    foothold (optionally with a relay), or a named cross-cloud next hop (a Cloud Run URL) —
    appends specs to ``target.pivot_targets``. Here we synthesise a target per spec and run
    the applicable modules against it, modelling lateral movement from the foothold toward
    the resources it can reach. When a spec carries a relay/proxy the traffic is routed
    through the foothold, so a genuinely segmented next hop is exercised, not missed.

    Bounded by ``PIVOT_MAX_DEPTH`` (hops), a wall-clock budget, de-duplication, and the
    scope allow-list: every pivot host is ``scope_guard.authorize``d, so an out-of-scope
    peer is mapped but never probed. Every reached resource is recorded in the shared
    proof-of-access ledger with its foothold provenance and relay.
    """
    import time
    from sandbox import ledger as ledger_mod
    pending = list(getattr(target, "pivot_targets", []) or [])
    if not pending:
        return []
    _cfg = __import__("config")
    max_depth = getattr(_cfg, "PIVOT_MAX_DEPTH", 2)
    budget = getattr(_cfg, "PIVOT_WALL_BUDGET", 600)
    run_intensity = getattr(target, "intensity", None)
    guard = getattr(target, "scope_guard", None)
    led = ledger_mod.get_or_create(target)
    hostport_mods = registry.modules_for(targetmod.HOSTPORT, run_intensity)
    url_mods = registry.modules_for(targetmod.URL, run_intensity)
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        hostport_mods = registry.by_names(wanted, hostport_mods)
        url_mods = registry.by_names(wanted, url_mods)
    if not hostport_mods and not url_mods:
        return []

    results = []
    deadline = time.monotonic() + budget
    seen_hosts = set()
    seen_cidrs = set()
    seen_urls = set()
    # Iterative breadth-first walk so a pivot host can itself publish further pivots.
    queue = [(spec, getattr(target, "pivot_depth", 0) + 1) for spec in pending]
    target.pivot_targets = []  # drained
    while queue:
        if time.monotonic() > deadline:
            print(f"[!] pivot fan-out hit the {budget}s budget; stopping.", file=sys.stderr)
            break
        spec, depth = queue.pop(0)
        if depth > max_depth:
            continue
        # Subnet-broadening pivot: a device with PROVEN access hands us its whole subnet
        # ("use the accessible device to broaden the audit"). Expand it to live, in-scope
        # peers and enqueue each at the SAME depth (they are one hop, discovered together).
        if spec.get("cidr") or spec.get("kind") == targetmod.NETRANGE:
            cidr = spec.get("cidr")
            if not cidr or cidr in seen_cidrs:
                continue
            seen_cidrs.add(cidr)
            for child in _expand_subnet_spec(spec, guard, deadline, target):
                queue.append((child, depth))
            continue
        # Named cross-cloud / service next hop (e.g. a Cloud Run URL reachable from the
        # foothold). Run the url modules against it, tunnelled through the relay proxy.
        if spec.get("kind") == targetmod.URL or spec.get("url"):
            url = spec.get("url")
            if not url or not url_mods:
                continue
            url_key = url.lower().rstrip("/")
            if url_key in seen_urls:
                continue
            seen_urls.add(url_key)
            authz = _authorize_pivot(guard, url)
            reached_from = spec.get("reached_from") or spec.get("via", "?")
            if not authz[0]:
                print(f"[*] pivot url {url} skipped (out of scope: {authz[1]}) "
                      f"[via {reached_from}]", file=sys.stderr)
                continue
            print(f"[*] pivot: probing url {url} via {reached_from} "
                  f"(depth {depth}/{max_depth})", file=sys.stderr)
            sub = targetmod.Target(kind=targetmod.URL, raw=str(url), url=url)
            _inherit_governance(sub, target)
            sub.pivot_depth = depth
            sub.reached_via = reached_from
            sub.proxy = spec.get("via_proxy") or getattr(target, "pivot_proxy", None) or sub.proxy
            if led is not None:
                led.record("service", url, reached_from=reached_from, via="proxy",
                           proof="reachable named next hop", proof_kind=ledger_mod.REACHABILITY,
                           scope_status="in-scope", severity="MEDIUM",
                           note=f"named next hop reached from {reached_from}")
            results.extend(_run_modules(url_mods, sub, jobs=jobs, resume=resume))
            # After URL modules, also probe this host's non-HTTP service ports.
            # _push_url_hostport_companion appends to sub.pivot_targets; the loop
            # below immediately queues the companion spec at the same depth.
            _push_url_hostport_companion(sub)
            for nxt in (getattr(sub, "pivot_targets", []) or []):
                queue.append((nxt, depth + 1))
            continue
        host = spec.get("host")
        ports = list(spec.get("ports") or ([spec["port"]] if spec.get("port") else []))
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        # Scope check: a pivot host must be explicitly authorised at intrusive+ intensities.
        if guard is not None:
            ok, reason = guard.authorize(host)
            if not ok:
                print(f"[*] pivot host {host} skipped (out of scope: {reason}) "
                      f"[via {spec.get('via', '?')}]", file=sys.stderr)
                continue
        reached_from = spec.get("reached_from") or spec.get("via", "?")
        print(f"[*] pivot: probing {host} via {reached_from} "
              f"(depth {depth}/{max_depth})", file=sys.stderr)
        sub = targetmod.Target(
            kind=targetmod.HOSTPORT, raw=str(host), host=host,
            port=(ports[0] if ports else None), ports=ports,
        )
        _inherit_governance(sub, target)
        sub.pivot_depth = depth
        # Provenance + relay: this peer was reached FROM the foothold; route its traffic
        # through the relay tunnel (if any) so the modules run as if from the foothold.
        sub.reached_via = reached_from
        sub.proxy = spec.get("via_proxy") or getattr(target, "pivot_proxy", None) or sub.proxy
        # --propagate: force relay proxy onto sub-target for full traffic routing
        if getattr(target, "propagate", False) and spec.get("relay"):
            from sandbox import relay as _relay_mod
            _r = _relay_mod.build_relay(spec.get("relay"),
                                        fallback_proxy=getattr(target, "pivot_proxy", None))
            rp = _r.proxy_url()
            if rp:
                sub.proxy = rp
        if led is not None:
            from sandbox import relay as _relay
            led.record(_relay.classify_resource_kind(targetmod.HOSTPORT,
                                                     port=(ports[0] if ports else None)),
                       f"{host}:{ports[0]}" if ports else str(host),
                       reached_from=reached_from, via=("proxy" if sub.proxy else "direct"),
                       proof="reachable from foothold", proof_kind=ledger_mod.REACHABILITY,
                       scope_status="in-scope", severity="MEDIUM",
                       note=f"subnet/peer reached from {reached_from}")
        # --propagate-script: deploy scanner into the foothold and run from inside
        if getattr(target, "propagate_script", False) and spec.get("relay"):
            relay_spec = spec.get("relay") or {}
            relay_type = relay_spec.get("type", "")
            if relay_type in ("docker", "kubelet", "k8s-api"):
                propagated = _propagate_to_foothold(
                    spec, target,
                    strategy=getattr(args, "propagate_strategy", None))
                if propagated:
                    results.extend(propagated)
                    for nxt in (getattr(sub, "pivot_targets", []) or []):
                        queue.append((nxt, depth + 1))
                    continue
        results.extend(_run_modules(hostport_mods, sub, jobs=jobs, resume=resume))
        # A probed pivot host may itself have published further pivots.
        for nxt in (getattr(sub, "pivot_targets", []) or []):
            queue.append((nxt, depth + 1))
    return results


def _authorize_pivot(guard, value) -> tuple:
    """Authorise a pivot URL/host against the scope guard (host extracted from a URL)."""
    if guard is None:
        return (True, "no scope guard")
    host = value
    if "://" in str(value):
        from urllib.parse import urlparse
        host = urlparse(value).hostname or value
    return guard.authorize(host)


def _derive_subnet(host_ip: str) -> str:
    """Derive a /24 CIDR from a host IP for subnet scanning on the propagated hop."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(host_ip)
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except (ValueError, TypeError):
        return ""


def _build_propagation_args(target, host: str) -> list:
    """Build the CLI args list for a propagated scanner instance.

    Inherits: intensity, scope, prove-access, propagate (with depth-1),
    spray, cve-*, host-subnet (derived from host IP), --yes.
    Does NOT inherit: --url (irrelevant from hop), --targets-file, --resume,
    --oob-listen, --json/--html/--sarif paths, --proxy (hop uses its own net).
    Parallelism is auto-detected on the hop (adaptive, no --jobs forwarded).
    """
    args = ["--yes"]  # always non-interactive

    # Intensity
    intensity = getattr(target, "intensity", None)
    if intensity:
        args += ["--intensity", str(intensity)]

    # Scope (shell-safe: passed via JSON sidecar, not shell string)
    scope_guard = getattr(target, "scope_guard", None)
    if scope_guard and hasattr(scope_guard, "specs"):
        for s in scope_guard.specs[:10]:
            args += ["--scope", str(s)]

    # Prove-access inheritance
    if getattr(target, "prove_access", False):
        args.append("--prove-access")
    else:
        if getattr(target, "prove_access_writes", False):
            args.append("--prove-access-writes")
        if getattr(target, "prove_access_shell", False):
            args.append("--prove-access-shell")

    # Propagation with depth decrement
    if getattr(target, "propagate_script", False):
        current_depth = getattr(target, "propagate_depth", None)
        if current_depth is None:
            current_depth = getattr(__import__("config"), "PROPAGATE_MAX_DEPTH", 2)
        new_depth = current_depth - 1
        if new_depth > 0:
            args += ["--propagate-script", "--propagate-depth", str(new_depth)]

    # Spray
    if getattr(target, "spray", False):
        args.append("--spray")

    # CVE flags
    if getattr(target, "_cve_lookup", False):
        args.append("--cve-lookup")
    if getattr(target, "_cve_test", False):
        args.append("--cve-test")
    cve_max = getattr(target, "_cve_max", None)
    if cve_max and cve_max != 10:
        args += ["--cve-max", str(cve_max)]
    cve_key = getattr(target, "_cve_api_key", None)
    if cve_key:
        args += ["--cve-api-key", str(cve_key)]

    # Host subnet: derive /24 from the foothold's IP for local network scanning
    subnet = _derive_subnet(host)
    if subnet:
        args += ["--host-subnet", subnet]

    # Propagation strategy inheritance (native/zipapp/source)
    propagate_strategy = getattr(target, "_propagate_strategy", None)
    if propagate_strategy:
        args += ["--propagate-strategy", propagate_strategy]

    # Always scan the propagated device itself (localhost services, privilege level,
    # WiFi/BT adapters, OS posture). This feeds device_posture and local modules.
    args.append("--local")

    # Mark the deployed instance as propagated so modules that inspect local
    # network state know the local network belongs to the foothold, not the operator.
    args += ["--propagated-instance"]

    # Output: JSON to stdout for the parent to collect
    args += ["--json", "/dev/stdout"]

    return args


def _propagate_to_foothold(spec: dict, target, *,
                           strategy: Optional[str] = None) -> list:
    """Deploy the scanner onto a proven foothold and merge results back.

    The propagated instance inherits the parent's governance (scope, intensity,
    prove-access, spray, CVE flags) and scans the foothold's /24 subnet. It does
    NOT run --local only — it performs a full network scan from the hop's vantage.
    Parallelism is auto-detected on the hop based on available resources.

    ``strategy`` overrides the payload strategy selection (native/zipapp/source/auto)
    from ``--propagate-strategy``; ``None`` means auto.

    Returns a list of ExploitResult objects from the propagated scan, or an empty list
    if propagation fails (non-fatal — falls back to normal relay probing).
    """
    from sandbox import propagate
    relay_spec = spec.get("relay") or {}
    relay_type = relay_spec.get("type", "")
    host = spec.get("host") or relay_spec.get("host", "")
    port = relay_spec.get("port", 0)
    reached_from = spec.get("reached_from") or spec.get("via", "?")

    # Build proper CLI args (JSON-safe, no shell injection)
    args_list = _build_propagation_args(target, host)

    print(f"[*] propagate-script: deploying scanner to {host}:{port} "
          f"via {relay_type} [from {reached_from}]", file=sys.stderr)
    try:
        archive = propagate.pack_scanner(bundle_cve_cache=True)
    except Exception as exc:
        print(f"[!] propagate-script: packing failed ({exc}); falling back to relay probe.",
              file=sys.stderr)
        return []

    ok = False
    output = ""
    try:
        if relay_type == "docker":
            try:
                relay_port = int(port)
            except (TypeError, ValueError):
                print(f"[!] propagate-script: invalid port {port!r} for docker relay; skipping.",
                      file=sys.stderr)
                return []
            ok, output = propagate.deploy_via_docker(host, relay_port, archive,
                                                     args_list=args_list)
        elif relay_type == "kubelet":
            try:
                relay_port = int(port)
            except (TypeError, ValueError):
                print(f"[!] propagate-script: invalid port {port!r} for kubelet relay; skipping.",
                      file=sys.stderr)
                return []
            ns = relay_spec.get("namespace", "default")
            pod = relay_spec.get("pod", "")
            container = relay_spec.get("container", "")
            if pod:
                ok, output = propagate.deploy_via_kubelet(
                    host, relay_port, ns, pod, container, archive, args_list=args_list)
        elif relay_type == "k8s-api":
            api_url = relay_spec.get("api_url", f"https://{host}:{port}")
            token = relay_spec.get("token", "")
            ns = relay_spec.get("namespace", "default")
            pod = relay_spec.get("pod", "")
            container = relay_spec.get("container", "")
            if pod:
                ok, output = propagate.deploy_via_k8s_api(
                    api_url, token, ns, pod, container, archive, args_list=args_list)
        elif relay_type == "ssh":
            # SSH-based propagation via discovered credentials — use the universal
            # entrypoint so --propagate-strategy (native/zipapp/source) is honoured.
            foothold = {
                "type": "ssh",
                "host": host,
                "port": relay_spec.get("port", 22),
                "user": relay_spec.get("user", "root"),
                "key_path": relay_spec.get("key_path", ""),
                "password": relay_spec.get("password", ""),
            }
            ok, output = propagate.propagate_universal(
                foothold, args_list, strategy=strategy or "auto")
        elif relay_type == "shell-exec":
            # Command-injection/Shellshock-based propagation
            from sandbox.propagate_transport import ShellExecTransport
            shell_transport = ShellExecTransport()
            foothold = {
                "type": "shell-exec",
                "method": relay_spec.get("method", "cmd-injection"),
                "url": relay_spec.get("url", ""),
                "technique": relay_spec.get("technique", "pipe"),
                "vector": relay_spec.get("vector", "param"),
                "inject_header": relay_spec.get("inject_header", ""),
            }
            if foothold["url"]:
                ok, output = shell_transport.deliver_and_exec(
                    foothold, archive, args_list)
        elif relay_type == "adb":
            # Android Debug Bridge — propagate to rooted/debug-enabled Android device
            from sandbox.propagate_transport import AdbTransport
            adb_transport = AdbTransport()
            foothold = {
                "type": "adb",
                "host": host,
                "port": relay_spec.get("port", 5555),
                "serial": relay_spec.get("serial", ""),
            }
            ok, output = adb_transport.deliver_and_exec(
                foothold, archive, args_list,
                timeout=_PROPAGATE_TIMEOUT if "_PROPAGATE_TIMEOUT" in dir() else 120)
        elif relay_type in ("aws-ssm", "gcp-oslogin", "azure-runcommand"):
            # Cloud API-based propagation
            from sandbox.propagate_transport import CloudStorageTransport
            cloud_transport = CloudStorageTransport()
            ok, output = cloud_transport.deliver_and_exec(
                relay_spec, archive, args_list)
    except Exception as exc:
        print(f"[!] propagate-script: deployment to {host}:{port} failed ({exc}); "
              f"falling back to relay probe.", file=sys.stderr)
        return []

    if not ok:
        print(f"[!] propagate-script: execution on {host}:{port} returned failure; "
              f"falling back to relay probe.", file=sys.stderr)
        return []

    parsed = propagate.parse_propagated_results(output)
    if parsed is None:
        print(f"[*] propagate-script: no parseable results from {host}:{port}.",
              file=sys.stderr)
        return []

    merged = propagate.merge_propagated_findings([], parsed, reached_from=reached_from)
    print(f"[*] propagate-script: merged {len(merged)} result(s) from {host}:{port}.",
          file=sys.stderr)
    return merged



# Latest known vulnerable version used when version is unknown — ensures CVE
# queries return results even without a banner.  Updated periodically.
_SERVICE_TYPE_VERSIONS = {
    "apache":  {"product": "apache httpd", "version": "2.4.58", "vendor": "apache"},
    "nginx":   {"product": "nginx",        "version": "1.24.0", "vendor": "nginx"},
    "openssh": {"product": "openssh",      "version": "9.3",    "vendor": "openbsd"},
    "ssh":     {"product": "openssh",      "version": "9.3",    "vendor": "openbsd"},
    "smtp":    {"product": "postfix",      "version": "3.8.0",  "vendor": "postfix"},
    "exim":    {"product": "exim",         "version": "4.96",   "vendor": "exim"},
    "php":     {"product": "php",          "version": "8.1.0",  "vendor": "php"},
    "wordpress": {"product": "wordpress",  "version": "6.4.0",  "vendor": "wordpress"},
    "drupal":  {"product": "drupal",       "version": "10.1.0", "vendor": "drupal"},
    "joomla":  {"product": "joomla",       "version": "4.4.0",  "vendor": "joomla"},
    "tomcat":  {"product": "apache tomcat","version": "10.1.0", "vendor": "apache"},
    "jenkins": {"product": "jenkins",      "version": "2.414.0","vendor": "jenkins"},
    "redis":   {"product": "redis",        "version": "7.0.0",  "vendor": "redis"},
    "mysql":   {"product": "mysql",        "version": "8.0.35", "vendor": "oracle"},
    "postgres": {"product": "postgresql",  "version": "16.0",   "vendor": "postgresql"},
    "mongodb": {"product": "mongodb",      "version": "7.0.0",  "vendor": "mongodb"},
    "grafana": {"product": "grafana",      "version": "10.2.0", "vendor": "grafana"},
    "openwrt":   {"product": "openwrt",         "version": "23.05.0", "vendor": "openwrt"},
    "dd-wrt":    {"product": "dd-wrt",           "version": "3.0-r49170", "vendor": "dd-wrt"},
    "mikrotik":  {"product": "routeros",         "version": "7.11.0", "vendor": "mikrotik"},
    "ubiquiti":  {"product": "airmax-firmware",  "version": "8.7.11", "vendor": "ubiquiti"},
    "android":   {"product": "android",          "version": "13",     "vendor": "google"},
    "ios":       {"product": "ios",              "version": "17.0",   "vendor": "apple"},
    "routeros":  {"product": "routeros",         "version": "7.11.0", "vendor": "mikrotik"},
    "fortios":   {"product": "fortios",          "version": "7.4.0",  "vendor": "fortinet"},
    "pfsense":   {"product": "pfsense",          "version": "2.7.0",  "vendor": "netgate"},
    "junos":     {"product": "junos",            "version": "23.1R1", "vendor": "juniper"},
}


def _infer_services_from_findings(results: list, target) -> list:
    """Synthesise (product, version) pairs from detected service *types* when version
    extraction found nothing.  Scans finding titles/evidence for service keywords and
    maps them to the latest known vulnerable version so CVE queries still run.

    Returns at most 5 candidate service dicts — flagged with ``inferred=True``.
    """
    import re
    keywords = set()
    for res in results:
        for fnd in (getattr(res, "findings", []) or []):
            text = (f"{fnd.title} {getattr(fnd,'evidence','')} "
                    f"{getattr(fnd,'detail','')}").lower()
            for kw in _SERVICE_TYPE_VERSIONS:
                if kw in text:
                    keywords.add(kw)

    # Also look at target URL/host/port for obvious hints
    raw = str(getattr(target, "raw", "")).lower()
    url = str(getattr(target, "url", "")).lower()
    port = getattr(target, "port", None)
    ports = list(getattr(target, "ports", []) or [])
    combined = raw + " " + url
    # Port hints: 22→ssh, 25/587→smtp, 3306→mysql, 5432→postgres, 6379→redis
    _port_kw = {22: "ssh", 25: "smtp", 587: "smtp", 3306: "mysql",
                5432: "postgres", 6379: "redis", 27017: "mongodb"}
    for p in ([port] if port else []) + ports:
        if p in _port_kw:
            keywords.add(_port_kw[p])

    # HTTP service: if we probed a URL target, always include the web server type
    if getattr(target, "kind", None) in ("url",) or "http" in combined:
        # Try to detect which web server from Server header findings
        server_hits = []
        for res in results:
            for fnd in (getattr(res, "findings", []) or []):
                ev = (getattr(fnd, "evidence", "") or "").lower()
                if "server:" in ev:
                    server_hits.append(ev)
        detected_server = False
        for hit in server_hits:
            for kw in ("apache", "nginx", "tomcat", "iis"):
                if kw in hit:
                    keywords.add(kw)
                    detected_server = True
        if not detected_server:
            keywords.add("nginx")  # most common; catches broad web CVEs

    out = []
    seen = set()
    for kw in sorted(keywords):
        if kw in _SERVICE_TYPE_VERSIONS and kw not in seen:
            seen.add(kw)
            svc = dict(_SERVICE_TYPE_VERSIONS[kw])
            svc["inferred"] = "true"
            out.append(svc)
    return out[:5]


def _run(target, selected, args, jobs: int = 1, resume=None) -> int:
    results = _run_modules(selected, target, jobs=jobs, resume=resume)

    # Network-range fan-out: once live hosts are discovered, probe each with the
    # existing per-service (hostport) modules.
    if getattr(target, "kind", None) == targetmod.NETRANGE:
        results.extend(_fanout_hostport(target, selected, args, jobs=jobs, resume=resume))

    # URL companion: after HTTP/HTTPS modules run, also probe the host on standard
    # service ports (SSH, databases, Redis, admin panels, etc.) via the pivot system.
    # URL modules handle application logic; hostport modules cover the rest of the
    # network surface on the same IP. Dedup is handled by _fanout_pivots (seen_hosts).
    if getattr(target, "kind", None) == targetmod.URL:
        _push_url_hostport_companion(target)

    # Lateral-movement iteration: any module may publish ``pivot_targets`` (e.g. cloud-pivot
    # maps the subnet peers of an SSM-reachable instance). Re-run the host:port modules
    # against each pivot host, bounded by depth + scope, so the toolkit iterates from a
    # foothold toward the resources sharing its subnet.
    results.extend(_fanout_pivots(target, args, jobs=jobs, resume=resume))

    # Proof-of-access ledger: render the consolidated identification path for every resource
    # reached/proven during the run (foothold -> relay -> peer, each with its proof) so the
    # report carries an auditable lateral-movement trail. Appended before correlation so the
    # attack-chain pass can reference it.
    led = getattr(target, "proof_ledger", None)
    if led is not None and getattr(led, "hops", None):
        try:
            results.append(led.to_result())
        except Exception as exc:
            print(f"[!] proof-ledger rendering skipped ({exc!r}).", file=sys.stderr)

    # Offline CVE enrichment: correlate every discovered service version with the
    # bundled offline feed, attach CVE refs to the originating findings, and append a
    # consolidated summary. Pure post-processing — no extra requests against the target.
    if not args.no_cve_enrich:
        try:
            from exploits import cve_enrich
            enrich = cve_enrich.enrich_results(results)
            if enrich.findings:
                results.append(enrich)
        except Exception as exc:
            print(f"[!] CVE enrichment skipped ({exc!r}).", file=sys.stderr)

    # Live CVE resolution + automated exploit testing (--cve-lookup / --cve-test).
    # Queries NVD 2.0, OSV.dev, EPSS for discovered service versions, then optionally
    # generates and runs verification scripts (Nuclei auto-exec, Python PoC with confirm).
    if getattr(args, "cve_lookup", False):
        try:
            from exploits import cve_resolver, exploit_planner, exploit_generator
            from exploits.base import ExploitResult as _ExploitResult, Finding as _Finding

            # Set API key if provided
            if getattr(args, "cve_api_key", None):
                os.environ["NVD_API_KEY"] = args.cve_api_key

            def _cve_status(msg):
                print(f"[*] CVE lookup: {msg}", file=sys.stderr)

            # Extract fingerprinted services from results.
            # Also harvest SSH/SMTP/HTTP banners stored on the target itself (set by
            # ssh-probe, http-probe, nmap-probe) so versions are available even when the
            # relevant module produced no findings at all.
            services = cve_resolver.extract_services_from_results(results)
            _extra_banners = list(getattr(target, "_discovered_banners", []) or [])
            for _b in _extra_banners:
                _extra = cve_resolver.extract_services_from_results([type(
                    "R", (), {"findings": [type("F", (), {
                        "title": _b, "evidence": _b, "detail": ""})()]})()]) if _b else []
                for _s in _extra:
                    if _s not in services:
                        services.append(_s)

            # Always augment with service-type heuristics: scan findings for service
            # keywords and port hints, then merge any inferred (product, version) pairs
            # not already present.  When banners are suppressed or version extraction
            # fails entirely the inferred set becomes the primary source; when real
            # services were extracted it adds any types that were detected but not
            # versioned (e.g. WordPress found via path-probe but no banner version).
            _inferred = _infer_services_from_findings(results, target)
            if _inferred:
                _known_products = {s.get("product", "").lower() for s in services}
                _added = []
                for _svc in _inferred:
                    if _svc.get("product", "").lower() not in _known_products:
                        services.append(_svc)
                        _known_products.add(_svc.get("product", "").lower())
                        _added.append(_svc)
                if not services and _inferred:
                    # Fallback: inferred set is the only source
                    print(f"[*] CVE lookup: no versioned services extracted; using "
                          f"service-type heuristics to infer {len(_inferred)} candidate(s).",
                          file=sys.stderr)
                elif _added:
                    print(f"[*] CVE lookup: augmented with {len(_added)} inferred service-type "
                          f"candidate(s) (suspected but unversioned).", file=sys.stderr)

            if services:
                print(f"[*] CVE lookup: resolving vulnerabilities for "
                      f"{len(services)} identified service(s): "
                      f"{', '.join(s['product'] + ' ' + s['version'] for s in services[:5])} ...",
                      file=sys.stderr)
                cve_records = cve_resolver.resolve_all(services, on_status=_cve_status)
                if cve_records:
                    print(f"[*] CVE lookup: found {len(cve_records)} HIGH/CRITICAL "
                          f"CVE(s) in the last 5 years.", file=sys.stderr)

                    if getattr(args, "cve_test", False):
                        # Determine target host/port for testing — prefer URL host for
                        # web CVEs, fall back to primary target host.
                        t_host = getattr(target, "host", "") or ""
                        if not t_host and getattr(target, "url", None):
                            from urllib.parse import urlparse as _up
                            t_host = _up(target.url).hostname or ""
                        t_port = (getattr(target, "port", None) or
                                  (getattr(target, "ports", None) or [80])[0]
                                  if hasattr(target, "ports") else 80)

                        # Check if LLM is available for script generation
                        has_llm = False
                        llm_model = ""
                        if args.llm:
                            try:
                                from llm import advisor
                                llm_model = advisor.available(
                                    args.model, allow_remote=args.allow_remote_llm) or ""
                                has_llm = bool(llm_model)
                            except Exception:
                                pass

                        plans = exploit_planner.prioritize(
                            cve_records, t_host, t_port,
                            max_plans=getattr(args, "cve_max", 10),
                            has_llm=has_llm)

                        if plans:
                            print(exploit_planner.summarize_plans(plans), file=sys.stderr)
                            autopwn = exploit_generator.execute_plans(
                                plans,
                                auto_confirm=getattr(args, "assume_yes", False),
                                llm_model=llm_model,
                                allow_remote_llm=getattr(args, "allow_remote_llm", False),
                                interactive=sys.stdin.isatty(),
                            )
                            # Always append autopwn result — even when no exploit confirmed,
                            # showing "MITIGATED" is more informative than silence.
                            if not autopwn.findings:
                                autopwn.findings.append(_Finding(
                                    title=f"CVE exploit tests executed: {len(plans)} plan(s) — "
                                          f"none confirmed on target",
                                    severity="INFO",
                                    location=t_host or str(target.raw),
                                    detail="Automated CVE verification scripts ran but found no "
                                           "confirming evidence on the live target. The target may "
                                           "be patched or the CVE requires specific conditions not "
                                           "present. Manual verification recommended.",
                                    evidence=f"plans={len(plans)} cves={len(cve_records)}",
                                ))
                            results.append(autopwn)
                        else:
                            # CVEs found but no executable test plan available.
                            results.append(_ExploitResult(
                                name="cve-autopwn",
                                description="CVE verification test execution",
                                exploited=False,
                                findings=[_Finding(
                                    title=f"{len(cve_records)} CVE(s) found — no automated "
                                          f"test plan available",
                                    severity="INFO",
                                    location=t_host or str(target.raw),
                                    detail="CVEs were identified for the discovered service "
                                           "versions but no automated verification strategy is "
                                           "available for them (no Nuclei template, no Python PoC, "
                                           "no LLM model). Manual exploitation research required.",
                                    evidence=", ".join(r.cve_id for r in cve_records[:10]),
                                )],
                            ))
                else:
                    print("[*] CVE lookup: no HIGH/CRITICAL CVEs matched the "
                          "discovered versions.", file=sys.stderr)
            else:
                print("[*] CVE lookup: no versioned services identified to query.",
                      file=sys.stderr)
        except Exception as exc:
            print(f"[!] CVE autopwn skipped ({exc!r}).", file=sys.stderr)

    # Attack-chain correlation: stitch the findings above into multi-step kill-chains.
    # Pure analysis (no requests); runs after enrichment so CVE links are visible.
    try:
        from exploits import attack_chain
        chain = attack_chain.correlate(results)
        if chain.exploited:
            results.append(chain)
    except Exception as exc:
        print(f"[!] attack-chain correlation skipped ({exc!r}).", file=sys.stderr)

    llm_text = None
    if args.llm:
        try:
            from llm import advisor
            model = advisor.available(args.model, allow_remote=args.allow_remote_llm)
            if model:
                print(f"[*] querying local model '{model}' for attacker briefing ...", file=sys.stderr)
                llm_text = advisor.advise(reporter.build_llm_payload(results), model,
                                          allow_remote=args.allow_remote_llm)
                if not llm_text:
                    print("[!] local model returned no text; continuing without briefing.", file=sys.stderr)
            else:
                print("[!] no local Ollama model reachable; skipping LLM briefing.", file=sys.stderr)
        except Exception as exc:
            print(f"[!] LLM step failed ({exc!r}); continuing.", file=sys.stderr)

    color = sys.stdout.isatty() and not args.no_color
    label = target.describe()
    exit_code = reporter.render_console(results, label, llm_text, color, args.fail_on)

    # Baseline comparison (optional): classify findings as new/fixed/unchanged and,
    # with --fail-on-new-only, base the exit code purely on NEW findings.
    if args.baseline:
        baseline = reporter.load_baseline(args.baseline)
        if baseline is None:
            print(f"[!] could not read baseline '{args.baseline}'; skipping diff.", file=sys.stderr)
        else:
            diff = reporter.diff_against_baseline(results, baseline)
            reporter.render_diff(diff, color)
            if args.fail_on_new_only:
                exit_code = 1 if reporter.gate_new_only(diff, args.fail_on) else 0

    try:
        reporter.write_json(results, label, args.json, llm_text)
        print(f"[*] JSON artifact: {args.json}", file=sys.stderr)
        if args.markdown:
            reporter.write_markdown_with_chains(results, label, args.markdown, llm_text)
            print(f"[*] Markdown report: {args.markdown}", file=sys.stderr)
        if args.sarif:
            reporter.write_sarif(results, label, args.sarif)
            print(f"[*] SARIF artifact: {args.sarif}", file=sys.stderr)
        if args.html:
            reporter.write_html(results, label, args.html, llm_text)
            print(f"[*] HTML report: {args.html}", file=sys.stderr)
    except Exception as exc:
        print(f"[!] failed to write artifact: {exc!r}", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
