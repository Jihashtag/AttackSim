"""Report rendering: console (ANSI), JSON artifact, and optional Markdown."""
from __future__ import annotations

import json
import os
import sys
import time
from typing import List, Optional

from exploits.base import ExploitResult, SEVERITY_ORDER, format_evidence

_COLORS = {
    "CRITICAL": "\033[1;37;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;34m", "INFO": "\033[0;37m", "WIN": "\033[1;31m",
    "OK": "\033[1;32m", "RESET": "\033[0m", "DIM": "\033[2m", "BOLD": "\033[1m",
}


def _c(key: str, text: str, enable: bool) -> str:
    if not enable:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['RESET']}"


def _meets(severity: str, threshold: str) -> bool:
    return (SEVERITY_ORDER.get((severity or "").upper(), 99)
            <= SEVERITY_ORDER.get((threshold or "").upper(), 99))


def gate(results: List[ExploitResult], fail_on: Optional[str]) -> bool:
    """Return True if the run should be considered a failure (exit 1).

    Without ``fail_on``, any exploited module fails the run. With ``fail_on``,
    only an exploited module whose worst finding meets the threshold counts.
    """
    won = [r for r in results if r.exploited]
    if not fail_on:
        return bool(won)
    return any(_meets(r.worst_severity, fail_on) for r in won)


def render_console(results: List[ExploitResult], target: str, llm_text: Optional[str],
                   color: bool, fail_on: Optional[str] = None) -> int:
    won = [r for r in results if r.exploited]
    line = "=" * 74
    print(_c("BOLD", line, color))
    print(_c("BOLD", "  UNAUTHENTICATED ATTACKER SIMULATION — security_test", color))
    print(f"  target: {target}")
    print(f"  modules: {len(results)}    attacker wins: {len(won)}")
    print(_c("BOLD", line, color))

    for r in results:
        if r.error and not r.findings:
            status = _c("INFO", "[ SKIP ]", color)
        elif r.exploited:
            status = _c("WIN", "[ EXPLOITED ]", color)
        else:
            status = _c("OK", "[ MITIGATED ]", color)
        print(f"\n{status} {_c('BOLD', r.name, color)} — {r.description}")
        if not r.tool_available and r.error:
            print(f"   {_c('DIM', 'note: ' + r.error, color)}")
        for f in sorted(r.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))[:12]:
            tag = _c(f.severity, f"{f.severity:<8}", color)
            print(f"   {tag} {f.location}")
            print(f"            {f.title}")
            if f.evidence:
                print(f"            {_c('DIM', 'evidence: ' + format_evidence(f.evidence), color)}")
            refs = list(getattr(f, "references", []) or [])
            if getattr(f, "cwe", ""):
                refs = [f.cwe] + refs
            if refs:
                print(f"            {_c('DIM', 'refs: ' + ', '.join(refs), color)}")
        extra = len(r.findings) - 12
        if extra > 0:
            print(f"   {_c('DIM', f'... and {extra} more finding(s)', color)}")

    print("\n" + _c("BOLD", line, color))
    if won:
        print(_c("WIN", "  RESULT: EXPLOITATION SUCCESSFUL — issues an attacker could use", color))
        print(_c("BOLD", line, color))
        for r in won:
            print(f"\n  {_c('WIN', '►', color)} {_c('BOLD', r.name, color)} ({r.worst_severity})")
            print(f"    what the attacker gains: {r.attacker_value}")
            print(f"    fix: {r.mitigation}")
    else:
        print(_c("OK", "  RESULT: ALL EXPLOITS FAILED — the assessed risks are MITIGATED", color))
        print(_c("BOLD", line, color))

    if llm_text:
        print("\n" + _c("BOLD", "-" * 74, color))
        print(_c("BOLD", "  LOCAL-LLM ATTACKER BRIEFING", color))
        print(_c("BOLD", "-" * 74, color))
        print(llm_text)

    print()
    return 1 if gate(results, fail_on) else 0


def write_json(results: List[ExploitResult], target: str, path: str, llm_text: Optional[str]) -> None:
    payload = {
        "tool": "security_test",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "target": target,
        "exploited": any(r.exploited for r in results),
        "modules": [r.to_dict() for r in results],
        "llm_briefing": llm_text,
        "attack_chains": _extract_chains(results),
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def build_llm_payload(results: List[ExploitResult]) -> dict:
    return {
        "modules": [
            {
                "name": r.name,
                "exploited": r.exploited,
                "attacker_value": r.attacker_value,
                "findings": [
                    {"title": f.title, "severity": f.severity, "location": f.location}
                    for f in r.findings
                ],
            }
            for r in results
        ]
    }


def write_markdown(results: List[ExploitResult], target: str, path: str, llm_text: Optional[str]) -> None:
    won = [r for r in results if r.exploited]
    lines = [
        "# Unauthenticated Attacker Simulation — Report",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Modules run:** {len(results)}",
        f"- **Attacker wins:** {len(won)}",
        "",
        "## Result",
        "",
        ("**EXPLOITATION SUCCESSFUL** — exploitable issues were found (see below)."
         if won else
         "**ALL EXPLOITS FAILED** — the assessed risks are mitigated."),
        "",
        "## Modules",
        "",
        "| Module | Outcome | Worst | Findings |",
        "|---|---|---|---|",
    ]
    for r in results:
        outcome = "EXPLOITED" if r.exploited else ("SKIP" if (r.error and not r.findings) else "MITIGATED")
        lines.append(f"| `{r.name}` | {outcome} | {r.worst_severity} | {len(r.findings)} |")
    for r in won:
        lines += [
            "", f"### `{r.name}` — {r.worst_severity}", "",
            f"**Attacker gains:** {r.attacker_value}", "",
            f"**Fix:** {r.mitigation}", "",
            "| Severity | Location | Finding | References |", "|---|---|---|---|",
        ]
        for f in r.findings:
            refs = list(getattr(f, "references", []) or [])
            if getattr(f, "cwe", ""):
                refs = [f.cwe] + refs
            lines.append(f"| {f.severity} | `{f.location}` | {f.title} | {', '.join(refs)} |")
    if llm_text:
        lines += ["", "## Local-LLM Attacker Briefing", "", llm_text]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ===========================================================================
# SARIF 2.1.0 output (for code-scanning / SARIF viewers)
# ===========================================================================
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}


def _finding_id(module_name: str, f) -> str:
    """Stable identifier for a finding (module + category/cwe), used by SARIF + baseline."""
    base = getattr(f, "category", "") or getattr(f, "cwe", "") or "finding"
    return f"{module_name}/{base}"


def _rules_from_results(results: List[ExploitResult]) -> dict:
    rules = {}
    for r in results:
        for f in r.findings:
            rid = _finding_id(r.name, f)
            if rid not in rules:
                # Only build a CWE MITRE helpUri when the finding actually carries a
                # numeric CWE; otherwise ".../0.html" is a dead link (BUG-26). Fall back
                # to the CWE index page.
                cwe_num = (getattr(f, "cwe", "") or "").replace("CWE-", "").strip()
                if cwe_num.isdigit():
                    help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                else:
                    help_uri = "https://cwe.mitre.org/"
                rules[rid] = {
                    "id": rid,
                    "name": rid.replace("/", "_"),
                    "shortDescription": {"text": (getattr(f, "category", "") or r.name)},
                    "helpUri": help_uri,
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f.severity, "note")},
                }
    return rules


def write_sarif(results: List[ExploitResult], target: str, path: str) -> None:
    tool_uri = "https://example.invalid/security_test"
    try:
        import config as _config
        tool_uri = getattr(_config, "SARIF_TOOL_URI", tool_uri)
    except Exception:
        pass
    rules = _rules_from_results(results)
    sarif_results = []
    for r in results:
        for f in r.findings:
            rid = _finding_id(r.name, f)
            detail = f.detail
            if f.evidence:
                detail += f"\nEvidence: {format_evidence(f.evidence)}"
            sarif_results.append({
                "ruleId": rid,
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f"{f.title} — {detail}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location or target},
                    },
                }],
                "properties": {
                    "security-severity": _security_severity(f.severity),
                    "module": r.name,
                    "cwe": getattr(f, "cwe", ""),
                    "tags": list(getattr(f, "tags", []) or []),
                },
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "security_test",
                "informationUri": tool_uri,
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)


def _security_severity(severity: str) -> str:
    """Map to the GitHub code-scanning numeric security-severity scale."""
    return {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0",
            "INFO": "1.0"}.get(severity, "1.0")


# ===========================================================================
# Standalone HTML report
# ===========================================================================
def _html_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def write_html(results: List[ExploitResult], target: str, path: str,
               llm_text: Optional[str] = None) -> None:
    won = [r for r in results if r.exploited]
    sev_color = {"CRITICAL": "#b30000", "HIGH": "#e34a00", "MEDIUM": "#c79100",
                 "LOW": "#2a6fb3", "INFO": "#666"}
    rows = []
    for r in results:
        outcome = ("EXPLOITED" if r.exploited
                   else ("SKIP" if (r.error and not r.findings) else "MITIGATED"))
        rows.append(
            f"<tr><td><code>{_html_escape(r.name)}</code></td>"
            f"<td class='o-{outcome.lower()}'>{outcome}</td>"
            f"<td style='color:{sev_color.get(r.worst_severity, '#666')}'>"
            f"{r.worst_severity}</td><td>{len(r.findings)}</td></tr>")
    detail_blocks = []
    for r in results:
        if not r.findings:
            continue
        items = []
        for f in sorted(r.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            refs = list(getattr(f, "references", []) or [])
            if getattr(f, "cwe", ""):
                refs = [f.cwe] + refs
            items.append(
                f"<li><span class='sev' style='background:{sev_color.get(f.severity,'#666')}'>"
                f"{f.severity}</span> <strong>{_html_escape(f.title)}</strong>"
                f"<div class='loc'>{_html_escape(f.location)}</div>"
                f"<div class='det'>{_html_escape(f.detail)}</div>"
                + (f"<div class='ev'>evidence: {_html_escape(format_evidence(f.evidence))}</div>"
                   if f.evidence else "")
                + (f"<div class='ref'>refs: {_html_escape(', '.join(refs))}</div>"
                   if refs else "")
                + "</li>")
        badge = "win" if r.exploited else "ok"
        detail_blocks.append(
            f"<section class='mod {badge}'><h3>{_html_escape(r.name)} "
            f"<span class='desc'>{_html_escape(r.description)}</span></h3>"
            + (f"<p class='av'><strong>Attacker gains:</strong> "
               f"{_html_escape(r.attacker_value)}</p>" if r.exploited and r.attacker_value else "")
            + (f"<p class='fix'><strong>Fix:</strong> {_html_escape(r.mitigation)}</p>"
               if r.exploited and r.mitigation else "")
            + "<ul>" + "".join(items) + "</ul></section>")
    result_banner = ("EXPLOITATION SUCCESSFUL" if won else
                     "ALL EXPLOITS FAILED — risks mitigated")
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>security_test report — {_html_escape(target)}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1a1a1a}}
 header{{background:#111;color:#fff;padding:20px 28px}}
 header h1{{margin:0 0 6px;font-size:18px}}
 .meta{{color:#bbb;font-size:13px}}
 .banner{{padding:12px 28px;font-weight:700;color:#fff;background:{'#b30000' if won else '#1f8a4c'}}}
 main{{padding:20px 28px;max-width:1000px;margin:0 auto}}
 table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px #0002}}
 th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid #eee}}
 th{{background:#fafafa}}
 .o-exploited{{color:#b30000;font-weight:700}} .o-mitigated{{color:#1f8a4c}}
 .o-skip{{color:#888}}
 section.mod{{background:#fff;margin:16px 0;padding:14px 18px;border-radius:6px;
   box-shadow:0 1px 3px #0002;border-left:5px solid #ccc}}
 section.win{{border-left-color:#b30000}} section.ok{{border-left-color:#1f8a4c}}
 section.mod h3{{margin:0 0 8px}} .desc{{font-weight:400;color:#777;font-size:13px}}
 section.mod ul{{list-style:none;padding:0;margin:8px 0 0}}
 section.mod li{{padding:8px 0;border-top:1px solid #f0f0f0}}
 .sev{{color:#fff;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:700}}
 .loc{{font-family:monospace;color:#444;font-size:12px}}
 .det{{color:#333;margin-top:3px}} .ev,.ref{{color:#777;font-size:12px;font-family:monospace}}
 .av{{color:#7a1010}} .fix{{color:#0a5a2a}}
</style></head><body>
<header><h1>Unauthenticated Attacker Simulation — security_test</h1>
<div class="meta">target: {_html_escape(target)} &nbsp;·&nbsp; modules: {len(results)}
 &nbsp;·&nbsp; attacker wins: {len(won)} &nbsp;·&nbsp;
 {_html_escape(time.strftime('%Y-%m-%d %H:%M:%S'))}</div></header>
<div class="banner">RESULT: {result_banner}</div>
<main>
<table><thead><tr><th>Module</th><th>Outcome</th><th>Worst</th><th>Findings</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{''.join(detail_blocks)}
{('<section class=mod><h3>Local-LLM Attacker Briefing</h3><pre>'
  + _html_escape(llm_text) + '</pre></section>') if llm_text else ''}
</main></body></html>"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ===========================================================================
# Baseline diff (new / fixed / unchanged classification)
# ===========================================================================
def _fingerprint_finding(module_name: str, f: dict) -> str:
    """A stable key for a finding across runs: module + id + location + title."""
    rid = f.get("category") or f.get("cwe") or "finding"
    return f"{module_name}|{rid}|{f.get('location', '')}|{f.get('title', '')}"


def _collect_fingerprints(modules: List[dict]) -> dict:
    out = {}
    for m in modules:
        name = m.get("name", "?")
        for f in m.get("findings", []):
            out[_fingerprint_finding(name, f)] = {
                "module": name, "severity": f.get("severity", "INFO"),
                "title": f.get("title", ""), "location": f.get("location", "")}
    return out


def load_baseline(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def diff_against_baseline(results: List[ExploitResult], baseline: dict) -> dict:
    """Classify current findings vs a previous JSON report into new/fixed/unchanged."""
    current = _collect_fingerprints([r.to_dict() for r in results])
    previous = _collect_fingerprints((baseline or {}).get("modules", []))
    new_keys = [k for k in current if k not in previous]
    fixed_keys = [k for k in previous if k not in current]
    unchanged_keys = [k for k in current if k in previous]
    return {
        "new": [current[k] for k in new_keys],
        "fixed": [previous[k] for k in fixed_keys],
        "unchanged": [current[k] for k in unchanged_keys],
    }


def render_diff(diff: dict, color: bool = False) -> None:
    line = "-" * 74
    print(_c("BOLD", line, color))
    print(_c("BOLD", "  BASELINE COMPARISON", color))
    print(_c("BOLD", line, color))
    print(f"  new: {len(diff['new'])}    fixed: {len(diff['fixed'])}    "
          f"unchanged: {len(diff['unchanged'])}")
    for item in sorted(diff["new"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
        print("  " + _c("WIN", "＋ NEW", color)
              + f"  {item['severity']:<8} [{item['module']}] {item['title']} @ {item['location']}")
    for item in diff["fixed"]:
        print("  " + _c("OK", "－ FIXED", color)
              + f" {item['severity']:<8} [{item['module']}] {item['title']} @ {item['location']}")


def gate_new_only(diff: dict, fail_on: Optional[str]) -> bool:
    """Return True (fail) only if there are NEW findings (optionally above a threshold)."""
    new = diff.get("new", [])
    if fail_on:
        return any(_meets(item["severity"], fail_on) for item in new)
    return bool(new)


# ===========================================================================
# Lateral-movement chain extraction & visualization
# ===========================================================================

def _extract_chains(results: List[ExploitResult]) -> List[dict]:
    """Extract attack chain data from proof-ledger results for JSON report."""
    chains: List[dict] = []
    for r in results:
        if r.name != "proof-ledger":
            continue
        for f in (r.findings or []):
            if "lateral-movement path" in (f.title or "").lower():
                chains.append({
                    "path_description": f.title,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "location": f.location,
                })
    return chains


def _render_mermaid_chain(results: List[ExploitResult]) -> str:
    """Attempt to get Mermaid diagram from proof-ledger if available."""
    # Look for a proof_ledger object attached to results metadata
    for r in results:
        if r.name == "proof-ledger" and hasattr(r, "_ledger"):
            return r._ledger.mermaid()
    # Fallback: reconstruct from findings
    nodes = set()
    edges = []
    for r in results:
        if r.name != "proof-ledger":
            continue
        for f in (r.findings or []):
            if ("reached from" in (f.title or "").lower()
                    and isinstance(f.evidence, str) and f.evidence):
                parts = f.evidence.split()
                for part in parts:
                    if "reached_from=" in part:
                        src = part.split("=", 1)[1]
                        nodes.add(src)
                        nodes.add(f.location)
                        proof_kind = ""
                        for p in parts:
                            if "proof=" in p:
                                proof_kind = p.split("=", 1)[1]
                                break
                        edges.append((src, f.location, proof_kind))
    if not edges:
        return ""
    lines = ["graph LR"]
    for node in nodes:
        safe = node.replace(":", "_").replace("/", "_").replace(".", "_")
        lines.append(f'    {safe}["{node}"]')
    for src, dst, label in edges:
        s = src.replace(":", "_").replace("/", "_").replace(".", "_")
        d = dst.replace(":", "_").replace("/", "_").replace(".", "_")
        lines.append(f"    {s} -->|{label}| {d}")
    return "\n".join(lines)


def write_markdown_with_chains(results: List[ExploitResult], target: str, path: str,
                               llm_text: Optional[str]) -> None:
    """Extended Markdown report with lateral-movement chain visualization."""
    # First write the standard markdown
    write_markdown(results, target, path, llm_text)

    # Append chain section
    chains = _extract_chains(results)
    mermaid = _render_mermaid_chain(results)
    if not chains and not mermaid:
        return

    lines = [
        "", "## Lateral Movement Paths", "",
    ]
    if mermaid:
        lines += ["```mermaid", mermaid, "```", ""]

    if chains:
        lines += [
            "| Path | Severity | Evidence |", "|---|---|---|",
        ]
        for chain in chains:
            lines.append(
                f"| {chain['path_description']} | {chain['severity']} | "
                f"`{format_evidence(chain.get('evidence', ''))[:100]}` |")

    # Check for "secure" (probed but not reachable) resources
    secure_resources = []
    for r in results:
        if r.name == "proof-ledger":
            for f in (r.findings or []):
                if "probed" in (f.title or "").lower():
                    secure_resources.append(f)
    if secure_resources:
        lines += [
            "", "### Segmentation Effective (True Negatives)", "",
            "These resources were probed but **not reachable** from the proven foothold chain, "
            "confirming that network segmentation is effective:",
            "",
        ]
        for f in secure_resources:
            lines.append(f"- **{f.location}**: {f.title}")

    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

