"""Proof-of-access ledger — an auditable identification path for every reached resource.

Lateral movement is only trustworthy if every hop can be *identified and attributed*: which
resource was reached, **from which foothold**, through **what relay**, and with **what proof**.
This ledger records exactly that. Each :class:`Hop` is one entry; the ledger reconstructs the
end-to-end path (``scanner -> ECS (proven) -> EKS (reachable) -> Cloud Run (reachable)``) so a
reviewer can follow — and independently verify — how each accessible resource was identified.

It is shared by reference across the root target and every synthesized pivot target, so hops
recorded deep in a lateral-movement fan-out all land in one place. Recording is thread-safe
(modules run concurrently). The ledger never performs I/O — it is pure bookkeeping that other
modules and the orchestrator write into, then :meth:`to_result` renders as a normal module
result for the report and the attack-chain correlation.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from exploits.base import ExploitResult, Finding, SEVERITY_ORDER

try:
    import config
except Exception:  # pragma: no cover
    config = None  # type: ignore

NAME = getattr(config, "LEDGER_MODULE_NAME", "proof-ledger")
DESCRIPTION = "Per-hop proof-of-access ledger (identification path for every reached resource)"
_MAX_HOPS = getattr(config, "LEDGER_MAX_HOPS", 1024)

SCANNER = "scanner"

# How strong the evidence for a hop is (lower == stronger / more authoritative).
PROVEN = "proven"            # a harmless, persistent artifact confirmed usable access
REACHABILITY = "reachability"  # the resource answered a connect from the foothold's vantage
SIMULATED = "simulated"      # capability confirmed by policy simulation, never executed
PROBED = "probed"            # touched but no access obtained (true negative)
_PROOF_ORDER = {PROVEN: 0, REACHABILITY: 1, SIMULATED: 2, PROBED: 3}


@dataclass
class Hop:
    """One identified access in the lateral-movement path."""

    resource_kind: str                 # container | host | cloud | service
    identity: str                      # host:port | url | cloud:<id>
    reached_from: str = SCANNER        # parent foothold identity, or "scanner"
    via: str = "direct"                # relay/provenance: docker-relay | proxy | ssm:<id> | direct
    proof: str = ""                    # artifact id / marker / "reachability-only" / "simulated"
    proof_kind: str = REACHABILITY     # PROVEN | REACHABILITY | SIMULATED | PROBED
    scope_status: str = "n/a"          # in-scope | out-of-scope | n/a
    severity: str = "INFO"             # severity of THIS access
    note: str = ""
    network_path: str = ""             # e.g. "vpn:aws-gcp", "peering:vpc-a→vpc-b", "internet"
    ts: float = field(default_factory=time.time)


class ProofLedger:
    """Thread-safe collection of hops with end-to-end path reconstruction."""

    def __init__(self) -> None:
        self._by_id: Dict[str, Hop] = {}
        self._order: List[str] = []
        self._footholds: List[dict] = []
        self._lock = threading.Lock()

    def register_foothold(self, spec: dict) -> None:
        """Register a proven foothold (e.g. SSH creds, Docker API, command injection)."""
        with self._lock:
            # Check for existing matching foothold to update/avoid duplication
            for fh in self._footholds:
                # Deduplicate by host/port/type or url/type
                match = False
                if fh.get("type") == spec.get("type"):
                    if "host" in spec and "port" in spec:
                        match = fh.get("host") == spec.get("host") and fh.get("port") == spec.get("port")
                    elif "url" in spec:
                        match = fh.get("url") == spec.get("url")
                if match:
                    # Update credentials or other fields
                    fh.update(spec)
                    return
            self._footholds.append(spec.copy())

    def get_footholds(self) -> List[dict]:
        """Retrieve all registered footholds."""
        with self._lock:
            return [fh.copy() for fh in self._footholds]

    # -- recording ----------------------------------------------------------
    def record(self, resource_kind: str, identity: str, *, reached_from: str = SCANNER,
               via: str = "direct", proof: str = "", proof_kind: str = REACHABILITY,
               scope_status: str = "n/a", severity: str = "INFO", note: str = "",
               network_path: str = ""
               ) -> Optional[Hop]:
        """Record (or upgrade) the hop for ``identity``. Stronger evidence wins.

        Recording the same resource twice (e.g. first *reachable*, later *proven*) keeps the
        single strongest entry so the ledger reads as one identification per resource.
        """
        if not identity:
            return None
        with self._lock:
            existing = self._by_id.get(identity)
            if existing is None:
                if len(self._by_id) >= _MAX_HOPS:
                    return None
                hop = Hop(resource_kind=resource_kind, identity=identity,
                          reached_from=reached_from, via=via, proof=proof,
                          proof_kind=proof_kind, scope_status=scope_status,
                          severity=severity, note=note, network_path=network_path)
                self._by_id[identity] = hop
                self._order.append(identity)
                return hop
            # Upgrade in place when the new evidence is stronger.
            if _PROOF_ORDER.get(proof_kind, 9) < _PROOF_ORDER.get(existing.proof_kind, 9):
                existing.proof_kind = proof_kind
                existing.proof = proof or existing.proof
                existing.via = via or existing.via
                existing.reached_from = reached_from or existing.reached_from
            if SEVERITY_ORDER.get(severity, 99) < SEVERITY_ORDER.get(existing.severity, 99):
                existing.severity = severity
            if scope_status and scope_status != "n/a":
                existing.scope_status = scope_status
            if network_path and not existing.network_path:
                existing.network_path = network_path
            if note and note not in (existing.note or ""):
                existing.note = (existing.note + "; " + note).strip("; ") if existing.note else note
            return existing

    # -- queries ------------------------------------------------------------
    @property
    def hops(self) -> List[Hop]:
        with self._lock:
            return [self._by_id[i] for i in self._order]

    def reached(self) -> List[Hop]:
        """Hops representing actual movement (anything not a plain scanner-side probe)."""
        return [h for h in self.hops if h.reached_from != SCANNER or h.proof_kind == PROVEN]

    def paths(self) -> List[List[Hop]]:
        """Reconstruct ordered lateral-movement paths by following ``reached_from`` links."""
        hops = self.hops
        by_id = {h.identity: h for h in hops}
        # Children grouped by their parent identity.
        children: Dict[str, List[Hop]] = {}
        for h in hops:
            children.setdefault(h.reached_from, []).append(h)
        # Roots: hops whose parent is the scanner or is not itself a recorded hop.
        roots = [h for h in hops if h.reached_from == SCANNER or h.reached_from not in by_id]
        paths: List[List[Hop]] = []

        def walk(node: Hop, trail: List[Hop], seen: set) -> None:
            trail = trail + [node]
            kids = [c for c in children.get(node.identity, []) if c.identity not in seen]
            if not kids:
                paths.append(trail)
                return
            for c in kids:
                walk(c, trail, seen | {node.identity})

        for r in roots:
            walk(r, [], set())
        return paths

    # -- rendering ----------------------------------------------------------
    def _path_str(self, path: List[Hop]) -> str:
        crumbs = ["scanner"]
        for h in path:
            tag = {PROVEN: "proven", REACHABILITY: "reachable",
                   SIMULATED: "simulated", PROBED: "probed"}.get(h.proof_kind, h.proof_kind)
            crumbs.append(f"{h.identity} ({tag})")
        return " -> ".join(crumbs)

    def to_result(self) -> ExploitResult:
        """Render the ledger as a module result for the report and chain correlation."""
        hops = self.hops
        if not hops:
            return ExploitResult(
                name=NAME, description=DESCRIPTION, exploited=False,
                findings=[Finding(
                    title="no lateral-movement hops recorded",
                    severity="INFO", location="(ledger)",
                    detail="No resource was reached beyond the initial targets.",
                    category="lateral-movement", tags=["ledger"])])
        findings: List[Finding] = []
        proven = sum(1 for h in hops if h.proof_kind == PROVEN)
        reach = sum(1 for h in hops if h.proof_kind == REACHABILITY)
        for path in self.paths():
            depth = len(path)
            if depth <= 1 and path and path[0].reached_from == SCANNER \
                    and path[0].proof_kind != PROVEN:
                continue  # a lone scanner-side hop is not a "path"
            worst = min((h.severity for h in path), key=lambda s: SEVERITY_ORDER.get(s, 99))
            findings.append(Finding(
                title=f"Lateral-movement path ({depth} hop{'s' if depth != 1 else ''}): "
                      + self._path_str(path),
                severity=worst, location=path[-1].identity,
                detail="Each hop is identified by resource, the foothold it was reached from, the "
                       "relay used, and its proof — an auditable identification path for the access.",
                evidence="; ".join(
                    f"{h.identity}: kind={h.resource_kind} via={h.via} proof={h.proof or h.proof_kind}"
                    f" scope={h.scope_status}" for h in path),
                category="lateral-movement", tags=["ledger", "chain", "lateral-movement"]))
        for h in hops:
            findings.append(Finding(
                title=f"Proof-of-access hop: {h.identity} reached from {h.reached_from} "
                      f"[{h.proof_kind}]",
                severity=h.severity, location=h.identity,
                detail=(h.note or "Identified access recorded in the proof-of-access ledger."),
                evidence=f"resource={h.resource_kind} via={h.via} proof={h.proof or h.proof_kind} "
                         f"reached_from={h.reached_from} scope={h.scope_status}",
                category="lateral-movement", tags=["ledger", "lateral-movement", h.proof_kind]))
        summary = Finding(
            title=f"Proof-of-access ledger: {len(hops)} resource(s) identified "
                  f"({proven} proven, {reach} reachable)",
            severity="INFO", location="(ledger)",
            detail="Consolidated identification path for every resource the assessment reached.",
            evidence="; ".join(self._path_str(p) for p in self.paths()[:20]) or "none",
            category="lateral-movement", tags=["ledger"])
        findings.insert(0, summary)
        exploited = any(h.proof_kind == PROVEN for h in hops) or bool(self.reached())
        return ExploitResult(
            name=NAME, description=DESCRIPTION, exploited=exploited, findings=findings,
            attacker_value=("Each reached resource is identified with its foothold, relay and proof "
                            "— a verifiable lateral-movement path, not just isolated findings."),
            mitigation=("Break the chain at any hop: segment networks, restrict instance-to-instance "
                        "and cross-cloud (VPN) traffic, and require authentication on internal "
                        "services so a single foothold cannot reach the next resource."))

    def to_chain_report(self) -> List[dict]:
        """Structured chain report: each path with proof artifact IDs and timestamps.

        Returns a list of chain dicts suitable for JSON/Markdown serialisation:
        ``[{"path": [...], "max_severity": "...", "proof_artifacts": [...], "depth": N}]``.
        """
        chains: List[dict] = []
        for path in self.paths():
            if not path:
                continue
            severities = [SEVERITY_ORDER.get(h.severity, 99) for h in path]
            worst_idx = severities.index(min(severities))
            chain = {
                "path": [
                    {"identity": h.identity, "resource_kind": h.resource_kind,
                     "reached_from": h.reached_from, "via": h.via,
                     "proof_kind": h.proof_kind, "severity": h.severity,
                     "network_path": h.network_path or ""}
                    for h in path
                ],
                "max_severity": path[worst_idx].severity,
                "depth": len(path),
                "proof_artifacts": [h.proof for h in path if h.proof],
                "all_proven": all(h.proof_kind == PROVEN for h in path),
            }
            chains.append(chain)
        return chains

    def mermaid(self) -> str:
        """Render the lateral-movement graph as a Mermaid flowchart."""
        lines = ["graph LR"]
        seen_nodes = set()
        for h in self.hops:
            node_id = h.identity.replace(":", "_").replace("/", "_").replace(".", "_")
            if node_id not in seen_nodes:
                label = f"{h.identity}\\n[{h.proof_kind}]"
                style = ""
                if h.proof_kind == PROVEN:
                    style = ":::proven"
                elif h.proof_kind == REACHABILITY:
                    style = ":::reachable"
                elif h.proof_kind == PROBED:
                    style = ":::probed"
                lines.append(f"    {node_id}[\"{label}\"]{style}")
                seen_nodes.add(node_id)
        for h in self.hops:
            if h.reached_from and h.reached_from != SCANNER:
                from_id = h.reached_from.replace(":", "_").replace("/", "_").replace(".", "_")
                to_id = h.identity.replace(":", "_").replace("/", "_").replace(".", "_")
                edge_label = h.via or "direct"
                if h.network_path:
                    edge_label += f"\\n({h.network_path})"
                lines.append(f"    {from_id} -->|{edge_label}| {to_id}")
            elif h.reached_from == SCANNER:
                to_id = h.identity.replace(":", "_").replace("/", "_").replace(".", "_")
                lines.append(f"    scanner[\"{SCANNER}\"] -->|direct| {to_id}")
        lines.append("    classDef proven fill:#ff6666,stroke:#b30000")
        lines.append("    classDef reachable fill:#ffcc66,stroke:#c79100")
        lines.append("    classDef probed fill:#99ccff,stroke:#2a6fb3")
        return "\n".join(lines)

    def downstream_count(self, identity: str) -> int:
        """Count how many resources are downstream (reachable only via) this hop."""
        hops = self.hops
        children_map: Dict[str, List[str]] = {}
        for h in hops:
            children_map.setdefault(h.reached_from, []).append(h.identity)
        count = 0
        queue = list(children_map.get(identity, []))
        seen = {identity}
        while queue:
            node = queue.pop(0)
            if node in seen:
                continue
            seen.add(node)
            count += 1
            queue.extend(children_map.get(node, []))
        return count


def get_or_create(target) -> Optional["ProofLedger"]:
    """Return ``target.proof_ledger``, creating and attaching one if absent."""
    if target is None:
        return None
    led = getattr(target, "proof_ledger", None)
    if led is None:
        led = ProofLedger()
        try:
            target.proof_ledger = led
        except Exception:
            return None
    return led
