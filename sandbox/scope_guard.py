"""Intensity tiers + scope allow-list — the safety governor for active modules.

This is the analogue of ``sandbox/credential_guard.py`` for *outbound aggressiveness*.
Two orthogonal controls are enforced **in code** (not merely documented):

* **Intensity tier** — how aggressive a module is allowed to be. A module declares its
  minimum tier via the ``INTENSITY`` attribute; the orchestrator only runs it when the
  run's intensity is at least that high. Tiers (ascending):

      detective  -> read-only fingerprinting (the historical default surface)
      active     -> bounded single-shot interactions (one auth attempt, one redirect…)
      intrusive  -> multi-request guessing/enumeration (cred spray, dir-busting, k8s-enum)
      proof      -> creates a harmless, persistent, labelled artifact (access-prover)
      fuzz       -> bounded mutational input testing (rate-limited, never a DoS)

  ``proof`` and ``fuzz`` are *peaks*, not a linear "more dangerous than intrusive": each
  is unlocked explicitly and additionally requires its own opt-in (``--prove-access`` /
  ``--intensity fuzz``). See :func:`allows`.

* **Scope allow-list** — *where* an active module may reach. Once the run is intrusive
  or above, every target host/URL must match an explicit allow-list (hosts, CIDRs, or
  domain suffixes). With an empty allow-list at that intensity the run is refused, so a
  wide/aggressive scan can never hit an unscoped target by accident.

Detective/active runs keep the historical behaviour (no allow-list required) so the
default experience is unchanged.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse

try:
    import config
except Exception:  # pragma: no cover
    config = None  # type: ignore

# Ascending rank for the linear part of the ladder.
ORDER = {"detective": 0, "active": 1, "intrusive": 2, "proof": 3, "fuzz": 4}

DETECTIVE = "detective"
ACTIVE = "active"
INTRUSIVE = "intrusive"
PROOF = "proof"
FUZZ = "fuzz"

VALID = tuple(ORDER.keys())

# At or above this tier an explicit scope allow-list is mandatory.
_REQUIRE_SCOPE_AT = getattr(config, "SCOPE_REQUIRE_ALLOWLIST_AT", "intrusive")


def normalise(level: Optional[str]) -> str:
    lvl = (level or DETECTIVE).strip().lower()
    return lvl if lvl in ORDER else DETECTIVE


def rank(level: Optional[str]) -> int:
    return ORDER.get(normalise(level), 0)


def allows(run_intensity: str, module_intensity: str) -> bool:
    """True if a run at ``run_intensity`` may execute a module needing ``module_intensity``.

    The linear tiers (detective<active<intrusive) are inclusive: a higher run intensity
    includes every lower module. ``proof`` and ``fuzz`` are special peaks — a run only
    executes them when its own intensity is exactly that peak (they are separately opted
    into), but such a peak run still includes the whole detective..intrusive base so the
    normal reconnaissance still happens first.
    """
    run_i = normalise(run_intensity)
    mod_i = normalise(module_intensity)
    if mod_i in (PROOF, FUZZ):
        return run_i == mod_i
    # base ladder module: any run at >= its rank (capping peaks to the intrusive base)
    base_run_rank = min(rank(run_i), ORDER[INTRUSIVE]) if run_i in (PROOF, FUZZ) else rank(run_i)
    return base_run_rank >= rank(mod_i)


def _host_of(value: str) -> str:
    """Extract a bare host from a URL, host:port, or host string."""
    if not value:
        return ""
    v = value.strip()
    if "://" in v:
        netloc = urlparse(v).netloc
        v = netloc
    # strip credentials and port
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    if v.startswith("["):  # IPv6 literal [::1]:443
        return v[1:v.index("]")] if "]" in v else v.strip("[]")
    if v.count(":") == 1:  # host:port
        v = v.split(":", 1)[0]
    return v


_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ldap": 389, "ldaps": 636}


def _port_of(value: str) -> Optional[int]:
    """Best-effort extraction of an explicit (or scheme-default) port from a target token."""
    if not value:
        return None
    v = value.strip()
    scheme = ""
    if "://" in v:
        parsed = urlparse(v)
        scheme = (parsed.scheme or "").lower()
        v = parsed.netloc
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    if v.startswith("["):  # IPv6 literal
        if "]:" in v:
            tail = v.rsplit("]:", 1)[1]
            return int(tail) if tail.isdigit() else None
        return _SCHEME_DEFAULT_PORTS.get(scheme)
    if v.count(":") == 1:
        tail = v.split(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return _SCHEME_DEFAULT_PORTS.get(scheme)



@dataclass
class ScopeGuard:
    """An allow-list of hosts / CIDRs / domain-suffixes plus the run intensity."""

    intensity: str = DETECTIVE
    hosts: List[str] = field(default_factory=list)       # exact IPs / hostnames
    cidrs: List[str] = field(default_factory=list)       # CIDR networks
    domains: List[str] = field(default_factory=list)     # suffix match (".example.com")
    # Optional per-target port allow-list. Maps a matcher (host/IP/domain/CIDR string) to
    # the set of ports allowed for it. A host with no entry here is unrestricted (all ports).
    port_rules: dict = field(default_factory=dict)
    _networks: list = field(default_factory=list, init=False, repr=False)

    def __post_init__(self):
        self.intensity = normalise(self.intensity)
        self._networks = []
        for c in self.cidrs:
            try:
                self._networks.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
        self.hosts = [h.strip().lower() for h in self.hosts if h.strip()]
        self.domains = [d.strip().lower().lstrip("*") for d in self.domains if d.strip()]


    # -- construction --------------------------------------------------------
    @classmethod
    def from_specs(cls, specs: List[str], intensity: str = DETECTIVE) -> "ScopeGuard":
        """Build from mixed CLI/file tokens; each token is a host, CIDR, or domain.

        A token may carry an explicit port (``host:8080``, ``10.0.0.0/24:443``,
        ``https://api.example.com``) to restrict the allow-list to that port. Multiple
        tokens for the same matcher union their ports. A matcher used without any port
        stays unrestricted (all ports allowed).
        """
        hosts: List[str] = []
        cidrs: List[str] = []
        domains: List[str] = []
        port_rules: dict = {}

        def _record_port(matcher: str, port: Optional[int]):
            if port is None:
                return
            port_rules.setdefault(matcher.lower(), set()).add(port)

        for raw in specs or []:
            tok = (raw or "").strip()
            if not tok or tok.startswith("#"):
                continue
            port = _port_of(tok)
            if "://" in tok:
                tok = _host_of(tok)
            else:
                # strip a trailing :port for non-CIDR host tokens (CIDR ports handled below)
                if "/" not in tok and tok.count(":") == 1 and tok.rsplit(":", 1)[1].isdigit():
                    tok = tok.rsplit(":", 1)[0]
                elif "/" in tok and tok.count(":") == 1 and tok.rsplit(":", 1)[1].isdigit():
                    tok = tok.rsplit(":", 1)[0]
            if "/" in tok:
                cidrs.append(tok)
                _record_port(tok, port)
            elif tok.startswith(".") or tok.startswith("*."):
                dom = tok.lstrip("*")
                domains.append(dom)
                _record_port(dom, port)
            else:
                try:
                    ipaddress.ip_address(tok)
                    hosts.append(tok)
                    _record_port(tok, port)
                except ValueError:
                    # bare hostname: treat as both an exact host and a domain suffix
                    hosts.append(tok)
                    domains.append("." + tok)
                    _record_port(tok, port)
                    _record_port("." + tok, port)
        return cls(intensity=intensity, hosts=hosts, cidrs=cidrs, domains=domains,
                   port_rules=port_rules)


    # -- queries -------------------------------------------------------------
    @property
    def empty(self) -> bool:
        return not (self.hosts or self._networks or self.domains)

    @property
    def requires_scope(self) -> bool:
        """True if the current intensity mandates confirmation.

        Under the new scope model (v2), intrusive+ runs require either:
        - An explicit ``--yes`` flag (non-interactive confirmation), OR
        - An interactive ``[y/N]`` prompt.
        
        An allow-list is NO LONGER mandatory. The scope is derived from the target
        itself (host, CIDR, URL domain). Optional --scope entries further narrow it.
        """
        if self.intensity in (PROOF, FUZZ):
            return False
        return rank(self.intensity) >= rank(_REQUIRE_SCOPE_AT)

    @property
    def requires_confirmation(self) -> bool:
        """True if intrusive+ and thus needs --yes or interactive prompt."""
        return rank(self.intensity) >= rank(_REQUIRE_SCOPE_AT)

    def in_scope(self, value: str) -> bool:
        """True if a host/URL/host:port is within the allow-list.

        An empty allow-list means "no restriction" (used for detective/active runs);
        callers that require scope must check :func:`needs_block` / :meth:`requires_scope`
        first. When the matched target carries port restrictions, the value's port (if
        known) must also be allowed.
        """
        if self.empty:
            return True
        host = _host_of(value)
        if not host:
            return False
        if not self._host_matches(host):
            return False
        return self._port_ok(host, _port_of(value))

    def _host_matches(self, host: str) -> bool:
        h = host.lower()
        if h in self.hosts:
            return True
        for dom in self.domains:
            if h == dom.lstrip(".") or h.endswith(dom):
                return True
        try:
            ip = ipaddress.ip_address(host)
            for net in self._networks:
                if ip in net:
                    return True
        except ValueError:
            # Not an IP literal — try DNS resolution so that a CIDR scope (e.g.
            # 0.0.0.0/0) can still match hostnames. Bounded single lookup, silent
            # on failure (offline / non-existent host stays out of scope).
            if self._networks:
                import socket as _socket
                try:
                    resolved = _socket.gethostbyname(host)
                    resolved_ip = ipaddress.ip_address(resolved)
                    for net in self._networks:
                        if resolved_ip in net:
                            return True
                except (OSError, ValueError):
                    pass
        return False

    def _port_ok(self, host: str, port: Optional[int]) -> bool:
        """True unless the host has explicit port rules that exclude ``port``."""
        if not self.port_rules:
            return True
        allowed: set = set()
        restricted = False
        h = host.lower()
        for matcher, ports in self.port_rules.items():
            if not ports:
                continue
            matched = False
            if matcher.startswith("."):
                matched = (h == matcher.lstrip(".") or h.endswith(matcher))
            elif "/" in matcher:
                try:
                    matched = ipaddress.ip_address(host) in ipaddress.ip_network(
                        matcher, strict=False)
                except ValueError:
                    matched = False
            else:
                matched = (h == matcher)
            if matched:
                restricted = True
                allowed |= ports
        if not restricted:
            return True
        if port is None:
            # Cannot determine the port — do not block on port grounds.
            return True
        return port in allowed


    def authorize(self, value: str) -> Tuple[bool, str]:
        """Return ``(allowed, reason)`` for reaching ``value`` at the current intensity.

        v2 scope model:
        * Below the scope-enforcement tier: always allowed (historical behaviour).
        * Peak tiers (proof/fuzz): always allowed — the operator explicitly opted in.
        * At/above intrusive WITHOUT an allow-list: allowed (scope = target-derived,
          confirmation was obtained via --yes or interactive prompt at startup).
        * At/above intrusive WITH an allow-list: allowed only if value matches the list
          (optional narrowing).
        """
        # Peak tiers are explicitly opted into — scope is advisory (if present, enforce it)
        if self.intensity in (PROOF, FUZZ):
            if self.empty:
                return True, "peak tier (proof/fuzz) — operator opted in; target is the scope"
            if self.in_scope(value):
                return True, "in scope"
            return False, f"{_host_of(value)!r} is not in the scope allow-list"
        if not self.requires_scope:
            return True, "intensity below scope-enforcement threshold"
        # v2: no allow-list is fine; scope = the target itself (confirmation was given)
        if self.empty:
            return True, "intrusive+ confirmed; scope = target-derived (no allow-list restriction)"
        if self.in_scope(value):
            return True, "in scope"
        return False, f"{_host_of(value)!r} is not in the scope allow-list"

    def summary(self) -> str:
        parts = []
        if self.hosts:
            parts.append(f"hosts={self.hosts}")
        if self._networks:
            parts.append(f"cidrs={[str(n) for n in self._networks]}")
        if self.domains:
            parts.append(f"domains={self.domains}")
        scope = ", ".join(parts) if parts else "(none)"
        return f"intensity={self.intensity}; scope={scope}"


def load_scope_file(path: str) -> List[str]:
    """Read one allow-list token per line from a file (``#`` comments allowed)."""
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except OSError:
        pass
    return out
