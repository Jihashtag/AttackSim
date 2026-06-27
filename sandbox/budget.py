"""Centralised request budget — the global anti-DoS governor for active modules.

Several active modules (``fuzz-probe``, ``content-discovery``, ``default-creds``,
``host-sweep``) each enforce their own request cap, rate limit, and wall-clock budget.
This module provides a single shared governor so the toolkit can additionally bound the
**whole run** — no matter how many modules execute, the total outbound request volume and
rate stay under one ceiling. Per-module caps remain in force; the effective limit is the
*minimum* of the local and global budgets (defence in depth).

Usage::

    budget = RequestBudget(max_requests=1000, rate_limit=20, wall_budget=600)
    if budget.acquire():          # blocks briefly to honour the rate limit
        do_one_request()
    # else: the global budget is exhausted; stop cleanly.

Thread-safe: ``acquire`` serialises callers so the rate limit holds even under the module
thread pools.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

try:
    import config
except Exception:  # pragma: no cover
    config = None  # type: ignore


class RequestBudget:
    """A thread-safe counter + token-bucket enforcing a request cap, rate, and deadline."""

    def __init__(self, *, max_requests: Optional[int] = None,
                 rate_limit: Optional[float] = None,
                 wall_budget: Optional[float] = None):
        self.max_requests = int(max_requests if max_requests is not None
                                else getattr(config, "GLOBAL_MAX_REQUESTS", 5000))
        rl = rate_limit if rate_limit is not None else getattr(config, "GLOBAL_RATE_LIMIT", 50)
        self.rate_limit = max(0.0, float(rl))
        wb = wall_budget if wall_budget is not None else getattr(config, "GLOBAL_WALL_BUDGET", 1800)
        self.wall_budget = float(wb)
        self._min_delay = (1.0 / self.rate_limit) if self.rate_limit > 0 else 0.0
        self._count = 0
        self._lock = threading.Lock()
        self._last = 0.0
        self._deadline = time.monotonic() + self.wall_budget

    # -- queries -------------------------------------------------------------
    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.max_requests - self._count)

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self._count >= self.max_requests or time.monotonic() > self._deadline

    # -- consumption ---------------------------------------------------------
    def acquire(self, n: int = 1) -> bool:
        """Reserve ``n`` request slots, sleeping to honour the rate limit.

        Returns ``True`` when the slots were granted, ``False`` when the global cap or
        wall-clock budget is exhausted (the caller should stop). The rate-limit sleep is
        performed while holding the lock so concurrent callers are paced together.
        """
        with self._lock:
            now = time.monotonic()
            if self._count + n > self.max_requests or now > self._deadline:
                return False
            if self._min_delay and self._last:
                wait = self._min_delay - (now - self._last)
                if wait > 0:
                    time.sleep(wait)
            self._count += n
            self._last = time.monotonic()
            return True


def from_config() -> RequestBudget:
    """Build a run-wide budget from config defaults."""
    return RequestBudget()
