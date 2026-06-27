"""Resume/state store for large multi-target runs.

Records which (target, module) pairs have already completed so a re-run with ``--resume``
can skip work already done — useful for long ``--cidr`` / ``--targets-file`` sweeps that may
be interrupted. The file is a small JSON document; writes are thread-safe and flushed as
each module finishes so progress survives an abrupt stop.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Optional, Set

try:
    import config
except Exception:  # pragma: no cover
    config = None  # type: ignore

_VERSION = getattr(config, "RESUME_STATE_VERSION", 1)


def _key(target_label: str, module_name: str) -> str:
    return f"{target_label}\x1f{module_name}"


class ResumeState:
    """A persisted set of completed (target, module) keys."""

    def __init__(self, path: str, done: Optional[Set[str]] = None):
        self.path = path
        self._done: Set[str] = set(done or ())
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: str) -> "ResumeState":
        done: Set[str] = set()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("done"), list):
                done = {str(k) for k in data["done"]}
        except (OSError, ValueError):
            done = set()
        return cls(path, done)

    def is_done(self, target_label: str, module_name: str) -> bool:
        with self._lock:
            return _key(target_label, module_name) in self._done

    def mark(self, target_label: str, module_name: str) -> None:
        with self._lock:
            self._done.add(_key(target_label, module_name))
            self._flush_locked()

    def _flush_locked(self) -> None:
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": _VERSION, "done": sorted(self._done)}, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._done)
