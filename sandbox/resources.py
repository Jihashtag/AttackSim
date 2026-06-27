"""Adaptive resource detection for parallelism tuning.

When no explicit --jobs or --profile is provided, the toolkit auto-detects the
machine's CPU count and available memory to pick an appropriate concurrency level.
This is especially important for propagated instances running inside containers
with tight cgroup limits.
"""
from __future__ import annotations

import os
from typing import Optional


def detect_optimal_jobs(*, floor: int = 2, ceiling: int = 32) -> int:
    """Detect an appropriate jobs value based on CPU + memory.

    Heuristic:
    - Base: min(cpu_count, 16)
    - Memory constraint: available_mb // 128 (each module ~128MB overhead estimate)
    - Container detection: if cgroup memory limit < 512MB, cap to 2
    - Final: clamp between floor and ceiling
    """
    # CPU detection
    try:
        cpus = os.cpu_count() or 4
    except Exception:
        cpus = 4

    base = min(cpus, 16)

    # Memory detection (Linux)
    mem_cap = ceiling
    try:
        # Check cgroup memory limit first (containerized environments)
        cgroup_limit = _cgroup_memory_limit()
        if cgroup_limit and cgroup_limit < (1 << 62):  # not "unlimited"
            mem_mb = cgroup_limit // (1024 * 1024)
            mem_cap = max(floor, mem_mb // 128)
        else:
            # Host memory from /proc/meminfo
            mem_mb = _proc_meminfo_available()
            if mem_mb:
                mem_cap = max(floor, mem_mb // 128)
    except Exception:
        pass  # can't detect memory, use CPU-only heuristic

    jobs = min(base, mem_cap, ceiling)
    return max(jobs, floor)


def _cgroup_memory_limit() -> Optional[int]:
    """Read cgroup v2 memory.max (or v1 memory.limit_in_bytes)."""
    for path in ("/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open(path) as f:
                val = f.read().strip()
                if val == "max":
                    return None  # unlimited
                return int(val)
        except (OSError, ValueError):
            continue
    return None


def _proc_meminfo_available() -> Optional[int]:
    """Read MemAvailable from /proc/meminfo, return MB."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024  # kB -> MB
    except (OSError, ValueError, IndexError):
        return None
    return None


def describe() -> str:
    """Human-readable summary of detected resources."""
    cpus = os.cpu_count() or "?"
    mem = _proc_meminfo_available()
    cgroup = _cgroup_memory_limit()
    parts = [f"cpu={cpus}"]
    if cgroup and cgroup < (1 << 62):
        parts.append(f"cgroup_mem={cgroup // (1024*1024)}MB")
    elif mem:
        parts.append(f"avail_mem={mem}MB")
    return ", ".join(parts)
