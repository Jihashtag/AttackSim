"""Payload packaging for propagation — strategy selection and payload building.

Strategies (in priority order):
1. native   — Pre-built static binary (zero dependencies on target)
2. zipapp   — Python zipapp (.pyz, needs python3 on target but no install)
3. source   — tar.gz of source tree (legacy, needs python3 + tar + base64)

The module auto-selects the best strategy based on:
- Available pre-built payloads (data/payloads/)
- Target platform (detected via relay probe)
- Target capabilities (python3 available? base64? chmod?)
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import pathlib
import tarfile
import zipfile
from typing import Dict, List, Optional, Tuple

# Project root (where main.py lives)
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Pre-built payload directory
_PAYLOADS_DIR = _PROJECT_ROOT / "data" / "payloads"

# Platform mappings
_PLATFORM_MAP = {
    ("Linux", "x86_64"): "linux-amd64",
    ("Linux", "aarch64"): "linux-arm64",
    ("Linux", "armv7l"): "linux-arm64",  # fallback
    ("Windows", "AMD64"): "windows-amd64",
    ("Windows", "x86_64"): "windows-amd64",
    ("Darwin", "x86_64"): "darwin-amd64",
    ("Darwin", "arm64"): "darwin-arm64",
}

# musl-based platforms (Alpine, etc.) need separate binaries
_MUSL_PLATFORM_MAP = {
    ("Linux", "x86_64"): "linux-musl-amd64",
    ("Linux", "aarch64"): "linux-musl-arm64",
}


# ===========================================================================
# Strategy: Native Binary
# ===========================================================================

def get_native_payload(platform: str) -> Optional[bytes]:
    """Get pre-built native binary for the given platform.

    Args:
        platform: one of 'linux-amd64', 'linux-arm64', 'windows-amd64'
    Returns:
        Binary payload bytes, or None if not available
    """
    # Check for compressed payload first (.zst, .gz)
    for ext in (".zst", ".gz", ""):
        if platform.startswith("windows"):
            name = f"sectest-{platform}.exe{ext}"
        else:
            name = f"sectest-{platform}{ext}"
        path = _PAYLOADS_DIR / name
        if path.exists():
            data = path.read_bytes()
            if ext == ".gz":
                import gzip
                data = gzip.decompress(data)
            elif ext == ".zst":
                # zstd decompression (optional dependency)
                try:
                    import zstandard
                    data = zstandard.ZstdDecompressor().decompress(data)
                except ImportError:
                    continue
            return data
    return None


def native_available(platform: str) -> bool:
    """Check if a native binary is available for the given platform."""
    return get_native_payload(platform) is not None


# ===========================================================================
# Strategy: Zipapp
# ===========================================================================

def build_zipapp_payload(interpreter: str = "/usr/bin/env python3") -> bytes:
    """Build a zipapp (.pyz) from the current source tree.

    Returns the zipapp bytes ready for deployment.
    """
    buf = io.BytesIO()
    # Shebang line
    shebang = f"#!{interpreter}\n".encode("utf-8")
    buf.write(shebang)

    # Build zip content
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src_file in sorted(_PROJECT_ROOT.rglob("*.py")):
            rel = src_file.relative_to(_PROJECT_ROOT)
            # Skip tests, build scripts, caches
            parts = set(rel.parts)
            if parts & {"tests", "__pycache__", ".venv", "venv", "build",
                        ".git", ".mypy_cache", ".ruff_cache"}:
                continue
            zf.writestr(str(rel), src_file.read_bytes())

        # Include data files (JSON configs, wordlists)
        for pattern in ("data/**/*.json", "data/**/*.txt"):
            for data_file in _PROJECT_ROOT.glob(pattern):
                rel = data_file.relative_to(_PROJECT_ROOT)
                zf.writestr(str(rel), data_file.read_bytes())

        # Entry point
        zf.writestr("__main__.py", (
            "import sys, os\n"
            "app_root = os.path.dirname(os.path.abspath(__file__))\n"
            "if app_root not in sys.path:\n"
            "    sys.path.insert(0, app_root)\n"
            "from main import main\n"
            "sys.exit(main() or 0)\n"
        ))

    return buf.getvalue()


def get_cached_zipapp() -> Optional[bytes]:
    """Get pre-built zipapp from payloads directory if available."""
    for ext in (".zst", ".gz", ""):
        path = _PAYLOADS_DIR / f"sectest.pyz{ext}"
        if path.exists():
            data = path.read_bytes()
            if ext == ".gz":
                import gzip
                data = gzip.decompress(data)
            elif ext == ".zst":
                try:
                    import zstandard
                    data = zstandard.ZstdDecompressor().decompress(data)
                except ImportError:
                    continue
            return data
    return None


# ===========================================================================
# Strategy: Source tar.gz (legacy)
# ===========================================================================

def build_source_payload() -> bytes:
    """Build a tar.gz of the source tree (legacy approach)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for src_file in sorted(_PROJECT_ROOT.rglob("*")):
            if not src_file.is_file():
                continue
            rel = src_file.relative_to(_PROJECT_ROOT)
            parts = set(rel.parts)
            if parts & {"tests", "__pycache__", ".venv", "venv", "build",
                        "audit_log", ".git", ".mypy_cache"}:
                continue
            if src_file.suffix not in (".py", ".json", ".txt", ".yaml", ".yml"):
                continue
            # Add to tar under sectest/ prefix
            arcname = f"sectest/{rel}"
            tf.add(str(src_file), arcname=arcname)
    return buf.getvalue()


# ===========================================================================
# Platform Detection
# ===========================================================================

def detect_platform_via_relay(relay) -> Optional[str]:
    """Detect target platform via relay exec (uname -sm).

    Returns platform string like 'linux-amd64' or None if detection fails.
    Detects musl/glibc distinction for Linux targets.
    """
    if not hasattr(relay, '_exec_cmd'):
        return None

    result = relay._exec_cmd("uname -sm 2>/dev/null || echo Windows AMD64")
    if not result:
        return None

    parts = result.strip().split()
    if len(parts) >= 2:
        os_name = parts[0]
        arch = parts[1]

        # For Linux, detect musl vs glibc
        if os_name == "Linux":
            is_musl = _detect_musl_via_relay(relay)
            if is_musl:
                musl_platform = _MUSL_PLATFORM_MAP.get((os_name, arch))
                if musl_platform and native_available(musl_platform):
                    return musl_platform
                # Fall through to glibc/zipapp if no musl binary available

        return _PLATFORM_MAP.get((os_name, arch))
    return None


def _detect_musl_via_relay(relay) -> bool:
    """Detect if the target uses musl libc (Alpine/BusyBox)."""
    if not hasattr(relay, '_exec_cmd'):
        return False
    # Multiple detection methods:
    # 1. Check if ldd reports musl
    # 2. Check /etc/os-release for Alpine
    # 3. Check if /lib/ld-musl-* exists
    result = relay._exec_cmd(
        "( ldd --version 2>&1 | grep -qi musl && echo MUSL ) || "
        "( grep -qi alpine /etc/os-release 2>/dev/null && echo MUSL ) || "
        "( ls /lib/ld-musl-* 2>/dev/null && echo MUSL ) || "
        "echo GLIBC"
    )
    return bool(result and "MUSL" in result)


def detect_python_available(relay) -> bool:
    """Check if python3 is available on the target."""
    if not hasattr(relay, '_exec_cmd'):
        return False
    result = relay._exec_cmd("python3 --version 2>/dev/null && echo OK")
    return bool(result and "OK" in result)


# ===========================================================================
# Strategy Selection
# ===========================================================================

class PayloadStrategy:
    """Represents a selected payload strategy with its payload bytes."""

    def __init__(self, name: str, payload: bytes, needs_python: bool = False,
                 is_executable: bool = True):
        self.name = name
        self.payload = payload
        self.needs_python = needs_python
        self.is_executable = is_executable
        self.size = len(payload)
        self.sha256 = hashlib.sha256(payload).hexdigest()[:16]

    def deploy_command(self, payload_path: str, args: List[str]) -> str:
        """Generate the shell command to run this payload."""
        args_str = " ".join(_sh_escape(a) for a in args)
        if self.needs_python:
            return f"python3 {payload_path} {args_str}"
        return f"{payload_path} {args_str}"


def select_strategy(platform: Optional[str] = None,
                    has_python: bool = True,
                    force: Optional[str] = None) -> PayloadStrategy:
    """Select the best propagation strategy.

    Args:
        platform: target platform (e.g., 'linux-amd64') or None for auto
        has_python: whether python3 is available on target
        force: force a specific strategy ('native', 'zipapp', 'source')

    Returns:
        PayloadStrategy with the selected payload
    """
    # Forced strategy
    if force == "native" and platform:
        payload = get_native_payload(platform)
        if payload:
            return PayloadStrategy("native", payload, needs_python=False)

    if force == "zipapp":
        payload = get_cached_zipapp() or build_zipapp_payload()
        return PayloadStrategy("zipapp", payload, needs_python=True)

    if force == "source":
        payload = build_source_payload()
        return PayloadStrategy("source", payload, needs_python=True,
                               is_executable=False)

    # Auto-selection: native > zipapp > source
    if platform:
        native = get_native_payload(platform)
        if native:
            return PayloadStrategy("native", native, needs_python=False)

    if has_python:
        # Prefer zipapp over source (smaller, single file, no unpack)
        zipapp = get_cached_zipapp() or build_zipapp_payload()
        return PayloadStrategy("zipapp", zipapp, needs_python=True)

    # Last resort: if no python and no native binary, still try source
    # (maybe the target has python after all)
    source = build_source_payload()
    return PayloadStrategy("source", source, needs_python=True,
                           is_executable=False)


# ===========================================================================
# Helpers
# ===========================================================================

def _sh_escape(s: str) -> str:
    """Basic POSIX shell escaping."""
    if not s:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./=:,@")
    if all(c in safe for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def payload_manifest() -> Dict:
    """Generate manifest of available payloads."""
    manifest: Dict = {"strategies": [], "payloads": {}}

    # Check native binaries
    if _PAYLOADS_DIR.exists():
        for f in _PAYLOADS_DIR.iterdir():
            if f.name.startswith("sectest-") and not f.name.endswith(".json"):
                manifest["payloads"][f.name] = {
                    "size": f.stat().st_size,
                    "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
                }

    # Available strategies
    for platform in ("linux-amd64", "linux-arm64", "linux-musl-amd64", "linux-musl-arm64",
                     "darwin-amd64", "darwin-arm64", "windows-amd64"):
        if native_available(platform):
            manifest["strategies"].append(f"native:{platform}")
    manifest["strategies"].append("zipapp")
    manifest["strategies"].append("source")

    return manifest
