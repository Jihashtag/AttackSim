"""Build a self-contained zipapp (.pyz) from the security_test source tree.

Usage:
    python build/build_zipapp.py [output_path]

The resulting .pyz can be run on any system with Python 3.9+:
    python3 sectest.pyz --targets 10.0.0.0/24 --prove-access
"""
from __future__ import annotations

import io
import os
import pathlib
import shutil
import sys
import tempfile
import zipapp
import zipfile

# Project root (parent of build/)
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Patterns to exclude from the zipapp (no test data, caches, build artifacts)
_EXCLUDE_DIRS = {
    "tests", "__pycache__", ".venv", "venv", "build", "audit_log",
    ".git", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "terraform.tfstate.d", "node_modules",
}
_EXCLUDE_EXTENSIONS = {".pyc", ".pyo", ".egg-info", ".so", ".dll", ".dylib"}


def _should_include(path: pathlib.Path, rel: pathlib.Path) -> bool:
    """Determine whether a file/dir should be included in the zipapp."""
    parts = set(rel.parts)
    # Skip excluded directories
    if parts & _EXCLUDE_DIRS:
        return False
    # Skip hidden dirs (except data files)
    for part in rel.parts[:-1]:
        if part.startswith(".") and part not in ("."):
            return False
    # Skip excluded extensions
    if path.suffix in _EXCLUDE_EXTENSIONS:
        return False
    # Only include files useful at runtime
    return path.suffix in (".py", ".json", ".txt", ".yaml", ".yml", ".toml", "")


def build_pyz(output: str = "sectest.pyz",
              interpreter: str = "/usr/bin/env python3",
              compress: bool = True) -> pathlib.Path:
    """Build a compressed zipapp from the project source tree.

    Returns the path to the created .pyz file.
    """
    output_path = pathlib.Path(output).resolve()

    with tempfile.TemporaryDirectory() as tmp:
        app_dir = pathlib.Path(tmp) / "app"
        app_dir.mkdir()

        # Copy relevant source files maintaining directory structure
        for src_file in sorted(_PROJECT_ROOT.rglob("*")):
            if not src_file.is_file():
                continue
            rel = src_file.relative_to(_PROJECT_ROOT)
            if not _should_include(src_file, rel):
                continue
            dest = app_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest)

        # Create __main__.py entry point
        main_py = app_dir / "__main__.py"
        main_py.write_text(
            "import sys\n"
            "import os\n"
            "# Ensure the app root is on sys.path\n"
            "app_root = os.path.dirname(os.path.abspath(__file__))\n"
            "if app_root not in sys.path:\n"
            "    sys.path.insert(0, app_root)\n"
            "from main import main\n"
            "sys.exit(main() or 0)\n"
        )

        # Build the zipapp
        zipapp.create_archive(
            app_dir,
            target=str(output_path),
            interpreter=interpreter,
            compressed=compress,
        )

    return output_path


def build_pyz_bytes(interpreter: str = "/usr/bin/env python3") -> bytes:
    """Build the zipapp and return it as bytes (for embedding in propagation payload)."""
    with tempfile.NamedTemporaryFile(suffix=".pyz", delete=False) as f:
        tmp_path = f.name
    try:
        build_pyz(output=tmp_path, interpreter=interpreter)
        return pathlib.Path(tmp_path).read_bytes()
    finally:
        os.unlink(tmp_path)


def build_pyz_from_source_bytes(source_files: dict[str, bytes],
                                interpreter: str = "/usr/bin/env python3") -> bytes:
    """Build a zipapp from in-memory source files (used during propagation).

    Args:
        source_files: mapping of relative path -> file content bytes
        interpreter: shebang interpreter line
    Returns:
        The zipapp bytes ready for deployment
    """
    buf = io.BytesIO()
    # Write shebang
    shebang = f"#!{interpreter}\n".encode("utf-8")
    buf.write(shebang)
    # Write zip content
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, content in sorted(source_files.items()):
            zf.writestr(rel_path, content)
        # Ensure __main__.py exists
        if "__main__.py" not in source_files:
            zf.writestr("__main__.py", (
                "import sys, os\n"
                "app_root = os.path.dirname(os.path.abspath(__file__))\n"
                "if app_root not in sys.path:\n"
                "    sys.path.insert(0, app_root)\n"
                "from main import main\n"
                "sys.exit(main() or 0)\n"
            ))
    return buf.getvalue()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sectest.pyz"
    result = build_pyz(output=out)
    size_kb = result.stat().st_size / 1024
    print(f"Built {result} ({size_kb:.1f} KB)")
