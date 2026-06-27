#!/usr/bin/env bash
#
# security_test / run_all.sh
# ---------------------------------------------------------------------------
# Bash orchestrator for the unauthenticated attacker simulation.
#
# Runs with ZERO cloud credentials (no AWS / EKS / ArgoCD / JFrog needed).
# The core is pure Python standard library; optional extras (bcrypt for the
# password cracker, ollama for the local-LLM briefing) enhance it when present.
#
# Usage:
#   ./run_all.sh                      # attack the parent workspace, pretty output
#   ./run_all.sh -t /path/to/repo     # attack a specific directory
#   ./run_all.sh --install            # best-effort install optional deps (needs network)
#   ./run_all.sh --llm --model gemma2 # add a local-LLM attacker briefing
#   ./run_all.sh --markdown report/report.md
#
# Exit codes: 0 = risks mitigated, 1 = exploitation succeeded, 2 = error.
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL=0
PASSTHRU=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) INSTALL=1; shift ;;
    *) PASSTHRU+=("$1"); shift ;;
  esac
done

# --- locate a python interpreter -------------------------------------------
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [[ -z "$PY" ]]; then
  echo "error: python3 is required but was not found on PATH." >&2
  exit 2
fi
echo "[*] using interpreter: $($PY --version 2>&1)" >&2

# --- optional: install enhancement packages --------------------------------
if [[ "$INSTALL" -eq 1 ]]; then
  echo "[*] attempting best-effort install of optional dependencies ..." >&2
  # Some interpreters ship without pip (e.g. minimal venvs); bootstrap it if we can.
  if ! "$PY" -m pip --version >/dev/null 2>&1; then
    "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
  fi
  if "$PY" -m pip --version >/dev/null 2>&1; then
    # PEP 668 "externally managed" envs need an explicit opt-in for --user installs.
    "$PY" -m pip install --quiet --user -r requirements.txt 2>/dev/null \
      || "$PY" -m pip install --quiet --user --break-system-packages -r requirements.txt 2>/dev/null \
      && echo "[*] optional dependencies installed." >&2 \
      || echo "[!] optional install failed (offline / restricted); core still runs on stdlib only." >&2
  else
    echo "[!] no pip available (try: $PY -m ensurepip, or 'uv pip install -r requirements.txt');" >&2
    echo "    core still runs on the stdlib alone." >&2
  fi
fi

# --- run --------------------------------------------------------------------
echo "[*] launching attacker simulation ..." >&2
set +e
"$PY" main.py "${PASSTHRU[@]}"
rc=$?
set -e

case "$rc" in
  0) echo "[*] done — no exploit succeeded (risks mitigated)." >&2 ;;
  1) echo "[*] done — exploitable issues were found (see summary above)." >&2 ;;
  *) echo "[!] toolkit exited with error code $rc." >&2 ;;
esac
exit "$rc"
