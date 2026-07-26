#!/usr/bin/env bash
###############################################################################
# AttackSim Run All Script — Framework Orchestrator with Dependency Management
#
# Runs the AttackSim security testing framework with automatic dependency
# installation and verification. The core runs on Python standard library
# alone; optional packages enhance advanced features (bcrypt, password
# cracking, LLM analysis, tool integrations).
#
# Runs with ZERO cloud credentials (no AWS / EKS / ArgoCD / JFrog needed).
#
# USAGE:
#   ./run_all.sh [TARGET_URL] [OPTIONS]
#   ./run_all.sh https://example.com
#   ./run_all.sh https://example.com --intensity detective
#   ./run_all.sh --setup-only              # Install deps only, don't run
#   ./run_all.sh --check-deps              # Check deps, don't run
#   ./run_all.sh --install                 # Force reinstall optional deps
#   ./run_all.sh --help                    # Show help
#
# EXIT CODES:
#   0 = success (no vulnerabilities found or setup completed)
#   1 = vulnerabilities detected
#   2 = error / missing dependencies
#
# DEPENDENCIES:
#   Required: Python 3.9+
#   Optional: bcrypt, passlib, psutil, pyyaml, dnspython, requests
#   External: nmap (optional), nuclei (optional)
###############################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" >&2
    exit 2
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse arguments
INSTALL=0
SETUP_ONLY=0
CHECK_DEPS_ONLY=0
PASSTHRU=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)
      INSTALL=1
      shift
      ;;
    --setup-only)
      SETUP_ONLY=1
      shift
      ;;
    --check-deps)
      CHECK_DEPS_ONLY=1
      shift
      ;;
    --help|-h)
      cat << 'EOF'
AttackSim v1.0 — Automated Security Testing Framework

USAGE:
    ./run_all.sh [TARGET_URL] [OPTIONS]

EXAMPLES:
    ./run_all.sh https://example.com
    ./run_all.sh https://example.com --intensity detective
    ./run_all.sh --setup-only
    ./run_all.sh --check-deps

OPTIONS:
    --intensity LEVEL       Intensity: detective (default), active, intrusive
    --scope PATTERN         Scope (required for intrusive)
    --only MODULE_NAME      Run specific module
    --yes                   Auto-confirm prompts
    --install               Force reinstall optional dependencies
    --setup-only            Install dependencies, don't run framework
    --check-deps            Check dependencies, exit
    --help                  Show this message

For full documentation, see: README.md and docs/

EOF
      exit 0
      ;;
    *)
      PASSTHRU+=("$1")
      shift
      ;;
  esac
done

# --- Locate Python interpreter -------------------------------------------
log_info "Locating Python interpreter..."
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then
    PY="$c"
    break
  fi
done

if [[ -z "$PY" ]]; then
  log_error "Python 3 is required but was not found on PATH. Please install Python 3.9 or later."
fi

PY_VERSION=$($PY --version 2>&1)
log_success "Using: $PY_VERSION"

# Verify minimum Python version (3.9)
if ! $PY -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
  log_error "Python 3.9+ is required (found: $PY_VERSION)"
fi

# --- Check for setup.sh ---------------------------------------------------
if [[ ! -f "$SCRIPT_DIR/setup.sh" ]]; then
  log_warn "setup.sh not found - some features may be unavailable"
fi

# --- Check dependencies --------------------------------------------------
check_python_module() {
  $PY -c "import $1" 2>/dev/null
  return $?
}

log_info "Checking dependencies..."

MISSING_OPTIONAL=()

# Check optional dependencies
for module in bcrypt passlib psutil yaml dns requests; do
  if check_python_module "$module"; then
    log_success "Module '$module' found"
  else
    MISSING_OPTIONAL+=("$module")
  fi
done

# Early exit if only checking deps
if [[ "$CHECK_DEPS_ONLY" -eq 1 ]]; then
  if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
    log_warn "Missing optional dependencies: ${MISSING_OPTIONAL[*]}"
    exit 1
  else
    log_success "All optional dependencies installed"
    exit 0
  fi
fi

# --- Install/update dependencies if needed --------------------------------
if [[ "$INSTALL" -eq 1 ]] || [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
  log_info "Installing/updating dependencies..."

  # Bootstrap pip if needed
  if ! $PY -m pip --version >/dev/null 2>&1; then
    log_info "Bootstrapping pip..."
    $PY -m ensurepip --upgrade >/dev/null 2>&1 || true
  fi

  # Try installing requirements
  if $PY -m pip --version >/dev/null 2>&1; then
    log_info "Installing from requirements.txt..."

    # Try different approaches for PEP 668 compatibility
    $PY -m pip install --quiet --user -r requirements.txt 2>/dev/null || \
    $PY -m pip install --quiet --user --break-system-packages -r requirements.txt 2>/dev/null || \
    log_warn "Some packages failed to install (may be offline or restricted)"

    # Also try installing extra optional packages
    log_info "Installing optional enhancements..."
    $PY -m pip install --quiet --user psutil pyyaml dnspython requests 2>/dev/null || true

    log_success "Dependency installation complete"
  else
    log_warn "pip not available - skipping package installation"
    log_info "To install dependencies manually, run: $PY -m ensurepip, then pip install -r requirements.txt"
  fi
fi

# Early exit if setup-only
if [[ "$SETUP_ONLY" -eq 1 ]]; then
  log_success "Setup complete! You can now run: ./run_all.sh https://target.com"
  exit 0
fi

# --- Run the framework ---------------------------------------------------
log_info "Launching AttackSim framework..."
log_info "Command: $PY main.py ${PASSTHRU[@]}"
echo ""

set +e
$PY main.py "${PASSTHRU[@]}"
rc=$?
set -e

echo ""
case "$rc" in
  0)
    log_success "Framework completed - no issues found or detective scan only"
    ;;
  1)
    log_warn "Framework completed - vulnerabilities detected (see summary above)"
    ;;
  *)
    log_error "Framework exited with error code $rc"
    ;;
esac

exit "$rc"
