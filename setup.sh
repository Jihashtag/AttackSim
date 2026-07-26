#!/bin/bash
###############################################################################
# AttackSim Setup Script — Multi-Distro Dependency Installation
#
# Installs all required and optional dependencies for:
# - Ubuntu/Debian (apt)
# - Fedora/RedHat/CentOS (yum/dnf)
# - Alpine (apk)
# - Arch (pacman)
# - OpenSUSE (zypper)
#
# Usage:
#   ./setup.sh              # Interactive mode
#   ./setup.sh --auto       # Auto-detect distro
#   ./setup.sh --ubuntu     # Force Ubuntu/Debian
#   ./setup.sh --fedora     # Force Fedora/RedHat
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION="$VERSION_ID"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$(echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION="$DISTRIB_RELEASE"
    elif [ -f /etc/redhat-release ]; then
        DISTRO=$(head -1 /etc/redhat-release | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION=$(head -1 /etc/redhat-release | grep -oP '\d+' | head -1)
    else
        log_error "Unable to detect Linux distribution"
    fi

    log_info "Detected: $DISTRO (version $DISTRO_VERSION)"
}

# Normalize distro names
normalize_distro() {
    case "$DISTRO" in
        ubuntu|debian)
            DISTRO_TYPE="debian"
            PKG_MANAGER="apt"
            ;;
        fedora|rhel|centos|rocky|almalinux|redhat)
            DISTRO_TYPE="redhat"
            PKG_MANAGER="dnf"
            ;;
        alpine)
            DISTRO_TYPE="alpine"
            PKG_MANAGER="apk"
            ;;
        arch|manjaro)
            DISTRO_TYPE="arch"
            PKG_MANAGER="pacman"
            ;;
        opensuse*|sles)
            DISTRO_TYPE="suse"
            PKG_MANAGER="zypper"
            ;;
        *)
            log_warn "Unknown distro: $DISTRO, attempting auto-detection"
            if command -v apt &> /dev/null; then
                DISTRO_TYPE="debian"
                PKG_MANAGER="apt"
            elif command -v dnf &> /dev/null; then
                DISTRO_TYPE="redhat"
                PKG_MANAGER="dnf"
            elif command -v yum &> /dev/null; then
                DISTRO_TYPE="redhat"
                PKG_MANAGER="yum"
            elif command -v apk &> /dev/null; then
                DISTRO_TYPE="alpine"
                PKG_MANAGER="apk"
            elif command -v pacman &> /dev/null; then
                DISTRO_TYPE="arch"
                PKG_MANAGER="pacman"
            elif command -v zypper &> /dev/null; then
                DISTRO_TYPE="suse"
                PKG_MANAGER="zypper"
            else
                log_error "Could not determine package manager"
            fi
            ;;
    esac

    log_success "Using package manager: $PKG_MANAGER ($DISTRO_TYPE)"
}

# Debian/Ubuntu setup
setup_debian() {
    log_info "Setting up for Debian/Ubuntu..."

    log_info "Updating package index..."
    sudo apt update -qq || log_error "Failed to update package index"

    log_info "Installing Python 3.9+ and pip..."
    sudo apt install -y \
        python3 python3-pip python3-venv python3-dev \
        || log_error "Failed to install Python"

    log_info "Installing system dependencies..."
    sudo apt install -y \
        git curl wget vim nano \
        nmap \
        dnsutils bind-utils \
        net-tools iputils-ping traceroute \
        || log_warn "Some system packages failed to install"

    log_info "Installing optional external tools..."
    # nuclei - optional advanced scanner
    if command -v curl &> /dev/null; then
        log_info "nuclei installation (optional - skipped in auto mode)"
        # nuclei can be installed from GitHub releases if needed
    fi
}

# Fedora/RedHat setup
setup_redhat() {
    log_info "Setting up for Fedora/RedHat/CentOS..."

    log_info "Installing Python 3.9+ and pip..."
    sudo dnf install -y \
        python3 python3-pip python3-devel \
        || log_error "Failed to install Python"

    log_info "Installing system dependencies..."
    sudo dnf install -y \
        git curl wget vim nano \
        nmap \
        bind-utils \
        net-tools iputils traceroute \
        || log_warn "Some system packages failed to install"
}

# Alpine setup
setup_alpine() {
    log_info "Setting up for Alpine Linux..."

    log_info "Installing Python 3.9+ and pip..."
    sudo apk add --no-cache \
        python3 py3-pip py3-virtualenv \
        || log_error "Failed to install Python"

    log_info "Installing system dependencies..."
    sudo apk add --no-cache \
        git curl wget vim nano \
        nmap \
        bind-tools \
        iputils traceroute \
        || log_warn "Some system packages failed to install"
}

# Arch setup
setup_arch() {
    log_info "Setting up for Arch Linux..."

    log_info "Installing Python 3.9+ and pip..."
    sudo pacman -S --noconfirm \
        python python-pip \
        || log_error "Failed to install Python"

    log_info "Installing system dependencies..."
    sudo pacman -S --noconfirm \
        git curl wget vim nano \
        nmap \
        bind-tools \
        net-tools iputils traceroute \
        || log_warn "Some system packages failed to install"
}

# OpenSUSE setup
setup_suse() {
    log_info "Setting up for openSUSE..."

    log_info "Installing Python 3.9+ and pip..."
    sudo zypper install -y \
        python3 python3-pip python3-devel \
        || log_error "Failed to install Python"

    log_info "Installing system dependencies..."
    sudo zypper install -y \
        git curl wget vim nano \
        nmap \
        bind-tools \
        net-tools iputils traceroute \
        || log_warn "Some system packages failed to install"
}

# Install Python dependencies
setup_python_deps() {
    log_info "Installing Python dependencies..."

    # Check Python version
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    log_info "Python version: $PYTHON_VERSION"

    if [ -f "requirements.txt" ]; then
        log_info "Installing from requirements.txt..."
        pip3 install --upgrade pip setuptools wheel || log_warn "Failed to upgrade pip"
        pip3 install -r requirements.txt || log_warn "Some Python packages failed to install"
    else
        log_warn "requirements.txt not found"
    fi

    # Install optional dependencies
    log_info "Installing optional Python dependencies..."
    pip3 install --upgrade \
        bcrypt passlib psutil pyyaml dnspython requests \
        || log_warn "Some optional packages failed to install"

    # Development dependencies
    if [ "$INSTALL_DEV" = "yes" ]; then
        log_info "Installing development dependencies..."
        pip3 install --upgrade pytest ruff mypy || log_warn "Some dev packages failed to install"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    # Check Python
    if command -v python3 &> /dev/null; then
        log_success "Python 3 installed: $(python3 --version)"
    else
        log_error "Python 3 not found"
    fi

    # Check pip
    if command -v pip3 &> /dev/null; then
        log_success "pip3 installed: $(pip3 --version)"
    else
        log_error "pip3 not found"
    fi

    # Check optional system tools
    for tool in nmap curl git; do
        if command -v "$tool" &> /dev/null; then
            log_success "$tool installed"
        else
            log_warn "$tool not found (optional)"
        fi
    done

    # Check Python modules
    log_info "Checking Python modules..."
    python3 -c "import bcrypt; print('✓ bcrypt')" 2>/dev/null || log_warn "bcrypt not installed"
    python3 -c "import passlib; print('✓ passlib')" 2>/dev/null || log_warn "passlib not installed"
    python3 -c "import psutil; print('✓ psutil')" 2>/dev/null || log_warn "psutil not installed"
    python3 -c "import yaml; print('✓ yaml')" 2>/dev/null || log_warn "yaml not installed"
    python3 -c "import dns; print('✓ dnspython')" 2>/dev/null || log_warn "dnspython not installed"

    log_success "Installation verification complete"
}

# Interactive setup
interactive_setup() {
    echo ""
    echo -e "${BLUE}=== AttackSim Setup Wizard ===${NC}"
    echo ""

    read -p "Install development dependencies (pytest, ruff, mypy)? [y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        INSTALL_DEV="yes"
    else
        INSTALL_DEV="no"
    fi
}

# Main execution
main() {
    log_info "AttackSim Setup Script v1.0"
    echo ""

    # Parse command line arguments
    if [ "$1" == "--auto" ]; then
        log_info "Auto mode"
        INSTALL_DEV="no"
    elif [ "$1" == "--ubuntu" ]; then
        DISTRO="ubuntu"
        INSTALL_DEV="no"
    elif [ "$1" == "--fedora" ]; then
        DISTRO="fedora"
        INSTALL_DEV="no"
    elif [ "$1" == "--dev" ]; then
        INSTALL_DEV="yes"
    else
        interactive_setup
    fi

    # Detect and normalize distro
    detect_distro
    normalize_distro

    # Run appropriate setup
    case "$DISTRO_TYPE" in
        debian)
            setup_debian
            ;;
        redhat)
            setup_redhat
            ;;
        alpine)
            setup_alpine
            ;;
        arch)
            setup_arch
            ;;
        suse)
            setup_suse
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO_TYPE"
            ;;
    esac

    # Install Python dependencies
    setup_python_deps

    # Verify
    echo ""
    verify_installation

    echo ""
    log_success "Setup complete! You can now run: ./run_all.sh"
}

# Check if running with sudo for interactive mode
if [ "$1" != "--auto" ] && [ "$1" != "--ubuntu" ] && [ "$1" != "--fedora" ] && [ "$1" != "--dev" ]; then
    if [ "$EUID" -eq 0 ]; then
        log_error "Please do not run this script with sudo. It will prompt for password when needed."
    fi
fi

main "$@"
