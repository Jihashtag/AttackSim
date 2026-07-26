# AttackSim Installation Guide

Complete setup and installation instructions for the AttackSim security testing framework across multiple Linux distributions and platforms.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Requirements](#system-requirements)
3. [Installation Methods](#installation-methods)
4. [Supported Distributions](#supported-distributions)
5. [Dependency Details](#dependency-details)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Fastest Way (Automatic)

```bash
./run_all.sh --setup-only     # Install dependencies only
./run_all.sh https://example.com  # Run security scan
```

The `run_all.sh` script will automatically:
1. Detect your Linux distribution
2. Install all required and optional dependencies
3. Verify the installation
4. Launch the framework

### Manual Setup

Choose your preferred installation method:

```bash
# Bash script (recommended for Linux)
./setup.sh --auto

# Python script (cross-platform)
python3 setup.py --auto

# Or interactive mode
./setup.sh      # Shows menu
python3 setup.py  # Shows menu
```

---

## System Requirements

### Minimum Requirements

- **OS**: Linux, macOS, or WSL2 (Windows)
- **Python**: 3.9 or later
- **RAM**: 512MB minimum (2GB recommended)
- **Disk**: 500MB for framework + dependencies

### Recommended

- **Python**: 3.11+
- **RAM**: 4GB+
- **Network**: Internet access for initial setup
- **Permissions**: Sudo access (for system package installation)

---

## Installation Methods

### Method 1: Bash Script (Linux/macOS)

**Recommended for Linux users.**

```bash
# Automatic detection
./setup.sh --auto

# Interactive mode
./setup.sh

# Force specific distro
./setup.sh --ubuntu      # For Debian/Ubuntu
./setup.sh --fedora      # For Fedora/RedHat
```

**Features:**
- ✅ Automatic distro detection
- ✅ Multi-distro support
- ✅ Interactive prompts
- ✅ Color-coded output
- ✅ Comprehensive error handling

**Supported Distros:**
- Ubuntu, Debian
- Fedora, RedHat, CentOS, Rocky, AlmaLinux
- Alpine Linux
- Arch Linux, Manjaro
- openSUSE, SLES

### Method 2: Python Script (Cross-Platform)

**Works on any system with Python 3.9+.**

```bash
# Automatic
python3 setup.py --auto

# Interactive
python3 setup.py

# Development mode (includes pytest, ruff, mypy)
python3 setup.py --auto --dev

# Verify existing installation
python3 setup.py --verify-only
```

**Features:**
- ✅ Cross-platform
- ✅ Pure Python
- ✅ No shell dependencies
- ✅ Detailed logging
- ✅ Dependency verification

### Method 3: run_all.sh (Quickest)

**One command to install and run.**

```bash
# Install and scan
./run_all.sh --setup-only https://example.com

# Install dependencies only
./run_all.sh --setup-only

# Check dependencies
./run_all.sh --check-deps

# Force reinstall
./run_all.sh --install https://example.com
```

**Features:**
- ✅ Automatic dependency detection
- ✅ Install on-demand
- ✅ Bootstrap pip if missing
- ✅ PEP 668 compatibility
- ✅ Handles system package install

---

## Supported Distributions

### Debian/Ubuntu (apt)

```bash
./setup.sh --ubuntu
# or
python3 setup.py --auto
```

**Tested on:**
- Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS
- Debian 11, 12
- Linux Mint

### Fedora/RedHat (dnf/yum)

```bash
./setup.sh --fedora
# or
python3 setup.py --auto
```

**Tested on:**
- Fedora 38, 39, 40
- RHEL 8, 9
- CentOS Stream
- Rocky Linux 8, 9
- AlmaLinux 8, 9

### Alpine Linux (apk)

```bash
python3 setup.py --auto
```

**Tested on:**
- Alpine 3.18, 3.19

### Arch Linux (pacman)

```bash
python3 setup.py --auto
```

**Tested on:**
- Arch Linux (rolling)
- Manjaro

### openSUSE (zypper)

```bash
python3 setup.py --auto
```

**Tested on:**
- openSUSE Leap 15.x
- openSUSE Tumbleweed

### macOS (Homebrew)

```bash
# Install Homebrew first: https://brew.sh
./setup.py --auto
```

---

## Dependency Details

### Required Dependencies

| Package | Purpose | License |
|---------|---------|---------|
| **Python 3.9+** | Runtime | Python Software Foundation |
| **pip** | Package manager | MIT |
| **Standard Library** | Core functionality | PSF |

### Optional Python Packages

| Package | Purpose | Version | Install |
|---------|---------|---------|---------|
| **bcrypt** | Password hash cracking | >=4.0 | Auto |
| **passlib** | Alternative password support | >=1.7 | Auto |
| **psutil** | Performance profiling | latest | Auto |
| **pyyaml** | Nuclei template export | latest | Auto |
| **dnspython** | DNS utilities | latest | Auto |
| **requests** | HTTP requests | latest | Auto |

### Optional System Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **nmap** | Network scanning | `apt install nmap` |
| **nuclei** | Vulnerability template scan | GitHub releases |
| **git** | Version control | Pre-installed |
| **curl/wget** | HTTP download | Pre-installed |

### Development Dependencies (Optional)

```bash
python3 setup.py --auto --dev
```

Installs: `pytest`, `ruff`, `mypy`

---

## Verification

### Quick Verification

```bash
./run_all.sh --check-deps
# or
python3 setup.py --verify-only
```

### Manual Verification

```bash
# Check Python version
python3 --version  # Should be 3.9+

# Check pip
python3 -m pip --version

# Check modules
python3 -c "import bcrypt, passlib, psutil, yaml, dns, requests; print('✓ All modules found')"

# Check tools
command -v nmap git curl
```

### Full Test Run

```bash
# Run framework detector-only scan
./run_all.sh https://example.com --intensity detective
```

---

## Troubleshooting

### "Python 3 not found"

```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip

# Fedora/RedHat
sudo dnf install python3 python3-pip

# Alpine
apk add python3 py3-pip

# Arch
pacman -S python python-pip

# macOS
brew install python3
```

### "Permission denied" on script execution

```bash
chmod +x setup.sh run_all.sh setup.py
```

### "sudo password required"

The setup scripts will prompt for sudo when needed. Provide your user password when asked.

### PEP 668 "externally managed environment"

Modern Python installations prevent system-wide pip changes. Solutions:

```bash
# Option 1: Use --user flag (automatic in run_all.sh)
python3 -m pip install --user -r requirements.txt

# Option 2: Break system packages (use with caution)
python3 -m pip install --break-system-packages -r requirements.txt

# Option 3: Use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### "Package not found" errors

Some optional packages may fail on minimal systems:

```bash
# Manual install with fallback
pip3 install bcrypt
pip3 install passlib
pip3 install psutil pyyaml dnspython requests || true

# Continue anyway - framework works without them
```

### "pip: command not found"

Bootstrap pip:

```bash
python3 -m ensurepip --upgrade
python3 -m pip --version
```

### Distro detection failed

Manually specify your distro:

```bash
# Debian/Ubuntu variants
./setup.sh --ubuntu

# Fedora/RedHat variants
./setup.sh --fedora

# Or use Python (auto-detects from PATH)
python3 setup.py --auto
```

### Network/offline installation

If you're offline during setup:

```bash
# Framework works without optional packages
# They'll be installed when you next run with --install
./run_all.sh --install https://example.com
```

### Partial installation succeeded

This is normal. Optional packages may fail, but the core framework works on the standard library alone:

```bash
# Verify what's installed
python3 setup.py --verify-only

# Try installing failed packages later
pip3 install bcrypt passlib psutil pyyaml dnspython requests
```

---

## Uninstallation

### Remove Python packages

```bash
python3 -m pip uninstall -r requirements.txt
```

### Remove all dependencies

To uninstall system packages:

```bash
# Ubuntu/Debian
sudo apt remove python3-pip nmap git curl

# Fedora/RedHat
sudo dnf remove python3-pip nmap git curl

# Alpine
sudo apk del py3-pip nmap git curl

# Arch
sudo pacman -R python-pip nmap git curl
```

### Clean up

```bash
# Remove pip cache
rm -rf ~/.cache/pip

# Remove AttackSim
rm -rf /home/jiha/dev/security/security_test
```

---

## Getting Help

If you encounter issues:

1. **Check logs**: `./run_all.sh --check-deps`
2. **Read error messages**: They often suggest solutions
3. **Try Python setup**: `python3 setup.py --auto`
4. **Manual verification**: Run the bash commands above
5. **Report issue**: Include output of:
   ```bash
   ./run_all.sh --check-deps 2>&1 | head -50
   uname -a
   python3 --version
   ```

---

## Next Steps

After successful installation:

```bash
# Run your first scan
./run_all.sh https://example.com

# Check available modules
./run_all.sh --list-modules

# Run specific module
./run_all.sh https://example.com --only http-infrastructure-mapper

# See all options
./run_all.sh --help
```

---

## Documentation

- **Main README**: [README.md](README.md)
- **Safety Guide**: [docs/safety.md](docs/safety.md)
- **Module Documentation**: [docs/modules.md](docs/modules.md)
- **Quick Start**: [docs/quickstart.md](docs/quickstart.md)

---

**Version:** AttackSim v1.0  
**Last Updated:** 2026-07-26  
**Status:** Production Ready
