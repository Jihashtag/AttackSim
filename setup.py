#!/usr/bin/env python3
"""
AttackSim Setup — Python-based dependency installation and verification

This script handles cross-platform dependency installation for:
- Ubuntu/Debian (apt)
- Fedora/RedHat/CentOS (dnf/yum)
- Alpine (apk)
- Arch (pacman)
- openSUSE (zypper)
- macOS (homebrew)

Usage:
    python3 setup.py                # Interactive setup
    python3 setup.py --auto         # Auto-detect distro
    python3 setup.py --verify-only  # Check existing installation
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path
from typing import List, Tuple, Optional

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

def log_info(msg: str):
    """Log information message"""
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")

def log_success(msg: str):
    """Log success message"""
    print(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")

def log_warn(msg: str):
    """Log warning message"""
    print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")

def log_error(msg: str):
    """Log error message and exit"""
    print(f"{Colors.RED}[✗]{Colors.NC} {msg}", file=sys.stderr)
    sys.exit(1)

class PlatformDetector:
    """Detect OS and package manager"""

    def __init__(self):
        self.system = platform.system()
        self.distro = self.detect_distro()
        self.pkg_manager = self.detect_package_manager()

    def detect_distro(self) -> str:
        """Detect Linux distribution"""
        if self.system == "Darwin":
            return "macos"

        if self.system != "Linux":
            return "unknown"

        # Try /etc/os-release first (modern systems)
        os_release = Path("/etc/os-release")
        if os_release.exists():
            for line in os_release.read_text().split('\n'):
                if line.startswith('ID='):
                    return line.split('=')[1].strip('"').lower()

        # Fallback to /etc/issue
        issue = Path("/etc/issue")
        if issue.exists():
            first_line = issue.read_text().split('\n')[0].lower()
            for name in ['ubuntu', 'debian', 'fedora', 'rhel', 'centos', 'alpine', 'arch', 'suse']:
                if name in first_line:
                    return name

        return "unknown"

    def detect_package_manager(self) -> Tuple[str, List[str]]:
        """Detect package manager and return (name, install_command)"""
        managers = {
            'apt': ['apt', 'install', '-y'],
            'dnf': ['dnf', 'install', '-y'],
            'yum': ['yum', 'install', '-y'],
            'apk': ['apk', 'add', '--no-cache'],
            'pacman': ['pacman', '-S', '--noconfirm'],
            'zypper': ['zypper', 'install', '-y'],
            'brew': ['brew', 'install'],
        }

        for mgr, cmd in managers.items():
            if shutil.which(mgr):
                return mgr, cmd

        return None, None

class DependencyInstaller:
    """Install system and Python dependencies"""

    PYTHON_PACKAGES = [
        'bcrypt>=4.0',
        'passlib>=1.7',
        'psutil',
        'pyyaml',
        'dnspython',
        'requests',
    ]

    SYSTEM_PACKAGES = {
        'apt': {
            'python': ['python3', 'python3-pip', 'python3-venv', 'python3-dev'],
            'tools': ['git', 'curl', 'wget', 'nmap', 'dnsutils', 'net-tools'],
        },
        'dnf': {
            'python': ['python3', 'python3-pip', 'python3-devel'],
            'tools': ['git', 'curl', 'wget', 'nmap', 'bind-utils', 'net-tools'],
        },
        'yum': {
            'python': ['python3', 'python3-pip', 'python3-devel'],
            'tools': ['git', 'curl', 'wget', 'nmap', 'bind-utils', 'net-tools'],
        },
        'apk': {
            'python': ['python3', 'py3-pip', 'py3-virtualenv'],
            'tools': ['git', 'curl', 'wget', 'nmap', 'bind-tools', 'iputils'],
        },
        'pacman': {
            'python': ['python', 'python-pip'],
            'tools': ['git', 'curl', 'wget', 'nmap', 'bind-tools', 'net-tools'],
        },
        'zypper': {
            'python': ['python3', 'python3-pip', 'python3-devel'],
            'tools': ['git', 'curl', 'wget', 'nmap', 'bind-tools', 'net-tools'],
        },
        'brew': {
            'python': ['python3'],
            'tools': ['git', 'curl', 'wget', 'nmap'],
        },
    }

    def __init__(self, detector: PlatformDetector, dev_mode: bool = False):
        self.detector = detector
        self.dev_mode = dev_mode

    def install_system_deps(self):
        """Install system-level dependencies"""
        if self.detector.pkg_manager is None:
            log_warn("Could not detect package manager - skipping system dependencies")
            return

        mgr_name, cmd = self.detector.pkg_manager
        packages_dict = self.SYSTEM_PACKAGES.get(mgr_name, {})

        if not packages_dict:
            log_warn(f"No system packages defined for {mgr_name}")
            return

        log_info(f"Installing system dependencies via {mgr_name}...")

        # Install Python
        python_pkgs = packages_dict.get('python', [])
        if python_pkgs:
            log_info(f"Installing Python packages: {', '.join(python_pkgs)}")
            self._run_install(cmd, python_pkgs)

        # Install tools
        tools_pkgs = packages_dict.get('tools', [])
        if tools_pkgs:
            log_info(f"Installing system tools: {', '.join(tools_pkgs)}")
            self._run_install(cmd, tools_pkgs, ignore_errors=True)

    def install_python_deps(self):
        """Install Python packages via pip"""
        log_info("Installing Python packages...")

        # Ensure pip is up to date
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
                capture_output=True,
                check=False
            )
        except Exception as e:
            log_warn(f"Failed to upgrade pip: {e}")

        # Install packages
        for package in self.PYTHON_PACKAGES:
            try:
                subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--quiet', package],
                    check=True,
                    capture_output=True
                )
                log_success(f"Installed {package}")
            except subprocess.CalledProcessError:
                log_warn(f"Failed to install {package} (optional)")

        # Install dev dependencies if requested
        if self.dev_mode:
            dev_packages = ['pytest>=7.0', 'ruff>=0.4', 'mypy>=1.8']
            for package in dev_packages:
                try:
                    subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', '--quiet', package],
                        check=True,
                        capture_output=True
                    )
                    log_success(f"Installed {package}")
                except subprocess.CalledProcessError:
                    log_warn(f"Failed to install {package}")

    def _run_install(self, cmd: List[str], packages: List[str], ignore_errors: bool = False):
        """Run package manager install command"""
        try:
            full_cmd = cmd + packages
            # Use sudo if not already root
            if os.getuid() != 0 and self.detector.system == "Linux":
                full_cmd = ['sudo'] + full_cmd

            subprocess.run(full_cmd, check=True)
            log_success(f"Installed: {', '.join(packages)}")
        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                log_error(f"Failed to install packages: {e}")
            else:
                log_warn(f"Some packages failed to install (optional)")
        except PermissionError:
            log_error("Permission denied - try running with sudo")

class DependencyVerifier:
    """Verify installed dependencies"""

    @staticmethod
    def check_python_version() -> bool:
        """Check Python version (3.9+)"""
        log_info(f"Python version: {sys.version}")

        if sys.version_info < (3, 9):
            log_error(f"Python 3.9+ required (found {sys.version_info.major}.{sys.version_info.minor})")

        log_success("Python version OK")
        return True

    @staticmethod
    def check_python_module(module: str) -> bool:
        """Check if Python module is installed"""
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    @staticmethod
    def verify_all() -> bool:
        """Verify all dependencies"""
        log_info("Verifying dependencies...")

        # Check Python version
        DependencyVerifier.check_python_version()

        # Check Python modules
        modules = ['bcrypt', 'passlib', 'psutil', 'yaml', 'dns', 'requests']
        missing = []

        for module in modules:
            if DependencyVerifier.check_python_module(module):
                log_success(f"Module '{module}' found")
            else:
                log_warn(f"Module '{module}' not found")
                missing.append(module)

        # Check system tools
        tools = ['git', 'curl', 'python3']
        for tool in tools:
            if shutil.which(tool):
                log_success(f"Tool '{tool}' found")
            else:
                log_warn(f"Tool '{tool}' not found")

        if missing:
            log_warn(f"Missing optional modules: {', '.join(missing)}")
            return False

        log_success("All dependencies verified")
        return True

def main():
    """Main setup function"""
    print("")
    print(f"{Colors.BLUE}{'='*50}{Colors.NC}")
    print(f"{Colors.CYAN}   AttackSim Setup & Dependency Installer{Colors.NC}")
    print(f"{Colors.BLUE}{'='*50}{Colors.NC}")
    print("")

    # Parse arguments
    auto_mode = '--auto' in sys.argv
    verify_only = '--verify-only' in sys.argv
    dev_mode = '--dev' in sys.argv

    # Detect platform
    detector = PlatformDetector()
    log_info(f"Detected OS: {detector.system}")
    log_info(f"Detected distro: {detector.distro}")
    if detector.pkg_manager:
        log_info(f"Package manager: {detector.pkg_manager[0]}")
    else:
        log_warn("Could not detect package manager")

    print("")

    # Only verify if requested
    if verify_only:
        success = DependencyVerifier.verify_all()
        sys.exit(0 if success else 1)

    # Interactive mode
    if not auto_mode and len(sys.argv) == 1:
        print("Installation options:")
        print("  1. Install all dependencies")
        print("  2. Verify existing installation")
        print("  3. Exit")
        choice = input("\nSelect option [1]: ").strip() or "1"

        if choice == "2":
            DependencyVerifier.verify_all()
            return
        elif choice == "3":
            return
        elif choice != "1":
            log_error("Invalid choice")

    # Install dependencies
    print("")
    installer = DependencyInstaller(detector, dev_mode=dev_mode)

    if detector.system == "Linux":
        installer.install_system_deps()
    elif detector.system == "Darwin":
        log_info("macOS detected - using Homebrew")
        log_info("Please ensure Homebrew is installed: https://brew.sh")

    print("")
    installer.install_python_deps()

    print("")
    print("Installation complete!")
    print(f"\nYou can now run: {Colors.CYAN}./run_all.sh https://target.com{Colors.NC}")

if __name__ == '__main__':
    main()
