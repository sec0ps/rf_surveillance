#!/usr/bin/env python3
# =============================================================================
# RF Scanner Detection System - Passive RF Surveillance Detection
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This module is part of the RF Scanner Detection System, designed to
#          passively identify unauthorized radio frequency scanning and monitoring
#          activities using HackRF One SDR hardware. It provides real-time detection
#          of sequential scanning, random scanning, targeted monitoring, and active
#          RF probes across VHF, UHF, and ISM frequency bands for defensive
#          cybersecurity operations and communications security (COMSEC) protection.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# LEGAL NOTICE: This system is designed for authorized security operations and
#               legitimate RF monitoring only. Users must ensure compliance with
#               local laws and regulations regarding radio frequency monitoring
#               and electronic surveillance before deployment.
#
# =============================================================================

import os
import sys
import subprocess
import platform
import json
import shutil
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import tempfile
import logging

class RFScannerInstaller:
    """Advanced installer for RF Scanner Detection System"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.os_version = platform.version()
        self.python_version = sys.version_info
        self.install_log = "rf_installer.log"
        self.requirements_file = "requirements.txt"
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.install_log),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Package definitions
        self.system_packages = {
            'ubuntu': [
                'gnuradio', 'gnuradio-dev', 'gr-osmosdr', 'hackrf', 
                'libhackrf-dev', 'hackrf-tools', 'git', 'python3-pip',
                'python3-dev', 'build-essential', 'cmake', 'pkg-config',
                'libusb-1.0-0-dev', 'libudev-dev'
            ],
            'debian': [
                'gnuradio', 'gnuradio-dev', 'gr-osmosdr', 'hackrf',
                'libhackrf-dev', 'hackrf-tools', 'git', 'python3-pip',
                'python3-dev', 'build-essential', 'cmake', 'pkg-config',
                'libusb-1.0-0-dev', 'libudev-dev'
            ],
            'fedora': [
                'gnuradio', 'gnuradio-devel', 'gr-osmosdr', 'hackrf',
                'hackrf-devel', 'git', 'python3-pip', 'python3-devel',
                'gcc', 'gcc-c++', 'make', 'cmake', 'pkgconfig',
                'libusb1-devel', 'systemd-devel'
            ],
            'darwin': [  # macOS via Homebrew
                'gnuradio', 'hackrf', 'git', 'python3'
            ]
        }

        self.python_packages = [
            'numpy>=1.21.0',
            'scipy>=1.7.0', 
            'matplotlib>=3.5.0',
            'pandas>=1.3.0',
            'scikit-learn>=1.0.0',
            'seaborn>=0.11.0',
            'requests>=2.25.0',
            'psutil>=5.8.0',
            'packaging>=21.0'  # ADD THIS - needed for version checking
        ]
    
    def check_prerequisites(self) -> Dict:
        """Check system prerequisites"""
        
        self.logger.info("Checking system prerequisites...")
        
        results = {
            'os_supported': False,
            'python_compatible': False,
            'internet_available': False,
            'sudo_available': False,
            'git_available': False
        }
        
        # Check OS support
        if self.os_type in ['linux', 'darwin']:
            results['os_supported'] = True
            self.logger.info(f"? OS supported: {platform.platform()}")
        else:
            self.logger.error(f"? Unsupported OS: {self.os_type}")
        
        # Check Python version
        if self.python_version >= (3, 8):
            results['python_compatible'] = True
            self.logger.info(f"? Python compatible: {sys.version}")
        else:
            self.logger.error(f"? Python 3.8+ required, found: {sys.version}")
        
        # Check internet connectivity
        try:
            urllib.request.urlopen('https://github.com', timeout=10)
            results['internet_available'] = True
            self.logger.info("? Internet connectivity available")
        except urllib.error.URLError:
            self.logger.error("? Internet connectivity required")
        
        # Check sudo availability (Linux only)
        if self.os_type == 'linux':
            try:
                subprocess.run(['sudo', '-n', 'true'], check=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                results['sudo_available'] = True
                self.logger.info("? Sudo privileges available")
            except subprocess.CalledProcessError:
                self.logger.warning("? Sudo may be required for installation")
        else:
            results['sudo_available'] = True  # Not needed for macOS with Homebrew
        
        # Check git availability
        try:
            subprocess.run(['git', '--version'], check=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            results['git_available'] = True
            self.logger.info("? Git is available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.warning("? Git will be installed during setup")
        
        return results
    
    def detect_linux_distribution(self) -> Optional[str]:
        """Detect specific Linux distribution"""
        
        if self.os_type != 'linux':
            return None
        
        try:
            # Try /etc/os-release first
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('ID='):
                            distro = line.split('=')[1].strip().strip('"')
                            return distro.lower()
            
            # Fallback methods
            if shutil.which('lsb_release'):
                result = subprocess.run(['lsb_release', '-si'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.strip().lower()
            
            # Check for specific distribution files
            distro_files = {
                '/etc/ubuntu-release': 'ubuntu',
                '/etc/debian_version': 'debian',
                '/etc/fedora-release': 'fedora',
                '/etc/centos-release': 'centos',
                '/etc/redhat-release': 'rhel'
            }
            
            for file_path, distro_name in distro_files.items():
                if os.path.exists(file_path):
                    return distro_name
                    
        except Exception as e:
            self.logger.error(f"Error detecting Linux distribution: {e}")
        
        return None
    
    def install_system_packages(self) -> bool:
        """Install system packages based on OS"""
        
        self.logger.info("Installing system packages...")
        
        try:
            if self.os_type == 'linux':
                distro = self.detect_linux_distribution()
                
                if distro in ['ubuntu', 'debian']:
                    return self._install_apt_packages()
                elif distro == 'fedora':
                    return self._install_dnf_packages()
                elif distro in ['centos', 'rhel']:
                    return self._install_yum_packages()
                elif distro == 'arch':
                    return self._install_pacman_packages()
                else:
                    self.logger.error(f"Unsupported Linux distribution: {distro}")
                    return False
                    
            elif self.os_type == 'darwin':
                return self._install_homebrew_packages()
            else:
                self.logger.error(f"Unsupported OS: {self.os_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"System package installation failed: {e}")
            return False
    
    def _install_apt_packages(self) -> bool:
        """Install packages using apt (Ubuntu/Debian)"""
        
        packages = self.system_packages['ubuntu']
        
        try:
            # Update package list
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            
            # Install packages
            cmd = ['sudo', 'apt', 'install', '-y'] + packages
            subprocess.run(cmd, check=True)
            
            self.logger.info("APT packages installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"APT installation failed: {e}")
            return False
    
    def _install_dnf_packages(self) -> bool:
        """Install packages using dnf (Fedora)"""
        
        packages = self.system_packages['fedora']
        
        try:
            subprocess.run(['sudo', 'dnf', 'update', '-y'], check=True)
            cmd = ['sudo', 'dnf', 'install', '-y'] + packages
            subprocess.run(cmd, check=True)
            
            self.logger.info("DNF packages installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"DNF installation failed: {e}")
            return False
    
    def _install_yum_packages(self) -> bool:
        """Install packages using yum (CentOS/RHEL)"""
        
        try:
            # Enable EPEL repository
            subprocess.run(['sudo', 'yum', 'install', '-y', 'epel-release'], 
                         check=True)
            
            packages = self.system_packages.get('fedora', [])  # Use Fedora package list
            cmd = ['sudo', 'yum', 'install', '-y'] + packages
            subprocess.run(cmd, check=True)
            
            self.logger.info("YUM packages installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"YUM installation failed: {e}")
            return False
    
    def _install_pacman_packages(self) -> bool:
        """Install packages using pacman (Arch Linux)"""
        
        packages = ['gnuradio', 'gnuradio-osmosdr', 'hackrf', 'git', 'python-pip', 'base-devel']
        
        try:
            subprocess.run(['sudo', 'pacman', '-Sy', '--noconfirm'] + packages, check=True)
            
            self.logger.info("Pacman packages installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Pacman installation failed: {e}")
            return False
    
    def _install_homebrew_packages(self) -> bool:
        """Install packages using Homebrew (macOS)"""
        
        try:
            # Check if Homebrew is installed
            if not shutil.which('brew'):
                self.logger.info("Installing Homebrew...")
                install_script = urllib.request.urlopen(
                    'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh'
                ).read().decode('utf-8')
                
                subprocess.run(['/bin/bash', '-c', install_script], check=True)
            
            # Update Homebrew
            subprocess.run(['brew', 'update'], check=True)
            
            # Install packages
            packages = self.system_packages['darwin']
            subprocess.run(['brew', 'install'] + packages, check=True)
            
            self.logger.info("Homebrew packages installed successfully")
            return True
            
        except (subprocess.CalledProcessError, urllib.error.URLError) as e:
            self.logger.error(f"Homebrew installation failed: {e}")
            return False
    
    def create_requirements_file(self):
        """Create requirements.txt file"""
        
        try:
            with open(self.requirements_file, 'w') as f:
                for package in self.python_packages:
                    f.write(f"{package}\n")
            
            self.logger.info(f"Created {self.requirements_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to create requirements file: {e}")
    
    def install_python_packages(self) -> bool:
        """Install Python packages"""
        
        self.logger.info("Installing Python packages...")
        
        try:
            # Create requirements file
            self.create_requirements_file()
            
            # Upgrade pip first
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                         check=True)
            
            # Install packages
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', self.requirements_file], 
                         check=True)
            
            self.logger.info("Python packages installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Python package installation failed: {e}")
            return False
    
    def configure_hackrf_permissions(self) -> bool:
        """Configure HackRF permissions (Linux only)"""
        
        if self.os_type != 'linux':
            return True  # Not needed for macOS
        
        self.logger.info("Configuring HackRF permissions...")
        
        try:
            # Add user to plugdev group
            username = os.getenv('USER')
            if username:
                subprocess.run(['sudo', 'usermod', '-a', '-G', 'plugdev', username], 
                             check=True)
                self.logger.info(f"Added {username} to plugdev group")
            
            # Create udev rules
            udev_rules = """# HackRF One
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", GROUP="plugdev", MODE="0664"
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="604b", GROUP="plugdev", MODE="0664"
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="cc15", GROUP="plugdev", MODE="0664"
"""
            
            udev_file = '/etc/udev/rules.d/53-hackrf.rules'
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                tmp.write(udev_rules)
                tmp_path = tmp.name
            
            subprocess.run(['sudo', 'cp', tmp_path, udev_file], check=True)
            os.unlink(tmp_path)
            
            # Reload udev rules
            subprocess.run(['sudo', 'udevadm', 'control', '--reload-rules'], check=True)
            subprocess.run(['sudo', 'udevadm', 'trigger'], check=True)
            
            self.logger.info("HackRF permissions configured")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Permission configuration failed: {e}")
            return False
    
    def test_installation(self) -> Dict:
        """Test the installation"""
        
        self.logger.info("Testing installation...")
        
        tests = {
            'python_deps': self._test_python_dependencies(),
            'gnuradio': self._test_gnuradio(),
            'hackrf': self._test_hackrf(),
            'osmosdr': self._test_osmosdr()
        }
        
        passed_tests = sum(tests.values())
        total_tests = len(tests)
        
        self.logger.info(f"Test results: {passed_tests}/{total_tests} passed")
        
        return {
            'tests': tests,
            'passed': passed_tests,
            'total': total_tests,
            'success': passed_tests == total_tests
        }

    def _test_python_dependencies(self) -> bool:
        """Test Python dependencies"""
        
        try:
            modules = ['numpy', 'scipy', 'matplotlib', 'pandas', 'sklearn', 'requests']
            
            for module in modules:
                __import__(module)
            
            self.logger.info("? Python dependencies working")
            return True
            
        except ImportError as e:
            self.logger.error(f"? Python dependency failed: {e}")
            return False
    
    def _test_gnuradio(self) -> bool:
        """Test GNU Radio installation"""
        
        try:
            import gnuradio
            version = gnuradio.version()
            self.logger.info(f"? GNU Radio working (version: {version})")
            return True
            
        except ImportError as e:
            self.logger.error(f"? GNU Radio import failed: {e}")
            return False
    
    def _test_osmosdr(self) -> bool:
        """Test osmosdr module"""
        
        try:
            import osmosdr
            self.logger.info("? osmosdr module working")
            return True
            
        except ImportError as e:
            self.logger.error(f"? osmosdr import failed: {e}")
            return False
    
    def _test_hackrf(self) -> bool:
        """Test HackRF connectivity"""
        
        try:
            result = subprocess.run(['hackrf_info'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and 'Found HackRF' in result.stdout:
                self.logger.info("? HackRF device detected")
                return True
            else:
                self.logger.warning("? HackRF command works but no device detected")
                return False
                
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.error("? HackRF test failed")
            return False
    
    def create_desktop_entry(self):
        """Create desktop entry for easy launching (Linux only)"""
        
        if self.os_type != 'linux':
            return
        
        try:
            desktop_dir = Path.home() / '.local' / 'share' / 'applications'
            desktop_dir.mkdir(parents=True, exist_ok=True)
            
            desktop_content = f"""[Desktop Entry]
Name=RF Scanner Detection
Comment=Passive RF surveillance detection system
Exec={sys.executable} {os.path.abspath('rf_scanner_detection.py')}
Icon=radio
Terminal=true
Type=Application
Categories=Network;Security;
"""
            
            desktop_file = desktop_dir / 'rf-scanner-detection.desktop'
            with open(desktop_file, 'w') as f:
                f.write(desktop_content)
            
            os.chmod(desktop_file, 0o755)
            self.logger.info("Desktop entry created")
            
        except Exception as e:
            self.logger.warning(f"Failed to create desktop entry: {e}")
    
    def install_system(self) -> bool:
        """Main installation process"""
        
        self.logger.info("Starting RF Scanner Detection System installation...")
        
        # Check prerequisites
        prereq_results = self.check_prerequisites()
        
        failed_prereqs = [k for k, v in prereq_results.items() if not v]
        if failed_prereqs:
            self.logger.error(f"Prerequisites failed: {failed_prereqs}")
            return False
        
        # Install system packages
        if not self.install_system_packages():
            self.logger.error("System package installation failed")
            return False
        
        # Install Python packages
        if not self.install_python_packages():
            self.logger.error("Python package installation failed")
            return False
        
        # Configure HackRF permissions
        if not self.configure_hackrf_permissions():
            self.logger.warning("HackRF permission configuration failed")
        
        # Create desktop entry
        self.create_desktop_entry()
        
        # Test installation
        test_results = self.test_installation()
        
        if test_results['success']:
            self.logger.info("Installation completed successfully!")
            self._show_success_message()
            return True
        else:
            self.logger.error(f"Installation tests failed: {test_results['passed']}/{test_results['total']} passed")
            return False
    
    def _show_success_message(self):
        """Display success message with next steps"""
        
        print("\n" + "="*70)
        print("?? RF SCANNER DETECTION SYSTEM INSTALLATION COMPLETE ??")
        print("="*70)
        print()
        print("Next Steps:")
        print("1. Connect your HackRF One device")
        print("2. Test the system:")
        print(f"   {sys.executable} rf_scanner_detection.py")
        print()
        print("3. Run comprehensive tests:")
        print(f"   {sys.executable} testing_framework.py")
        print()
        print("4. Check for updates:")
        print(f"   {sys.executable} auto_updater.py --check")
        print()
        print("Configuration Files:")
        print("• rf_config.json - System configuration")
        print("• rf_detections.db - Detection database")
        print("• rf_scanner_detection.log - System logs")
        print()
        print("Documentation:")
        print("• README.md - Complete usage guide")
        print(f"• {self.install_log} - Installation log")
        print()
        if self.os_type == 'linux':
            print("IMPORTANT: Log out and back in for HackRF permissions to take effect")
        print()
        print("="*70)

def main():
    """Main installer CLI"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='RF Scanner Detection System Installer')
    parser.add_argument('--install', action='store_true', default=True,
                       help='Install the system (default)')
    parser.add_argument('--test', action='store_true',
                       help='Test current installation')
    parser.add_argument('--check', action='store_true',
                       help='Check prerequisites only')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    installer = RFScannerInstaller()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.check:
        print("Checking prerequisites...")
        results = installer.check_prerequisites()
        
        for test, passed in results.items():
            status = "?" if passed else "?"
            print(f"{status} {test.replace('_', ' ').title()}")
        
        all_passed = all(results.values())
        print(f"\nPrerequisites: {'PASSED' if all_passed else 'FAILED'}")
        sys.exit(0 if all_passed else 1)
    
    elif args.test:
        print("Testing installation...")
        results = installer.test_installation()
        
        for test, passed in results['tests'].items():
            status = "?" if passed else "?"
            print(f"{status} {test.replace('_', ' ').title()}")
        
        print(f"\nTest Results: {results['passed']}/{results['total']} passed")
        sys.exit(0 if results['success'] else 1)
    
    else:
        # Default: install
        print("RF Scanner Detection System Installer")
        print("=====================================")
        print()
        
        # Confirm installation
        response = input("Do you want to install the RF Scanner Detection System? (y/N): ")
        if response.lower() not in ['y', 'yes']:
            print("Installation cancelled")
            sys.exit(0)
        
        success = installer.install_system()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
