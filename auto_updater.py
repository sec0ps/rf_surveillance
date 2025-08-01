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
import requests
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Tuple
from packaging import version
import tempfile
import shutil

logger = logging.getLogger(__name__)

class AutoUpdater:
    """Automatic update system for RF Scanner Detection"""
    
    def __init__(self, repo_url="https://github.com/sec0ps/rf_surveillance", branch="main"):
        self.repo_url = repo_url
        self.branch = branch
        self.github_api_url = "https://api.github.com/repos/sec0ps/rf_surveillance"
        self.raw_file_base = f"https://raw.githubusercontent.com/sec0ps/rf_surveillance/{branch}"
        self.local_version_file = "version.txt"
        self.backup_dir = "backup_before_update"
        
    def check_for_updates(self) -> Dict:
        """Check if updates are available"""
        
        logger.info("Checking for updates...")
        
        try:
            # Get local version
            local_version = self._get_local_version()
            logger.info(f"Current local version: {local_version}")
            
            # Get remote version
            remote_version = self._get_remote_version()
            if not remote_version:
                return {
                    'update_available': False,
                    'error': 'Unable to fetch remote version'
                }
            
            logger.info(f"Remote version available: {remote_version}")
            
            # Compare versions
            update_available = self._is_newer_version(remote_version, local_version)
            
            return {
                'update_available': update_available,
                'local_version': local_version,
                'remote_version': remote_version,
                'repo_url': self.repo_url
            }
            
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
            return {
                'update_available': False,
                'error': str(e)
            }
    
    def _get_local_version(self) -> str:
        """Get current local version from version.txt"""
        
        try:
            if os.path.exists(self.local_version_file):
                with open(self.local_version_file, 'r') as f:
                    return f.read().strip()
            else:
                logger.warning("Local version.txt not found, assuming version 0.0.0")
                return "0.0.0"
        except Exception as e:
            logger.error(f"Error reading local version: {e}")
            return "0.0.0"
    
    def _get_remote_version(self) -> Optional[str]:
        """Get remote version from GitHub"""
        
        try:
            # Try to get version.txt from GitHub raw content
            version_url = f"{self.raw_file_base}/version.txt"
            
            response = requests.get(version_url, timeout=10)
            response.raise_for_status()
            
            remote_version = response.text.strip()
            return remote_version
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching remote version: {e}")
            
            # Fallback: try to get latest release tag from GitHub API
            try:
                api_url = f"{self.github_api_url}/releases/latest"
                response = requests.get(api_url, timeout=10)
                response.raise_for_status()
                
                release_data = response.json()
                tag_name = release_data.get('tag_name', '').lstrip('v')
                return tag_name if tag_name else None
                
            except requests.exceptions.RequestException as api_e:
                logger.error(f"Error fetching from GitHub API: {api_e}")
                return None
    
    def _is_newer_version(self, remote_ver: str, local_ver: str) -> bool:
        """Compare version strings to determine if update is needed"""
        
        try:
            # Use packaging library for proper version comparison
            return version.parse(remote_ver) > version.parse(local_ver)
        except Exception as e:
            logger.error(f"Error comparing versions: {e}")
            # Fallback: simple string comparison
            return remote_ver != local_ver
    
    def perform_update(self, force_update=False) -> Dict:
        """Perform the actual update process"""
        
        logger.info("Starting update process...")
        
        try:
            # Check if we're in a git repository
            if not self._is_git_repo():
                return {
                    'success': False,
                    'error': 'Not a git repository. Manual installation required.'
                }
            
            # Check for updates unless forcing
            if not force_update:
                update_check = self.check_for_updates()
                if not update_check.get('update_available'):
                    return {
                        'success': True,
                        'message': 'No updates available',
                        'local_version': update_check.get('local_version'),
                        'remote_version': update_check.get('remote_version')
                    }
            
            # Create backup before update
            backup_success = self._create_backup()
            if not backup_success:
                logger.warning("Backup creation failed, but continuing with update")
            
            # Perform git pull
            update_result = self._git_pull_update()
            
            if update_result['success']:
                # Update local version file
                new_version = self._get_remote_version()
                if new_version:
                    self._update_local_version(new_version)
                
                logger.info("Update completed successfully")
                return {
                    'success': True,
                    'message': 'Update completed successfully',
                    'new_version': new_version,
                    'backup_created': backup_success,
                    'backup_location': self.backup_dir if backup_success else None
                }
            else:
                return update_result
                
        except Exception as e:
            logger.error(f"Update failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _is_git_repo(self) -> bool:
        """Check if current directory is a git repository"""
        
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _create_backup(self) -> bool:
        """Create backup of current installation"""
        
        try:
            # Remove old backup if it exists
            if os.path.exists(self.backup_dir):
                shutil.rmtree(self.backup_dir)
            
            # Create new backup directory
            os.makedirs(self.backup_dir)
            
            # Files to backup
            important_files = [
                'rf_scanner_detection.py',
                'rf_advanced_features.py', 
                'testing_framework.py',
                'rf_config.json',
                'version.txt',
                'README.md'
            ]
            
            # Backup important files
            for filename in important_files:
                if os.path.exists(filename):
                    shutil.copy2(filename, self.backup_dir)
            
            # Backup database if it exists
            if os.path.exists('rf_detections.db'):
                shutil.copy2('rf_detections.db', self.backup_dir)
            
            logger.info(f"Backup created in {self.backup_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return False
    
    def _git_pull_update(self) -> Dict:
        """Perform git pull to update code"""
        
        try:
            # Check current branch
            result = subprocess.run(
                ['git', 'branch', '--show-current'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            current_branch = result.stdout.strip()
            logger.info(f"Current branch: {current_branch}")
            
            # Switch to target branch if needed
            if current_branch != self.branch:
                logger.info(f"Switching to branch: {self.branch}")
                result = subprocess.run(
                    ['git', 'checkout', self.branch],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    return {
                        'success': False,
                        'error': f'Failed to switch to branch {self.branch}: {result.stderr}'
                    }
            
            # Perform git pull
            logger.info("Pulling latest changes...")
            result = subprocess.run(
                ['git', 'pull', 'origin', self.branch],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info("Git pull completed successfully")
                return {
                    'success': True,
                    'message': 'Code updated successfully',
                    'git_output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': f'Git pull failed: {result.stderr}',
                    'git_output': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Git operation timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _update_local_version(self, new_version: str):
        """Update local version.txt file"""
        
        try:
            with open(self.local_version_file, 'w') as f:
                f.write(new_version)
            logger.info(f"Updated local version to {new_version}")
        except Exception as e:
            logger.error(f"Failed to update local version file: {e}")
    
    def rollback_update(self) -> Dict:
        """Rollback to previous version from backup"""
        
        logger.info("Starting rollback process...")
        
        try:
            if not os.path.exists(self.backup_dir):
                return {
                    'success': False,
                    'error': 'No backup found for rollback'
                }
            
            # Restore files from backup
            backup_files = os.listdir(self.backup_dir)
            restored_files = []
            
            for filename in backup_files:
                backup_path = os.path.join(self.backup_dir, filename)
                if os.path.isfile(backup_path):
                    shutil.copy2(backup_path, filename)
                    restored_files.append(filename)
            
            logger.info(f"Rollback completed. Restored files: {restored_files}")
            return {
                'success': True,
                'message': 'Rollback completed successfully',
                'restored_files': restored_files
            }
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_update_info(self) -> Dict:
        """Get detailed information about available updates"""
        
        try:
            # Check for updates
            update_check = self.check_for_updates()
            
            if not update_check.get('update_available'):
                return update_check
            
            # Get release notes from GitHub API
            try:
                api_url = f"{self.github_api_url}/releases/latest"
                response = requests.get(api_url, timeout=10)
                response.raise_for_status()
                
                release_data = response.json()
                
                update_check.update({
                    'release_name': release_data.get('name', 'Unknown'),
                    'release_notes': release_data.get('body', 'No release notes available'),
                    'release_date': release_data.get('published_at', 'Unknown'),
                    'download_url': release_data.get('html_url', self.repo_url)
                })
                
            except requests.exceptions.RequestException:
                logger.warning("Could not fetch release information from GitHub API")
            
            # Get commit information
            try:
                commits_url = f"{self.github_api_url}/commits"
                response = requests.get(commits_url, params={'per_page': 5}, timeout=10)
                response.raise_for_status()
                
                commits = response.json()
                recent_commits = []
                
                for commit in commits:
                    recent_commits.append({
                        'sha': commit['sha'][:8],
                        'message': commit['commit']['message'].split('\n')[0],
                        'author': commit['commit']['author']['name'],
                        'date': commit['commit']['author']['date']
                    })
                
                update_check['recent_commits'] = recent_commits
                
            except requests.exceptions.RequestException:
                logger.warning("Could not fetch commit information")
            
            return update_check
            
        except Exception as e:
            logger.error(f"Error getting update info: {e}")
            return {
                'update_available': False,
                'error': str(e)
            }

def check_and_update():
    """Standalone function to check and perform updates"""
    
    updater = AutoUpdater()
    
    # Check for updates
    update_info = updater.get_update_info()
    
    if update_info.get('error'):
        print(f"Error checking for updates: {update_info['error']}")
        return False
    
    if not update_info.get('update_available'):
        print(f"No updates available. Current version: {update_info.get('local_version', 'Unknown')}")
        return True
    
    # Display update information
    print("\n" + "="*60)
    print("UPDATE AVAILABLE")
    print("="*60)
    print(f"Current Version: {update_info.get('local_version', 'Unknown')}")
    print(f"New Version: {update_info.get('remote_version', 'Unknown')}")
    
    if 'release_name' in update_info:
        print(f"Release Name: {update_info['release_name']}")
        print(f"Release Date: {update_info.get('release_date', 'Unknown')}")
    
    if 'recent_commits' in update_info:
        print("\nRecent Changes:")
        for commit in update_info['recent_commits'][:3]:
            print(f"  • {commit['message']} ({commit['sha']})")
    
    if 'release_notes' in update_info and update_info['release_notes']:
        print(f"\nRelease Notes:\n{update_info['release_notes'][:500]}...")
    
    print("="*60)
    
    # Ask user for confirmation
    response = input("\nDo you want to update now? (y/N): ").lower().strip()
    
    if response in ['y', 'yes']:
        print("\nPerforming update...")
        
        # Perform update
        update_result = updater.perform_update()
        
        if update_result['success']:
            print(f"? Update completed successfully!")
            print(f"  New version: {update_result.get('new_version', 'Unknown')}")
            
            if update_result.get('backup_created'):
                print(f"  Backup created: {update_result.get('backup_location')}")
            
            print("\nRestart the application to use the new version.")
            return True
        else:
            print(f"? Update failed: {update_result.get('error', 'Unknown error')}")
            
            # Offer rollback option
            rollback_response = input("\nDo you want to rollback to the previous version? (y/N): ").lower().strip()
            if rollback_response in ['y', 'yes']:
                rollback_result = updater.rollback_update()
                if rollback_result['success']:
                    print("? Rollback completed successfully")
                else:
                    print(f"? Rollback failed: {rollback_result.get('error')}")
            
            return False
    else:
        print("Update cancelled by user")
        return False

def add_updater_to_main_system():
    """Add auto-update functionality to the main RF scanner detection system"""
    
    # This function should be called from the main rf_scanner_detection.py
    # Add this to the RFScannerDetector class
    
    def check_for_updates_on_startup(self):
        """Check for updates when system starts"""
        
        try:
            updater = AutoUpdater()
            update_check = updater.check_for_updates()
            
            if update_check.get('update_available'):
                logger.info(f"Update available: {update_check.get('remote_version')}")
                logger.info("Run 'python auto_updater.py' to update")
            else:
                logger.info(f"System up to date: {update_check.get('local_version')}")
                
        except Exception as e:
            logger.debug(f"Update check failed: {e}")
    
    return check_for_updates_on_startup

# CLI interface
def main():
    """Main CLI interface for the auto-updater"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='RF Scanner Detection Auto-Updater')
    parser.add_argument('--check', action='store_true', help='Check for updates only')
    parser.add_argument('--update', action='store_true', help='Perform update if available')
    parser.add_argument('--force', action='store_true', help='Force update even if versions match')
    parser.add_argument('--rollback', action='store_true', help='Rollback to previous version')
    parser.add_argument('--info', action='store_true', help='Show detailed update information')
    
    args = parser.parse_args()
    
    updater = AutoUpdater()
    
    if args.rollback:
        print("Performing rollback...")
        result = updater.rollback_update()
        if result['success']:
            print("? Rollback completed successfully")
        else:
            print(f"? Rollback failed: {result.get('error')}")
        return
    
    if args.check or args.info:
        if args.info:
            update_info = updater.get_update_info()
        else:
            update_info = updater.check_for_updates()
        
        if update_info.get('error'):
            print(f"Error: {update_info['error']}")
            return
        
        print(f"Local Version: {update_info.get('local_version', 'Unknown')}")
        print(f"Remote Version: {update_info.get('remote_version', 'Unknown')}")
        print(f"Update Available: {'Yes' if update_info.get('update_available') else 'No'}")
        
        if args.info and 'recent_commits' in update_info:
            print("\nRecent Commits:")
            for commit in update_info['recent_commits']:
                print(f"  {commit['sha']}: {commit['message']}")
        
        return
    
    if args.update or args.force:
        result = updater.perform_update(force_update=args.force)
        if result['success']:
            print("? Update completed successfully")
            if 'new_version' in result:
                print(f"  New version: {result['new_version']}")
        else:
            print(f"? Update failed: {result.get('error')}")
        return
    
    # Interactive mode
    check_and_update()

if __name__ == "__main__":
    # Set up logging for standalone usage
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    main()