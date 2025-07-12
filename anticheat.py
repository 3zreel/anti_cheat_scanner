#python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Anti-Cheat Scanner
Copyright (c) 2025 MT | KHALID
All rights reserved.

This software is the property of MT | KHALID and is protected by copyright laws.
Unauthorized reproduction or distribution of this software is prohibited.

Contact: MT | KHALID
Version: 2.0
"""

import os
import sys
import subprocess
import time
import math
import logging
import platform
import threading
import json
import hashlib
import shutil
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import Tk, Frame, Label, Button, Listbox, Scrollbar, END, messagebox, Toplevel, Text
from tkinter import ttk

# Auto-install dependencies
def install_dependencies():
    """Install required dependencies automatically"""
    required_packages = {
        'requests': 'requests',
        'Pillow': 'PIL',
        'psutil': 'psutil'
    }
    
    # Windows-specific packages
    if platform.system() == "Windows":
        required_packages.update({
            'wmi': 'wmi',
            'pywin32': 'win32api'
        })
    
    missing_packages = []
    for package, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Installing missing dependencies: {', '.join(missing_packages)}")
        for package in missing_packages:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            except subprocess.CalledProcessError as e:
                print(f"Failed to install {package}: {e}")
                sys.exit(1)

# Install dependencies before importing
install_dependencies()

# Import required modules
import requests
from PIL import Image, ImageTk
import psutil

# Platform-specific imports
if platform.system() == "Windows":
    try:
        import wmi
        import winreg
        import win32api
        import win32process
        import win32security
        WINDOWS_AVAILABLE = True
    except ImportError:
        WINDOWS_AVAILABLE = False
        print("Warning: Windows-specific features are not available")
else:
    WINDOWS_AVAILABLE = False

# Configuration and Constants
class Config:
    """Configuration class for the anti-cheat scanner"""
    
    # Application info
    APP_NAME = "Enhanced Anti-Cheat Scanner"
    VERSION = "2.0"
    AUTHOR = "MT | KHALID"
    
    # Logging configuration
    LOG_DIR = os.path.join(os.path.expanduser("~"), ".anticheat_scanner")
    LOG_FILE = os.path.join(LOG_DIR, "anticheat_scanner.log")
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    BACKUP_COUNT = 5
    
    # Discord webhook
    WEBHOOK_URL = "https://canary.discord.com/api/webhooks/1393563844604854282/Hhy9hxtEEO9rbFW7HuO5hEIiLeI3eiCtB7Kcd9oQDqBRwK91g29_iK5QJMP444aRjtto"
    
    # Scan configuration
    SCAN_THREADS = 4
    TIMEOUT_SECONDS = 30
    
    # UI Configuration
    WINDOW_WIDTH = 800
    WINDOW_HEIGHT = 600
    THEME_COLOR = "#2E2E2E"
    ACCENT_COLOR = "#FFB74D"
    TEXT_COLOR = "#F5F5F5"

# Enhanced logging setup
def setup_logging():
    """Setup comprehensive logging system"""
    # Create log directory if it doesn't exist
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    
    # Create rotating file handler
    from logging.handlers import RotatingFileHandler
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        Config.LOG_FILE,
        maxBytes=Config.MAX_LOG_SIZE,
        backupCount=Config.BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log system information
    logger.info(f"=== {Config.APP_NAME} v{Config.VERSION} Started ===")
    logger.info(f"Platform: {platform.system()} {platform.release()}")
    logger.info(f"Python Version: {sys.version}")
    logger.info(f"Architecture: {platform.architecture()[0]}")
    logger.info(f"User: {os.getlogin() if hasattr(os, 'getlogin') else 'Unknown'}")
    
    return logger

# Initialize logging
logger = setup_logging()

# Threat Detection Database
class ThreatDatabase:
    """Comprehensive threat detection database"""
    
    def __init__(self):
        self.suspicious_files = [
            "chromedriver.dll", "notepad.exe", "grandfromsawar.exe",
            "cheatengine.exe", "artmoney.exe", "memoryhacker.exe",
            "speedhack.exe", "gamehack.exe", "trainer.exe",
            "injector.exe", "loader.exe", "bypass.exe"
        ]
        
        self.suspicious_extensions = [
            ".rpf", ".ini", ".cfg", ".dll", ".exe", ".bat", ".cmd",
            ".ps1", ".vbs", ".js", ".jar", ".tmp", ".temp"
        ]
        
        self.suspicious_processes = [
            "cheatengine", "artmoney", "memoryhacker", "speedhack",
            "gamehack", "trainer", "injector", "loader", "bypass",
            "xenos", "extremeinjector", "ollydbg", "x64dbg", "ida",
            "wireshark", "fiddler", "processhacker", "systemexplorer"
        ]
        
        self.spoofer_indicators = [
            "spoof", "hwidspoof", "spotless", "desync", "tracecleaner",
            "rootkit", "trojan", "obfuscator", "stealth", "invisible",
            "ghost", "phantom", "shadow", "hide", "mask"
        ]
        
        self.cheat_loaders = [
            "cheatloader", "injector", "lunarclient", "wurst", "impact",
            "baritone", "meteor", "aristois", "inertia", "future"
        ]
        
        self.memory_modifications = [
            "memoryhack", "debug", "speedhack", "memoryeditor",
            "ramhack", "processhack", "memoryscan", "memoryview"
        ]
        
        self.unauthorized_scripts = [
            "lua", "csharp", "kiddionsmodestmenu", "autohotkey",
            "autoit", "macro", "script", "bot", "automation"
        ]
        
        self.exploit_patterns = [
            "packetmanipulation", "clientsideexploit", "serverexploit",
            "bufferoverflow", "codeinjection", "dllinjection",
            "processhollowing", "reflectivedll", "shellcode"
        ]
        
        self.bypass_tools = [
            "bypass", "hideinjector", "antianticheat", "stealth",
            "invisible", "undetected", "ghost", "phantom"
        ]
        
        self.monitored_registry_paths = [
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            r"SYSTEM\CurrentControlSet\Services\EventLog",
            r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ]
        
        self.monitored_services = [
            "EventLog", "SysMain", "bam", "WinDefend", "MpsSvc",
            "BITS", "wuauserv", "TrustedInstaller"
        ]

# System compatibility checker
class SystemChecker:
    """System compatibility and requirements checker"""
    
    @staticmethod
    def check_python_version():
        """Check if Python version is compatible"""
        if sys.version_info < (3, 6):
            logger.error("Python 3.6 or higher is required")
            messagebox.showerror("Error", "Python 3.6 or higher is required")
            return False
        return True
    
    @staticmethod
    def check_admin_privileges():
        """Check if running with administrative privileges"""
        try:
            if platform.system() == "Windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logger.warning("Not running as administrator - some features may be limited")
                return is_admin
            else:
                return os.geteuid() == 0
        except Exception as e:
            logger.error(f"Error checking admin privileges: {e}")
            return False
    
    @staticmethod
    def check_disk_space():
        """Check available disk space"""
        try:
            if platform.system() == "Windows":
                free_bytes = shutil.disk_usage(Config.LOG_DIR).free
                return free_bytes > 100 * 1024 * 1024
            else:
                statvfs = os.statvfs(Config.LOG_DIR)
                free_space = statvfs.f_frsize * statvfs.f_bavail
                return free_space > 100 * 1024 * 1024
        except Exception as e:
            logger.error(f"Error checking disk space: {e}")
            return True
    
    @staticmethod
    def check_network_connectivity():
        """Check network connectivity for Discord webhook"""
        try:
            response = requests.get("https://httpbin.org/status/200", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Network connectivity check failed: {e}")
            return False

# File analysis utilities
class FileAnalyzer:
    """File analysis and signature verification"""
    
    @staticmethod
    def is_file_signed(file_path):
        """Check if file is digitally signed (Windows only)"""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            import win32api
            import win32security
            
            info = win32api.GetFileVersionInfo(file_path, "\\")
            version = "%d.%d.%d.%d" % (
                info['FileVersionMS'] // 65536,
                info['FileVersionMS'] % 65536,
                info['FileVersionLS'] // 65536,
                info['FileVersionLS'] % 65536
            )
            return len(version) > 0
        except Exception:
            return False
    
    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA256 hash of file"""
        # Skip files in WindowsApps directory
        if "WindowsApps" in file_path:
            logger.info(f"Skipping hash calculation for UWP app file: {file_path}")
            return None
        
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except (PermissionError, OSError) as e:
            logger.warning(f"Unable to calculate hash for {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error calculating hash for {file_path}: {e}")
            return None
    
    @staticmethod
    def get_file_metadata(file_path):
        """Get comprehensive file metadata"""
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime),
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.fromtimestamp(stat.st_atime),
                'hash': FileAnalyzer.calculate_file_hash(file_path),
                'signed': FileAnalyzer.is_file_signed(file_path)
            }
        except Exception as e:
            logger.error(f"Error getting metadata for {file_path}: {e}")
            return None

# Process analysis utilities
class ProcessAnalyzer:
    """Process analysis and monitoring"""
    
    @staticmethod
    def check_memory_modification(process):
        """Check for memory modification indicators"""
        try:
            process_info = psutil.Process(process.pid)
            mem_info = process_info.memory_info()
            
            if mem_info.rss > 1024 * 1024 * 500:
                logger.warning(f"High memory usage detected: {process.info['name']} - {mem_info.rss / (1024*1024):.2f}MB")
                return True
            
            try:
                open_files = process_info.open_files()
                for file_info in open_files:
                    if any(pattern in file_info.path.lower() for pattern in ['temp', 'cache', 'appdata']):
                        return True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return False
        except Exception as e:
            logger.error(f"Error checking memory modification: {e}")
            return False
    
    @staticmethod
    def analyze_process_behavior(process):
        """Analyze process behavior for suspicious patterns"""
        try:
            process_info = psutil.Process(process.pid)
            
            cpu_percent = process_info.cpu_percent(interval=1)
            if cpu_percent > 80:
                logger.warning(f"High CPU usage: {process.info['name']} - {cpu_percent}%")
                return True
            
            try:
                connections = process_info.connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        logger.info(f"Network connection: {process.info['name']} -> {conn.raddr}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return False
        except Exception as e:
            logger.error(f"Error analyzing process behavior: {e}")
            return False

# Registry monitoring (Windows only)
class RegistryMonitor:
    """Windows registry monitoring for suspicious changes"""
    
    def __init__(self):
        self.threat_db = ThreatDatabase()
    
    def monitor_registry_changes(self):
        """Monitor registry for suspicious changes"""
        if not WINDOWS_AVAILABLE:
            logger.info("Registry monitoring not available on this platform")
            return []
        
        suspicious_changes = []
        
        for path in self.threat_db.monitored_registry_paths:
            try:
                if path.startswith("SYSTEM"):
                    root_key = winreg.HKEY_LOCAL_MACHINE
                elif path.startswith("SOFTWARE"):
                    root_key = winreg.HKEY_LOCAL_MACHINE
                else:
                    root_key = winreg.HKEY_CURRENT_USER
                
                key = winreg.OpenKey(root_key, path, 0, winreg.KEY_READ)
                
                try:
                    i = 0
                    while True:
                        name, value, type_id = winreg.EnumValue(key, i)
                        if any(pattern in str(value).lower() for pattern in self.threat_db.spoofer_indicators):
                            suspicious_changes.append({
                                'path': path,
                                'name': name,
                                'value': value,
                                'type': 'Suspicious Registry Value'
                            })
                        i += 1
                except WindowsError:
                    pass
                
                winreg.CloseKey(key)
                logger.info(f"Monitored registry path: {path}")
                
            except WindowsError as e:
                logger.warning(f"Registry key not accessible: {path} - {e}")
                suspicious_changes.append({
                    'path': path,
                    'error': str(e),
                    'type': 'Registry Access Error'
                })
        
        return suspicious_changes

# Discord notification system
class DiscordNotifier:
    """Enhanced Discord notification system"""
    
    def __init__(self):
        self.webhook_url = Config.WEBHOOK_URL
        self.severity_levels = {
            "Spoofer": ("Critical", 0xFF0000),
            "Cheat Loader": ("High", 0xFFA500),
            "Memory Modification": ("High", 0xFFA500),
            "Unauthorized Script": ("Medium", 0xFFFF00),
            "Bypass Tool": ("Critical", 0xFF0000),
            "Service Tampering": ("Medium", 0xFFFF00),
            "Registry Tampering": ("Medium", 0xFFFF00),
            "Suspicious Process": ("Low", 0x00FF00),
            "Unsigned Cheat File": ("Low", 0x00FF00),
            "Network Anomaly": ("Medium", 0xFFA500),
            "File System Anomaly": ("Low", 0x00FF00)
        }
    
    def send_notification(self, scan_results):
        """Send comprehensive scan results to Discord"""
        if not self.webhook_url:
            logger.warning("Discord webhook URL not configured")
            return False
        
        try:
            threat_level = "Clean"
            max_severity = 0
            threat_types = []
            
            for result in scan_results:
                threat_type = result.get('type', 'Unknown')
                threat_types.append(threat_type)
                
                if threat_type in self.severity_levels:
                    severity, color = self.severity_levels[threat_type]
                    if color > max_severity:
                        max_severity = color
                        threat_level = severity
            
            system_info = f"{platform.system()} {platform.release()}"
            username = os.getlogin() if hasattr(os, 'getlogin') else 'Unknown'
            
            embed = {
                "title": f"🛡️ {Config.APP_NAME} - تقرير الفحص",
                "description": f"**فحص النظام مكتمل**\n{'🚨 **تم اكتشاف تهديدات!**' if scan_results else '✅ **النظام نظيف**'}",
                "color": max_severity if max_severity > 0 else 0x00FF00,
                "fields": [
                    {
                        "name": "🔍 ملخص الفحص",
                        "value": f"**التهديدات المكتشفة:** {len(scan_results)}\n**مستوى التهديد:** {threat_level}\n**وقت الفحص:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**النظام:** {system_info}\n**المستخدم:** {username}",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": f"{Config.APP_NAME} v{Config.VERSION} | © {Config.AUTHOR}"
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if scan_results:
                threat_summary = {}
                for result in scan_results:
                    threat_type = result.get('type', 'Unknown')
                    threat_summary[threat_type] = threat_summary.get(threat_type, 0) + 1
                
                threat_details = "\n".join([f"• {t}: {c}" for t, c in threat_summary.items()])
                embed["fields"].append({
                    "name": "⚠️ التهديدات المكتشفة",
                    "value": threat_details,
                    "inline": False
                })
                
                top_threats = scan_results[:5]
                for i, threat in enumerate(top_threats, 1):
                    embed["fields"].append({
                        "name": f"🎯 التهديد #{i}",
                        "value": f"**النوع:** {threat.get('type', 'Unknown')}\n**المسار:** {threat.get('path', 'N/A')}\n**التفاصيل:** {threat.get('details', 'N/A')}",
                        "inline": True
                    })
            
            payload = {"embeds": [embed]}
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Discord notification sent successfully - Status: {response.status_code}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False

# Main scanner class
class AntiCheatScanner:
    """Main anti-cheat scanner with comprehensive threat detection"""
    
    def __init__(self):
        self.threat_db = ThreatDatabase()
        self.file_analyzer = FileAnalyzer()
        self.process_analyzer = ProcessAnalyzer()
        self.registry_monitor = RegistryMonitor()
        self.discord_notifier = DiscordNotifier()
        self.scan_results = []
        self.is_scanning = False
    
    def scan_files(self, base_path=None):
        """Comprehensive file system scan"""
        if not base_path:
            base_path = os.path.expanduser("~")
        
        logger.info(f"Starting file scan in: {base_path}")
        file_threats = []
        
        try:
            for root, dirs, files in os.walk(base_path, onerror=lambda err: logger.warning(f"Error accessing directory {err.filename}: {err}")):
                # Skip system directories and problematic folders to avoid permission issues
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['System32', 'Windows', 'WindowsApps', 'Application Data', 'Cookies', 'History', 'Temporary Internet Files']]
                
                logger.debug(f"Scanning directory: {root}")
                
                for file in files:
                    if not self.is_scanning:
                        logger.info("File scan interrupted by user")
                        break
                    
                    file_path = os.path.join(root, file)
                    file_name = file.lower()
                    
                    try:
                        # Check suspicious files
                        if any(sus_file in file_name for sus_file in self.threat_db.suspicious_files):
                            metadata = self.file_analyzer.get_file_metadata(file_path)
                            file_threats.append({
                                'type': 'Suspicious File',
                                'path': file_path,
                                'details': f"Matches known suspicious file pattern",
                                'metadata': metadata,
                                'severity': 'Medium'
                            })
                            logger.debug(f"Suspicious file detected: {file_path}")
                        
                        # Check file extensions
                        if any(file_name.endswith(ext) for ext in self.threat_db.suspicious_extensions):
                            if not self.file_analyzer.is_file_signed(file_path):
                                file_threats.append({
                                    'type': 'Unsigned Cheat File',
                                    'path': file_path,
                                    'details': f"Unsigned file with suspicious extension",
                                    'severity': 'Low'
                                })
                                logger.debug(f"Unsigned cheat file detected: {file_path}")
                        
                        # Check for spoofer indicators
                        if any(indicator in file_name for indicator in self.threat_db.spoofer_indicators):
                            file_threats.append({
                                'type': 'Spoofer',
                                'path': file_path,
                                'details': f"File name contains spoofer indicators",
                                'severity': 'Critical'
                            })
                            logger.debug(f"Spoofer detected: {file_path}")
                        
                        # Check for cheat loaders
                        if any(loader in file_name for loader in self.threat_db.cheat_loaders):
                            file_threats.append({
                                'type': 'Cheat Loader',
                                'path': file_path,
                                'details': f"Potential cheat loader detected",
                                'severity': 'High'
                            })
                            logger.debug(f"Cheat loader detected: {file_path}")
                    
                    except (PermissionError, OSError) as e:
                        logger.warning(f"Skipping file {file_path}: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Unexpected error processing file {file_path}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error during file scan: {e}")
        
        logger.info(f"File scan completed. Found {len(file_threats)} threats")
        return file_threats
    
    def scan_processes(self):
        """Comprehensive process scan"""
        logger.info("Starting process scan")
        process_threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                if not self.is_scanning:
                    logger.info("Process scan interrupted by user")
                    break
                
                try:
                    proc_name = proc.info['name'].lower()
                    
                    if any(sus_proc in proc_name for sus_proc in self.threat_db.suspicious_processes):
                        process_threats.append({
                            'type': 'Suspicious Process',
                            'path': f"PID: {proc.info['pid']}",
                            'details': f"Process: {proc_name}",
                            'severity': 'Medium',
                            'pid': proc.info['pid']
                        })
                        logger.debug(f"Suspicious process detected: {proc_name} (PID: {proc.info['pid']})")
                    
                    if self.process_analyzer.check_memory_modification(proc):
                        process_threats.append({
                            'type': 'Memory Modification',
                            'path': f"PID: {proc.info['pid']}",
                            'details': f"Suspicious memory usage pattern in {proc_name}",
                            'severity': 'High',
                            'pid': proc.info['pid']
                        })
                        logger.debug(f"Memory modification detected: {proc_name} (PID: {proc.info['pid']})")
                    
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline']).lower()
                        if any(pattern in cmdline for pattern in self.threat_db.exploit_patterns):
                            process_threats.append({
                                'type': 'Exploit Pattern',
                                'path': f"PID: {proc.info['pid']}",
                                'details': f"Suspicious command line arguments",
                                'severity': 'High',
                                'pid': proc.info['pid']
                            })
                            logger.debug(f"Exploit pattern detected: {proc_name} (PID: {proc.info['pid']})")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logger.error(f"Unexpected error processing process PID {proc.info['pid']}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error during process scan: {e}")
        
        logger.info(f"Process scan completed. Found {len(process_threats)} threats")
        return process_threats
    
    def scan_registry(self):
        """Scan registry for suspicious changes"""
        logger.info("Starting registry scan")
        registry_threats = []
        
        try:
            suspicious_changes = self.registry_monitor.monitor_registry_changes()
            for change in suspicious_changes:
                registry_threats.append({
                    'type': 'Registry Tampering',
                    'path': change.get('path', 'Unknown'),
                    'details': f"Suspicious registry modification detected",
                    'severity': 'Medium'
                })
                logger.debug(f"Registry tampering detected: {change.get('path', 'Unknown')}")
        
        except Exception as e:
            logger.error(f"Error during registry scan: {e}")
        
        logger.info(f"Registry scan completed. Found {len(registry_threats)} threats")
        return registry_threats
    
    def perform_comprehensive_scan(self, progress_callback=None):
        """Perform comprehensive system scan"""
        self.is_scanning = True
        self.scan_results = []
        
        try:
            logger.info("Starting comprehensive anti-cheat scan")
            
            if progress_callback:
                progress_callback("جاري فحص الملفات...")
            file_threats = self.scan_files()
            self.scan_results.extend(file_threats)
            
            if progress_callback:
                progress_callback("جاري فحص العمليات...")
            process_threats = self.scan_processes()
            self.scan_results.extend(process_threats)
            
            if WINDOWS_AVAILABLE:
                if progress_callback:
                    progress_callback("جاري فحص السجل...")
                registry_threats = self.scan_registry()
                self.scan_results.extend(registry_threats)
            
            if progress_callback:
                progress_callback("جاري إرسال التقرير...")
            self.discord_notifier.send_notification(self.scan_results)
            
            logger.info(f"Comprehensive scan completed. Total threats found: {len(self.scan_results)}")
            
        except Exception as e:
            logger.error(f"Error during comprehensive scan: {e}")
            if progress_callback:
                progress_callback(f"خطأ أثناء الفحص: {str(e)}")
        finally:
            self.is_scanning = False
        
        return self.scan_results
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        logger.info("Scan stopped by user")

# Enhanced GUI Application
class AntiCheatGUI:
    """Enhanced GUI for the anti-cheat scanner"""
    
    def __init__(self):
        self.root = tk.Tk()  # Initialize main window
        self.scanner = AntiCheatScanner()
        self.splash_root = None
        self.show_splash_screen()
        self.setup_ui()  # Setup UI immediately
        self.check_system_requirements()
        # Delay start_scan until mainloop starts
        self.root.after(100, self.start_scan)  # Schedule start_scan after 100ms
    
    def show_splash_screen(self):
        """Show splash screen with logo and progress indicator"""
        self.splash_root = Toplevel(self.root)  # Use Toplevel instead of Tk
        self.splash_root.title("جاري التحميل...")
        self.splash_root.geometry("400x300")
        self.splash_root.configure(bg=Config.THEME_COLOR)
        self.splash_root.attributes('-topmost', True)

        # Try to load logo (assuming logo.ico exists, or use a placeholder)
        try:
            self.splash_root.iconbitmap("logo.ico")
        except:
            pass

        # Logo or placeholder label
        logo_label = Label(
            self.splash_root,
            text="Enhanced Anti-Cheat Scanner",
            font=("Arial", 16, "bold"),
            fg=Config.ACCENT_COLOR,
            bg=Config.THEME_COLOR
        )
        logo_label.pack(pady=20)

        # Progress label
        self.progress_label = Label(
            self.splash_root,
            text="جاري التحميل...",
            font=("Arial", 12),
            fg=Config.TEXT_COLOR,
            bg=Config.THEME_COLOR
        )
        self.progress_label.pack(pady=10)

        # Progress bar
        self.progress_bar = ttk.Progressbar(
            self.splash_root,
            orient="horizontal",
            length=200,
            mode="indeterminate"
        )
        self.progress_bar.pack(pady=10)
        self.progress_bar.start()

    def show_completion_window(self, results):
        """Show completion window with logo and scan results"""
        # Close splash screen
        if self.splash_root:
            self.splash_root.destroy()
            self.splash_root = None

        # Create completion window
        completion_window = Toplevel(self.root)  # Use self.root as parent
        completion_window.title("اكتمال الفحص")
        completion_window.geometry("400x300")
        completion_window.configure(bg=Config.THEME_COLOR)
        completion_window.attributes('-topmost', True)

        # Try to load logo
        try:
            completion_window.iconbitmap("logo.ico")
        except:
            pass

        # Logo or placeholder label
        logo_label = Label(
            completion_window,
            text="Enhanced Anti-Cheat Scanner",
            font=("Arial", 16, "bold"),
            fg=Config.ACCENT_COLOR,
            bg=Config.THEME_COLOR
        )
        logo_label.pack(pady=20)

        # Completion message
        message = f"اكتمل الفحص!\nعدد التهديدات المكتشفة: {len(results)}"
        completion_label = Label(
            completion_window,
            text=message,
            font=("Arial", 12),
            fg=Config.TEXT_COLOR,
            bg=Config.THEME_COLOR
        )
        completion_label.pack(pady=10)

        # OK button to close
        ok_button = Button(
            completion_window,
            text="موافق",
            font=("Arial", 10, "bold"),
            bg=Config.ACCENT_COLOR,
            fg=Config.TEXT_COLOR,
            command=completion_window.destroy
        )
        ok_button.pack(pady=10)

    def setup_ui(self):
        """Setup the main user interface"""
        self.root.title(f"{Config.APP_NAME} v{Config.VERSION}")
        self.root.geometry(f"{Config.WINDOW_WIDTH}x{Config.WINDOW_HEIGHT}")
        self.root.configure(bg=Config.THEME_COLOR)
        
        try:
            self.root.iconbitmap("logo.ico")
        except:
            pass
        
        header_frame = Frame(self.root, bg=Config.THEME_COLOR)
        header_frame.pack(fill="x", padx=10, pady=5)
        
        title_label = Label(
            header_frame,
            text=Config.APP_NAME,
            font=("Arial", 24, "bold"),
            fg=Config.ACCENT_COLOR,
            bg=Config.THEME_COLOR
        )
        title_label.pack(pady=10)
        
        main_frame = Frame(self.root, bg=Config.THEME_COLOR)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        controls_frame = Frame(main_frame, bg=Config.THEME_COLOR)
        controls_frame.pack(fill="x", pady=5)
        
        self.scan_button = Button(
            controls_frame,
            text="بدء الفحص",
            font=("Arial", 12, "bold"),
            bg=Config.ACCENT_COLOR,
            fg=Config.TEXT_COLOR,
            command=self.start_scan,
            width=15
        )
        self.scan_button.pack(side="left", padx=5)
        
        self.stop_button = Button(
            controls_frame,
            text="إيقاف الفحص",
            font=("Arial", 12, "bold"),
            bg="#FF4444",
            fg=Config.TEXT_COLOR,
            command=self.stop_scan,
            width=15,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
        
        self.progress_label = Label(
            controls_frame,
            text="جاهز للفحص",
            font=("Arial", 10),
            fg=Config.TEXT_COLOR,
            bg=Config.THEME_COLOR
        )
        self.progress_label.pack(side="left", padx=10)
        
        results_frame = Frame(main_frame, bg=Config.THEME_COLOR)
        results_frame.pack(fill="both", expand=True, pady=5)
        
        scrollbar = Scrollbar(results_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.results_listbox = Listbox(
            results_frame,
            font=("Arial", 10),
            fg=Config.TEXT_COLOR,
            bg="#3A3A3A",
            selectbackground=Config.ACCENT_COLOR,
            selectforeground=Config.TEXT_COLOR,
            height=20
        )
        self.results_listbox.pack(fill="both", expand=True)
        self.results_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.results_listbox.yview)
        
        status_frame = Frame(self.root, bg=Config.THEME_COLOR)
        status_frame.pack(fill="x", side="bottom", pady=5)
        
        self.status_label = Label(
            status_frame,
            text=f"Version {Config.VERSION} | © {Config.AUTHOR}",
            font=("Arial", 8),
            fg=Config.TEXT_COLOR,
            bg=Config.THEME_COLOR
        )
        self.status_label.pack(side="left", padx=5)
        
        self.system_status = Label(
            status_frame,
            text="System Ready",
            font=("Arial", 8),
            fg=Config.TEXT_COLOR,
            bg=Config.THEME_COLOR
        )
        self.system_status.pack(side="right", padx=5)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def check_system_requirements(self):
        """Check system requirements and update status"""
        checker = SystemChecker()
        
        if not checker.check_python_version():
            self.system_status.config(text="Error: Incompatible Python version", fg="#FF4444")
            self.scan_button.config(state="disabled")
            if self.splash_root:
                self.splash_root.destroy()
            return
        
        if not checker.check_admin_privileges():
            self.system_status.config(text="Warning: Limited permissions", fg="#FFA500")
        
        if not checker.check_disk_space():
            self.system_status.config(text="Warning: Low disk space", fg="#FFA500")
        
        if not checker.check_network_connectivity():
            self.system_status.config(text="Warning: No network connectivity", fg="#FFA500")
    
    def update_progress(self, message):
        """Update progress label safely using the main thread"""
        if self.splash_root:
            self.root.after(0, lambda: self.progress_label.config(text=message))
        elif self.root:
            self.root.after(0, lambda: self.progress_label.config(text=message))
        logger.info(message)
    
    def start_scan(self):
        """Start the scanning process"""
        if self.scanner.is_scanning:
            return
        
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.results_listbox.delete(0, END)
        self.update_progress("Initializing scan...")
        
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self):
        """Run the comprehensive scan"""
        try:
            results = self.scanner.perform_comprehensive_scan(self.update_progress)
            
            for result in results:
                display_text = f"[{result['severity']}] {result['type']}: {result['path']}"
                self.root.after(0, lambda txt=display_text: self.results_listbox.insert(END, txt))
                
                if result['severity'] == 'Critical':
                    self.root.after(0, lambda: self.results_listbox.itemconfig(END, {'fg': '#FF4444'}))
                elif result['severity'] == 'High':
                    self.root.after(0, lambda: self.results_listbox.itemconfig(END, {'fg': '#FFA500'}))
                elif result['severity'] == 'Medium':
                    self.root.after(0, lambda: self.results_listbox.itemconfig(END, {'fg': '#FFFF00'}))
                else:
                    self.root.after(0, lambda: self.results_listbox.itemconfig(END, {'fg': '#00FF00'}))
            
            status_text = f"Scan completed: {len(results)} threats found"
            self.update_progress(status_text)
            self.root.after(0, lambda: self.system_status.config(
                text=status_text,
                fg="#FF4444" if results else "#00FF00"
            ))
            
            # Show completion window
            self.root.after(0, lambda: self.show_completion_window(results))
        
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.update_progress(f"Error during scan: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
        
        finally:
            self.root.after(0, lambda: self.scan_button.config(state="normal"))
            self.root.after(0, lambda: self.stop_button.config(state="disabled"))
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanner.is_scanning:
            self.scanner.stop_scan()
            self.update_progress("Scan stopped by user")
            self.root.after(0, lambda: self.scan_button.config(state="normal"))
            self.root.after(0, lambda: self.stop_button.config(state="disabled"))
            if self.splash_root:
                self.root.after(0, self.splash_root.destroy)
    
    def on_closing(self):
        """Handle window closing"""
        if self.scanner.is_scanning:
            if messagebox.askyesno("Confirm", "A scan is in progress. Do you want to stop it and exit?"):
                self.scanner.stop_scan()
                self.root.destroy()
                if self.splash_root:
                    self.splash_root.destroy()
        else:
            self.root.destroy()
            if self.splash_root:
                self.splash_root.destroy()
    
    def run(self):
        """Start the GUI main loop"""
        self.root.mainloop()

# Main execution
if __name__ == "__main__":
    try:
        app = AntiCheatGUI()
        app.run()
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        messagebox.showerror("Fatal Error", f"Application failed to start: {str(e)}")
        sys.exit(1)
