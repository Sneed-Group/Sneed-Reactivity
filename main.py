import os
import time
import psutil
import subprocess
import threading
import win32security
import winreg
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from pathlib import Path
import requests
import certifi
import getpass
import tensorflow as tf  # TensorFlow for GPU monitoring
import re  # Regular expressions for address detection

# Regular expressions for detecting crypto addresses
bitcoin_regex = re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', re.IGNORECASE)
ethereum_regex = re.compile(r'0x[a-fA-F0-9]{40}', re.IGNORECASE)
monero_regex = re.compile(r'4[AB][A-Za-z0-9]{93}', re.IGNORECASE)

# Monitored URLs
monitored_urls = [
    "https://discord.com",
    "https://discordapp.com",
    "https://google.com",
    "https://mail.google.com",
    "https://play.google.com",
    "https://drive.google.com",
    "https://minecraft.net",
    "https://github.com",
    "https://roblox.com",
    "https://microsoft.com",
    "https://hotmail.com"
]

# Updated list of known mining processes
mining_processes = [
    "xmrig.exe",
    "bfgminer.exe",
    "cgminer.exe",
    "ethminer.exe",
    "nicehash.exe",
    "miner.exe",
    "miner",
    "xmrig",
    "bfgminer",
    "cgminer",
    "ethminer",
    "nicehash"
]

# Folders to monitor
def get_folders_to_monitor():
    folders = []

    # Common user directories
    user_dirs = ['Downloads', 'Documents', 'Pictures', 'Videos']
    for d in user_dirs:
        user_folder = Path.home() / d
        if user_folder.exists():
            folders.append(str(user_folder))

    # System directories
    if os.name == 'nt':  # Windows
        system_dirs = [
            'C:\\Program Files', 'C:\\Windows', 'C:\\Program Files (x86)'
        ]
    else:  # Unix-like (Linux, macOS)
        system_dirs = [
            '/usr/bin', '/bin', '/usr/sbin'
        ]

    folders.extend(system_dirs)
    return folders

# Load bypassed processes
def load_bypassed_processes():
    bypassed = set()
    if os.path.exists("bypassed.txt"):
        with open("bypassed.txt", "r") as f:
            for line in f:
                bypassed.add(line.strip().lower())
    return bypassed

bypassed_processes = load_bypassed_processes()

# File System Monitoring
class SuspiciousFileHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.event_type in ['created', 'modified', 'deleted']:
            file_owner = get_file_owner(event.src_path)
            current_user = getpass.getuser()  # Get current user
            if file_owner.lower() not in [current_user.lower(), "trustedinstaller"]:
                print(f"Suspicious file operation: {event.event_type} {event.src_path} by {file_owner}")

def get_file_owner(file_path):
    try:
        if os.name == 'nt':  # Windows
            sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            owner, _ = win32security.LookupAccountSid(None, owner_sid)
            return owner
        else:  # Unix-like systems
            import pwd
            file_stat = os.stat(file_path)
            return pwd.getpwuid(file_stat.st_uid).pw_name
    except Exception as e:
        print(f"Error getting file owner: {e}")
        return "Unknown"

def start_file_system_monitor():
    observer = Observer()
    event_handler = SuspiciousFileHandler()
    for folder in get_folders_to_monitor():
        observer.schedule(event_handler, path=folder, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Detect Excessive CPU Workloads
def monitor_cpu_gpu_usage():
    while True:
        cpu_percent = psutil.cpu_percent(interval=1)
        gpu_usage = get_gpu_usage()

        if cpu_percent > 80 and gpu_usage < 10:
            print("Warning: High CPU usage detected with low GPU usage.")
            kill_suspicious_processes()
        
        if gpu_usage > 80 and cpu_percent < 10:
            print("Warning: High GPU usage detected with low CPU usage.")
        
        time.sleep(5)

def get_gpu_usage():
    gpus = tf.config.list_physical_devices('GPU')
    if gpus:
        try:
            # Check GPU memory usage
            for gpu in gpus:
                gpu_details = tf.config.experimental.get_memory_info(gpu.name)
                memory_total = gpu_details['total']
                memory_free = gpu_detai
