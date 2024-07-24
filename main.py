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
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from pathlib import Path
import requests
import certifi
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
            current_user = win32security.GetUserName()
            if file_owner.lower() not in [current_user.lower(), "trustedinstaller"]:
                print(f"Suspicious file operation: {event.event_type} {event.src_path} by {file_owner}")

def get_file_owner(file_path):
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        return win32security.LookupAccountSid(None, owner_sid)[0]
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
                memory_free = gpu_details['free']
                usage = (memory_total - memory_free) / memory_total * 100
                return usage
        except Exception as e:
            print(f"Error getting GPU usage: {e}")
    return 0

def kill_suspicious_processes():
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            proc_name = proc.info['name'].lower()
            cmdline = " ".join(proc.info['cmdline']).lower()

            if proc_name in mining_processes and proc_name not in bypassed_processes:
                print(f"Terminating suspicious mining process: {proc.info['name']} (PID: {proc.info['pid']})")
                proc.terminate()
                proc.wait()

            # Check for crypto addresses in command line arguments
            if (bitcoin_regex.search(cmdline) or
                ethereum_regex.search(cmdline) or
                monero_regex.search(cmdline)) and proc_name not in bypassed_processes:
                print(f"Terminating process with crypto address: {proc.info['name']} (PID: {proc.info['pid']})")
                proc.terminate()
                proc.wait()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Error terminating process: {e}")

# Monitor Registry Changes (Windows)
def monitor_registry_changes():
    reg_path = r"Software\Microsoft\Windows\CurrentVersion"
    registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
    
    while True:
        try:
            for i in range(winreg.QueryInfoKey(registry_key)[1]):  # Number of subkeys
                subkey_name = winreg.EnumKey(registry_key, i)
                print(f"Registry subkey detected: {subkey_name}")
            
            time.sleep(10)
        except WindowsError as e:
            print(f"Registry monitoring error: {e}")

    winreg.CloseKey(registry_key)

# Verify TLS Certificates
def verify_tls_cert(url):
    try:
        response = requests.get(url, verify=certifi.where())
        print(f"TLS certificate valid for {url}")
    except requests.exceptions.SSLError as e:
        print(f"TLS certificate error for {url}: {e}")

def monitor_tls_certificates():
    urls = [
        "https://google.com",
        "https://discord.com"
        # Add more URLs as needed
    ]
    while True:
        for url in urls:
            verify_tls_cert(url)
        time.sleep(3600)  # Check every hour

# Detecting Suspicious Browser Activity
def monitor_browser(browser='chrome'):
    if browser == 'chrome':
        caps = DesiredCapabilities.CHROME
        caps['goog:loggingPrefs'] = {'performance': 'ALL'}
        driver = webdriver.Chrome(desired_capabilities=caps)
    elif browser == 'firefox':
        caps = DesiredCapabilities.FIREFOX.copy()
        caps['loggingPrefs'] = {'performance': 'ALL'}
        driver = webdriver.Firefox(desired_capabilities=caps)
    else:
        raise ValueError("Unsupported browser!")

    while True:
        logs = driver.get_log('performance')
        for entry in logs:
            for url in monitored_urls:
                if url in entry['message']:
                    print(f'Alert: Potential cookie or token theft attempt detected on {url}!')

                    # Kill process involved in suspicious browser activity
                    for proc in psutil.process_iter(['pid', 'name', 'connections']):
                        if any(url in conn.raddr for conn in proc.info['connections']):
                            if proc.info['name'].lower() not in bypassed_processes:
                                print(f'Alert: Killing suspicious process {proc.info["name"]} (PID: {proc.info["pid"]})')
                                proc.terminate()
                                proc.wait()
        time.sleep(1)
    driver.quit()

# Start Monitoring in Threads
threads = [
    threading.Thread(target=start_file_system_monitor),
    threading.Thread(target=monitor_cpu_gpu_usage),
    threading.Thread(target=monitor_registry_changes),
    threading.Thread(target=monitor_tls_certificates),
    threading.Thread(target=monitor_browser, args=('chrome',)),
    threading.Thread(target=monitor_browser, args=('firefox',))
]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()
