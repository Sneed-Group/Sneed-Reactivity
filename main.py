import os
import time
import psutil
import subprocess
import threading
import win32security
import win32process
import winreg
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.service import Service as ChromeService
from pathlib import Path
import requests
import certifi
import getpass
import tensorflow as tf  # TensorFlow for GPU monitoring
import re  # Regular expressions for address detection
import yara  # YARA for malware scanning

critical_processes = [
    "System Idle Process", "System", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "explorer.exe",
    "dwm.exe", "ntoskrnl.exe", "hal.dll", "kernel32.dll", "user32.dll", "WmiPrvSE.exe"
    "kernel_task", "launchd", "loginwindow", "windowserver", "cfprefsd",
    "usernoted", "hidd", "mds", "kernel", "syslogd", "distnoted", "cloudd",
    "securityd", "init", "systemd", "kthreadd", "rcu_sched", "ksoftirqd/0",
    "migration/0", "watchdog/0", "kworker/0:0H", "kdevtmpfs", "netns",
    "khungtaskd", "khelper", "kworker/u2:1", "kswapd0", "fsnotify_mark",
    "systemd-journald", "systemd-logind", "udevd", "dbus-daemon", "sshd",
    "cron", "atd"
]


# YARA Rules
def load_yara_rules():
    yara_rules = []
    yara_dir = Path('yara-ReversingLabs')
    if yara_dir.exists() and yara_dir.is_dir():
        for yara_file in yara_dir.rglob('*.yar'):
            try:
                rule = yara.compile(filepath=str(yara_file))
                yara_rules.append(rule)
            except Exception as e:
                print(f"Error compiling YARA rule {yara_file}: {e}")
    else:
        print(f"YARA rules directory not found: {yara_dir}")
    time.sleep(1)
    yara_dir = Path('yara-mikesxrs')
    if yara_dir.exists() and yara_dir.is_dir():
        for yara_file in yara_dir.rglob('*.yar'):
            try:
                rule = yara.compile(filepath=str(yara_file))
                yara_rules.append(rule)
            except Exception as e:
                print(f"Error compiling YARA rule {yara_file}: {e}")
    else:
        print(f"YARA rules directory not found: {yara_dir}")
    yara_dir = Path('yara-Neo23x0')
    if yara_dir.exists() and yara_dir.is_dir():
        for yara_file in yara_dir.rglob('*.yar'):
            try:
                rule = yara.compile(filepath=str(yara_file))
                yara_rules.append(rule)
            except Exception as e:
                print(f"Error compiling YARA rule {yara_file}: {e}")
    else:
        print(f"YARA rules directory not found: {yara_dir}")
    return yara_rules

yara_rules = load_yara_rules()

# Regular expressions for detecting crypto addresses
# Bitcoin address regex
bitcoin_regex = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", re.IGNORECASE)
# Ethereum address regex
ethereum_regex = re.compile(r"^0x[a-fA-F0-9]{40}$", re.IGNORECASE)
# Monero address regex
monero_regex = re.compile(r"^4[0-9AB][0-9a-f]{93}$", re.IGNORECASE)

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

def does_not_contain_critical_process(file_path):
    """
    Check if the file_path does not contain any of the critical processes in the critical_processes list.

    Parameters:
    - file_path (str): The path of the file to check.
    - critical_processes (list): List of critical process names to check against.

    Returns:
    - bool: True if file_path does not contain any critical process names, False otherwise.
    """
    return all(process not in file_path for process in critical_processes)

# Folders to monitor
def get_folders_to_monitor():
    folders = []

    # Common user directories
    user_dirs = ['Downloads', 'Documents', 'Pictures', 'Videos']
    user_folder = Path.home()
    for folder in user_folder.iterdir():
        if folder.is_dir() and any(d.lower() in folder.name.lower() for d in user_dirs):
            folders.append(str(folder))

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
                #print(f"Loaded exception {line.strip().lower()}!") # FOR DEBUGGING
    return bypassed


# File System Monitoring
class SuspiciousFileHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.event_type in ['created', 'modified', 'deleted']:
            file_owner = get_file_owner(event.src_path)
            current_user = get_current_user()
            if file_owner.lower() not in [current_user.lower(), "trustedinstaller"]:
                print(f"Suspicious file operation: {event.event_type} {event.src_path} by {file_owner}")

def get_file_owner(file_path):
    try:
        # On Windows, use the current user’s name
        if os.name == 'nt':
            sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            owner, _ = win32security.LookupAccountSid(None, owner_sid)
            return owner
        else:
            # On Unix-like systems, use the owner of the file
            import pwd
            file_stat = os.stat(file_path)
            return pwd.getpwuid(file_stat.st_uid).pw_name
    except Exception as e:
        print(f"Error getting file owner: {e}")
        return "Unknown"

def get_current_user():
    return getpass.getuser()

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

def scan_for_malware(file_path):
    if yara_rules:
        for rule in yara_rules:
            matches = rule.match(filepath=file_path)
            if matches and does_not_contain_critical_process(file_path):
                return True
    return False

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
            kill_suspicious_processes()
        
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
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name'].lower()
            cmdline = []

            # Attempt to get command line arguments
            try:
                cmdline = proc.cmdline()
            except psutil.AccessDenied:
                # Fallback for access denied
                print(f"Access denied getting CLI args for process {proc.info['name']} (PID: {proc.info['pid']})")
                continue

            cmdline_str = " ".join(cmdline).lower()
            bypassed_processes = load_bypassed_processes()

            if proc_name in mining_processes and proc_name not in bypassed_processes and proc_name not in critical_processes:
                print(f"Terminating suspicious mining process: {proc.info['name']} (PID: {proc.info['pid']})")
                proc.terminate()
                proc.wait()

            # Check for crypto addresses in command line arguments
            if (bitcoin_regex.search(cmdline_str) or
                ethereum_regex.search(cmdline_str) or
                monero_regex.search(cmdline_str)) and proc_name not in bypassed_processes and proc_name not in critical_processes:
                print(f"Terminating process with crypto address: {proc.info['name']} (PID: {proc.info['pid']}) due to {cmdline_str}.")
                proc.terminate()
                proc.wait()

            # Scan files for malware as they launch and kill if potentially malicious.
            for file_path in cmdline:
                if os.path.isfile(file_path):
                    if scan_for_malware(file_path) and proc_name not in bypassed_processes and proc_name not in critical_processes:
                        print(f"Terminating potentially malicious process {proc.info['name']}  (PID: {proc.info['pid']}) NOW...")
                        proc.terminate()
                        proc.wait()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Error terminating process: {e}")

# Monitor Registry Changes (Windows)
def monitor_registry_changes():
    reg_path = r"Software\Microsoft\Windows\CurrentVersion"
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
        while True:
            try:
                for i in range(winreg.QueryInfoKey(registry_key)[1]):  # Number of subkeys
                    subkey_name = winreg.EnumKey(registry_key, i)
                    print(f"Registry subkey detected: {subkey_name}")

                time.sleep(10)
            except WindowsError as e:
                print(f"Registry monitoring error: {e}")

    finally:
        winreg.CloseKey(registry_key)

# Verify TLS Certificates
def verify_tls_cert(url):
    try:
        response = requests.get(url, verify=certifi.where())
        print(f"TLS certificate valid for {url}")
    except requests.exceptions.SSLError as e:
        print(f"TLS certificate error for {url}: {e}")

def monitor_tls_certificates():
    urls = monitored_urls
    while True:
        for url in urls:
            verify_tls_cert(url)
        time.sleep(60)  # Check every minute

# Detecting Suspicious Browser Activity
def monitor_browser(browser='chrome'):
    if browser == 'chrome':
        driver = setup_chrome_driver()
    elif browser == 'firefox':
        driver = setup_firefox_driver()
    else:
        raise ValueError("Unsupported browser!")
    bypassed_processes = load_bypassed_processes()  # Load bypassed processes
    
    while True:
        try:
            logs = driver.get_log('performance')
            for entry in logs:
                for url in monitored_urls:
                    if url in entry['message']:
                        print(f'Alert: Potential cookie or token theft attempt detected on {url}!')

                        # Kill process involved in suspicious browser activity
                        for proc in psutil.process_iter(['pid', 'name', 'connections']):
                            try:
                                if any(url in conn.raddr for conn in proc.info['connections']):
                                    if proc.info['name'].lower() not in bypassed_processes and proc.info['name'].lower() not in critical_processes:
                                        print(f'Alert: Killing suspicious process {proc.info["name"]} (PID: {proc.info["pid"]})')
                                        proc.terminate()
                                        proc.wait()
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                # Handle the case where process info is not accessible
                                continue
        except Exception as e:
            print(f"Exception while monitoring browser behavior - {e}")
        time.sleep(1)

    driver.quit()

# Setup Chrome and Firefox Drivers
def setup_chrome_driver():
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--enable-logging") # Enable logging
    chrome_options.add_argument("--v=1")  # Adjust verbosity level if needed
    chrome_options.add_argument("--auto-open-devtools-for-tabs") # Open Dev Tools
    service = ChromeService()
    return webdriver.Chrome(service=service, options=options)

def setup_firefox_driver():
    options = webdriver.FirefoxOptions()
    options.add_argument("--headless")  # Run in headless mode
    service = FirefoxService()
    return webdriver.Firefox(service=service, options=options)

def realtimeAV():
    while True:
        print(f"Realtime AntiMalware active")
        try:
            kill_suspicious_processes()
        except:
            print("Realtime AntiMalware error. :()")
        time.sleep(1) # check for malware every second

def threadCounter():
    previous_count = 0
    current_count = 0
    while True:
        previous_count = threading.active_count()
        print(f"Active AntiMalware Threads: {current_count}")
        if current_count > previous_count and current_count - previous_count > -1:
            print("WARNING: THREAD KILL DETECTED!")
        time.sleep(3) # check for malware every second
        current_count = threading.active_count()

# Start Monitoring in Threads
threads = [
    threading.Thread(target=start_file_system_monitor),
    threading.Thread(target=monitor_cpu_gpu_usage),
    threading.Thread(target=monitor_registry_changes),
    threading.Thread(target=realtimeAV),
    threading.Thread(target=threadCounter),
    threading.Thread(target=monitor_tls_certificates),
    threading.Thread(target=monitor_browser, args=('chrome',)),
    threading.Thread(target=monitor_browser, args=('firefox',))
]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()
