import os
import time
import psutil
import subprocess
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from pathlib import Path

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

# File System Monitoring
class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(('.doc', '.docx', '.png', '.pdf')):
            print(f'Alert: {event.src_path} was modified!')

            # Kill process modifying the file
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                if any(file.path == event.src_path for file in proc.info['open_files']):
                    if proc.info['name'].lower() not in bypassed_processes:
                        print(f'Alert: Killing suspicious process {proc.info["name"]} (PID: {proc.info["pid"]})')
                        proc.terminate()
                        proc.wait()

def start_file_system_monitor():
    observer = Observer()
    event_handler = MonitorHandler()
    for folder in get_folders_to_monitor():
        observer.schedule(event_handler, path=folder, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Network Activity Monitoring
def monitor_network():
    while True:
        connections = psutil.net_connections()
        for conn in connections:
            if conn.raddr and conn.raddr.port in [25, 587, 6667]:  # SMTP, IRC ports
                print(f'Alert: Suspicious network activity detected: {conn}')

                # Kill process involved in suspicious network activity
                for proc in psutil.process_iter(['pid', 'name', 'connections']):
                    if any(conn.raddr and conn.raddr.port in [25, 587, 6667] for conn in proc.info['connections']):
                        if proc.info['name'].lower() not in bypassed_processes:
                            print(f'Alert: Killing suspicious process {proc.info["name"]} (PID: {proc.info["pid"]})')
                            proc.terminate()
                            proc.wait()
        time.sleep(1)

# Access Control and Sandboxing
def restrict_permissions_unix():
    important_files = [str(Path.home() / d / '*') for d in ['Downloads', 'Documents', 'Pictures', 'Videos']]
    for file in important_files:
        subprocess.run(['chmod', 'o-rwx', file])
        subprocess.run(['chattr', '+i', file])

def restrict_permissions_windows():
    import win32api
    import win32security
    import ntsecuritycon as con

    important_files = [str(Path.home() / d / '*') for d in ['Downloads', 'Documents', 'Pictures', 'Videos']]
    for file in important_files:
        sd = win32security.GetFileSecurity(file, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        user, domain, type = win32security.LookupAccountName("", "Everyone")
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(file, win32security.DACL_SECURITY_INFORMATION, sd)

if os.name != 'nt':
    restrict_permissions_unix()
else:
    restrict_permissions_windows()

# Detecting and Preventing Cookie and Token Theft (Chrome and Firefox)
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

# Load bypassed processes
bypassed_processes = load_bypassed_processes()

# Start Monitoring in Threads
threads = [
    threading.Thread(target=start_file_system_monitor),
    threading.Thread(target=monitor_network),
    threading.Thread(target=monitor_browser, args=('chrome',)),
    threading.Thread(target=monitor_browser, args=('firefox',))
]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()
