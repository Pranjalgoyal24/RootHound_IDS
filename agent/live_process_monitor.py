import psutil
import time

SUSPICIOUS_KEYWORDS = ['mimikatz', 'keylogger', 'backdoor', 'meterpreter', 'hacktool']

def monitor_processes(interval=5):
    seen = set()

    while True:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                exe = proc.info.get('exe', '')

                identifier = (pid, name)
                if identifier not in seen:
                    seen.add(identifier)

                    # Check if suspicious
                    if any(keyword in name.lower() for keyword in SUSPICIOUS_KEYWORDS):
                        print(f"[ Suspicious Process] {name} (PID: {pid}) — Executable: {exe}")
                    elif 'temp' in exe.lower() or 'appdata' in exe.lower():
                        print(f"[ Unusual Path] {name} (PID: {pid}) — {exe}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(interval)
