import psutil
from agent.mitre_mapper import map_process_to_mitre

WHITELIST = [
    "explorer.exe", "chrome.exe", "firefox.exe", "svchost.exe", "System",
    "cmd.exe", "python.exe", "conhost.exe", "SearchIndexer.exe", "RuntimeBroker.exe"
]

SUSPICIOUS_KEYWORDS = [
    "powershell -enc", "wget", "curl", "certutil", ".bat", ".vbs", ".js",
    "AppData\\Roaming", "\\Temp\\", "\\Downloads\\"
]

def is_suspicious(cmdline):
    cmd = " ".join(cmdline).lower() if cmdline else ""
    return any(keyword in cmd for keyword in SUSPICIOUS_KEYWORDS)

def is_unusual_location(exe_path):
    exe_path = exe_path.lower()
    return any(folder in exe_path for folder in ["\\appdata\\roaming", "\\temp", "\\downloads", "\\usb"])

def scan_suspicious_processes():
    raw_logs = []
    mitre_matches = []
    seen_mitre_keys = set()  # to prevent duplicates

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info['name']
            if name in WHITELIST:
                continue

            cmdline = proc.info['cmdline'] or []
            exe_path = proc.info['exe'] or ""
            pid = proc.info['pid']
            mitre = map_process_to_mitre(name)

            if is_suspicious(cmdline) or is_unusual_location(exe_path) or mitre:
                log = f"{name} (PID: {pid}) from {exe_path} — Cmd: {' '.join(cmdline)}"
                raw_logs.append(log)

                if mitre:
                    key = (name.lower(), mitre)
                    if key not in seen_mitre_keys:
                        seen_mitre_keys.add(key)
                        mitre_matches.append({
                            "process": name,
                            "pid": pid,
                            "command": " ".join(cmdline),
                            "technique": mitre
                        })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return raw_logs, mitre_matches
