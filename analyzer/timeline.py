from agent.collect_logs import collect_logs
from datetime import datetime
from collections import defaultdict

def clean_message(raw):
    """
    Extract meaningful content from raw log.
    """
    if "%%2304" in raw or "0xc000006d" in raw:
        return "Failed login attempt detected"
    elif "cmd.exe" in raw.lower():
        return "Command prompt executed"
    elif "powershell" in raw.lower():
        return "PowerShell activity observed"
    elif "logon" in raw.lower():
        return "User logon event"
    return "Suspicious system activity"

def build_timeline():
    events = collect_logs()
    print(f"[+] Retrieved {len(events)} logs from Security log")

    timeline = []
    seen = set()

    for event in events:
        try:
            raw_text = " ".join(event.StringInserts)
        except Exception as e:
            print("[!] Error parsing:", e)
            raw_text = str(event)

        time = event.TimeGenerated

        if any(keyword in raw_text.lower() for keyword in [
            "logon", "login", "failed", "unauthorized", "access denied",
            "cmd.exe", "powershell", "%%2304", "0xc000006d", "0xc000006e"
        ]):
            summary = clean_message(raw_text)
            key = (summary, time.strftime("%Y-%m-%d %H:%M:%S"))

            if key not in seen:
                timeline.append((summary, time, raw_text))
                seen.add(key)

    # Sort and return only the latest 20
    timeline.sort(key=lambda x: x[1], reverse=True)
    return timeline[:20]
