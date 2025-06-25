# roothound/analyzer/summary_engine.py

def generate_summary(alerts, usb_logs, suspicious_processes, mitre_matches):
    summary = []

    if alerts:
        summary.append(f"Brute-force behavior detected from {len(alerts)} IP(s).")

    if usb_logs:
        summary.append(f"Unusual USB activity detected ({len(usb_logs)} events).")

    if suspicious_processes:
        summary.append(f"{len(suspicious_processes)} suspicious processes found.")

    if mitre_matches:
        techniques = list(set(m['technique'] for m in mitre_matches))
        summary.append(f"MITRE ATT&CK techniques identified: {', '.join(techniques)}")

    if not summary:
        summary.append("No suspicious activity detected.")

    return summary
