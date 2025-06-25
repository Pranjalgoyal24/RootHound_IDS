<h1 align="center" id="title">RootHound - Windows Intrusion Detection &amp; Forensics System</h1>

<p id="description">RootHound is a lightweight yet powerful intrusion detection and forensics toolkit built for Windows environments. Designed with cybercrime investigation and security auditing in mind it helps analyze system logs detect suspicious processes identify brute force attacks and correlate threats with the MITRE ATT&amp;CK framework.</p>

  
  
<h2>🧐 Features</h2>

Here're some of the project's best features:

*   1\. Brute Force Detection - Parses Windows Security logs (Event ID 4625) - Detects multiple failed logon attempts - Shows attack IPs and timestamps
*   2\. Suspicious Process Analysis - Scans live system processes - Flags processes from suspicious paths (e.g. AppData Temp) - Detects encoded PowerShell certutil and other known techniques
*   3\. MITRE ATT&CK Mapping - Associates flagged processes with known MITRE TTPs \_Example: \`certutil.exe\` → T1140 - Deobfuscate/Decode\_
*   4\. Activity Timeline - Generates a visual timestamped timeline of critical events (e.g. failed logins command executions)
*   5\. Summary Engine - Creates a human-readable summary based on all collected data \_Example: “Multiple failed logins from IP 192.168.1.10 — Brute force likely”\_

<h2>🛠️ Installation Steps:</h2>

<p>1. Clone the repository</p>

```
git clone https://github.com/yourusername/roothound.git
cd roothound
```

<p>2. Install dependencies</p>

```
pip install -r requirements.txt
```

<p>3. Run the app</p>

```
python app.py
Then open: http://127.0.0.1:5000 in your browser.
```

  
  
<h2>💻 Built with</h2>

Technologies used in the project:

*   Python
*   Flask web framework
*   pywin32 (Windows Event Log access)
*   HTML (Dashboard UI)
*   MITRE ATT&CK Framework Mapping
*   psutil (Process Scanning)

## 📁 Project Structure

```
roothound/
├── app.py                     # Main Flask application to run the dashboard

├── templates/
│   └── dashboard.html         # Frontend dashboard UI for visualizing alerts and logs

├── agent/
│   ├── collect_logs.py        # Retrieves real-time Windows Event Logs (e.g., logon failures)
│   ├── process_scanner.py     # Scans currently running system processes for suspicious behavior
│   └── mitre_mapper.py        # Maps suspicious process names to MITRE ATT&CK techniques

├── analyzer/
│   ├── detect_intrusion.py    # Contains brute force detection logic from collected logs
│   ├── process_analyzer.py    # Combines MITRE detection with process scanning
│   ├── timeline.py            # Builds timeline of system activity and suspicious events
│   └── summary_engine.py      # Generates a human-readable conclusion based on log analysis
```

> 📌 **Explanation**:
- `agent/` – handles data collection from system logs and processes  
- `analyzer/` – contains logic to analyze, detect intrusions, and generate reports  
- `templates/` – contains the HTML structure of the dashboard  
- `app.py` – integrates everything and runs the Flask web server  
