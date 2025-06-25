# roothound/agent/mitre_mapper.py

MITRE_MAP = {
    "cmd.exe": "T1059.003 - Command and Scripting Interpreter: Windows Command Shell",
    "powershell.exe": "T1059.001 - Command and Scripting Interpreter: PowerShell",
    "wmic.exe": "T1047 - Windows Management Instrumentation",
    "certutil.exe": "T1140 - Deobfuscate/Decode Files or Information",
    "rundll32.exe": "T1218.011 - Signed Binary Proxy Execution: Rundll32",
    "regsvr32.exe": "T1218.010 - Signed Binary Proxy Execution: Regsvr32",
    "mshta.exe": "T1218.005 - Signed Binary Proxy Execution: Mshta",
    "tasklist.exe": "T1057 - Process Discovery",
    "whoami.exe": "T1033 - System Owner/User Discovery",
}

def map_process_to_mitre(process_name):
    return MITRE_MAP.get(process_name.lower(), None)
