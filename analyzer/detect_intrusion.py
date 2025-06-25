from agent.collect_logs import collect_logs

def detect_brute_force():
    logs = collect_logs()
    attempts = {}

    for log in logs:
        try:
            if log.EventID == 4625:  # Failed logon event
                ip = "Unknown"
                if log.StringInserts:
                    for s in log.StringInserts:
                        if s.count('.') == 3:
                            ip = s

                time_str = log.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')

                if ip not in attempts:
                    attempts[ip] = []
                attempts[ip].append(time_str)
        except Exception as e:
            print("[!] Error parsing log:", e)

    alerts = []
    for ip, times in attempts.items():
        if len(times) >= 3:
            alerts.append({
                "ip": ip,
                "count": len(times),
                "times": times
            })

    return alerts
