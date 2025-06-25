import win32evtlog

def collect_logs():
    server = 'localhost'
    log_type = 'Security'
    query_flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    handle = win32evtlog.OpenEventLog(server, log_type)

    event_list = []
    while True:
        events = win32evtlog.ReadEventLog(handle, query_flags, 0)
        if not events:
            break
        for event in events:
            if event.EventID == 4625:  # Failed login attempt
                event_list.append(event)
                if len(event_list) >= 50:  # Collect latest 50 failed attempts
                    return event_list
    return event_list
