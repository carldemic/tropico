import json
import os
import datetime

LOG_DIR = os.getenv("LOG_DIR", "/logs")
os.makedirs(LOG_DIR, exist_ok=True)

def log_event(service, event_type, ip, details):
    log_file = os.path.join(LOG_DIR, f"tropico-{service.lower()}.log")
    log_entry = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "service": service,
        "event_type": event_type,
        "ip": ip,
        "details": details
    }
    with open(log_file, 'a') as log:
        log.write(json.dumps(log_entry) + '\n')
