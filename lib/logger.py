import json
import os
import shutil
import tarfile
from datetime import datetime, UTC

LOG_DIR = os.getenv("LOG_DIR", "/logs")
LOG_MAX_SIZE_MB = int(os.getenv("LOG_MAX_SIZE_MB", 5))
MAX_BYTES = LOG_MAX_SIZE_MB * 1024 * 1024
BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", 3))  # Number of compressed backups to keep

os.makedirs(LOG_DIR, exist_ok=True)

def compress_log(log_file_path):
    tar_path = f"{log_file_path}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(log_file_path, arcname=os.path.basename(log_file_path))
    os.remove(log_file_path)

def cleanup_old_archives(log_file_base):
    existing_archives = sorted(
        [f for f in os.listdir(LOG_DIR) if f.startswith(os.path.basename(log_file_base)) and f.endswith(".tar.gz")]
    )
    # Keep only the newest BACKUP_COUNT files
    if len(existing_archives) > BACKUP_COUNT:
        for f in existing_archives[:-BACKUP_COUNT]:
            os.remove(os.path.join(LOG_DIR, f))

def rotate_log(log_file):
    if os.path.exists(log_file) and os.path.getsize(log_file) > MAX_BYTES:
        rotated_file = f"{log_file}.1"
        shutil.move(log_file, rotated_file)
        compress_log(rotated_file)
        cleanup_old_archives(log_file)

def log_event(service, event_type, ip, details):
    log_file = os.path.join(LOG_DIR, f"tropico-{service.lower()}.log")

    rotate_log(log_file)  # Rotate BEFORE writing

    log_entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "service": service,
        "event_type": event_type,
        "ip": ip,
        "details": details
    }
    with open(log_file, 'a') as log:
        log.write(json.dumps(log_entry) + '\n')
