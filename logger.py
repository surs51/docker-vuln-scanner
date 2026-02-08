import traceback
from datetime import datetime

LOG_FILE = "log.txt"


def log_exception():
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"\n[{datetime.utcnow().isoformat()}] FATAL ERROR\n")
            f.write(traceback.format_exc())
    except Exception:
        pass
