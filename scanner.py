
import sys
sys.dont_write_bytecode = True
from checks.utils import get_containers
from checks.basic import basic_scan
from checks.escape import escape_scan
from reporter import print_report
from logger import log_exception

VALID_MODES = ("basic", "full", "paranoid")


def main():
    mode = "full"

    if len(sys.argv) > 1 and sys.argv[1] in VALID_MODES:
        mode = sys.argv[1]

    containers = get_containers()
    results = []

    for c in containers:
        issues = []

        if mode in ("basic", "full", "paranoid"):
            issues.extend(basic_scan(c))

        if mode in ("full", "paranoid"):
            issues.extend(escape_scan(c))

        results.append({
            "id": c.get("Id", "")[:12],
            "name": c.get("Name", "").lstrip("/"),
            "issues": issues,
        })

    print_report(results, mode)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        log_exception()
        print("[!] Fatal error occurred. See log.txt")
        sys.exit(1)
