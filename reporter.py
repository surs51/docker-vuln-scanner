SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def normalize_issue(issue):
    return {
        "description": issue.get("description", "No description"),
        "severity": issue.get("severity", "low").lower(),
        "fix": issue.get("fix", "N/A"),
    }


def severity_index(issue):
    sev = issue.get("severity", "low").lower()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def print_report(results, mode):
    print(f"[+] Scan mode: {mode}")
    print(f"[+] Containers scanned: {len(results)}\n")

    for r in results:
        issues = [normalize_issue(i) for i in (r.get("issues") or [])]

        if not issues:
            print(f"[+] {r.get('name', 'unknown')}: OK\n")
            continue

        print(f"[!] container: {r.get('name', 'unknown')}")

        for i in sorted(issues, key=severity_index):
            print(f"    - {i['severity'].upper()}: {i['description']}")
            print(f"      -> FIX: {i['fix']}")

        print()

    print("Scan complete.")
