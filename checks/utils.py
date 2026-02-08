import subprocess
import json


def issue(description, severity="low", fix="N/A"):
    return {
        "description": description,
        "severity": severity.lower(),
        "fix": fix,
    }


def docker(cmd):
    try:
        result = subprocess.run(
            ["docker"] + cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            text=True,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_containers():
    ids_raw = docker(["ps", "-q"])
    if not ids_raw:
        return []

    containers = []

    for cid in ids_raw.splitlines():
        raw = docker(["inspect", cid])
        if not raw:
            continue

        try:
            data = json.loads(raw)
            if data:
                containers.append(data[0])
        except json.JSONDecodeError:
            continue

    return containers
