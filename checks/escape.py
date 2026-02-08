from checks.utils import issue

DANGEROUS_CAPS = {
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "DAC_READ_SEARCH", "NET_ADMIN"
}

DANGEROUS_MOUNTS = {
    "/", "/proc", "/sys", "/var/run/docker.sock"
}


def escape_scan(container):
    issues = []

    hc = container.get("HostConfig") or {}
    mounts = container.get("Mounts") or []

    if hc.get("Privileged"):
        return issues

    for cap in hc.get("CapAdd") or []:
        if cap in DANGEROUS_CAPS:
            issues.append(issue(
                f"Dangerous capability enabled: {cap}",
                "high",
                f"Drop capability {cap}"
            ))

    if not hc.get("CapDrop"):
        issues.append(issue(
            "No Linux capabilities dropped",
            "medium",
            "Drop all capabilities and add back only required ones"
        ))

    for ns in ("PidMode", "NetworkMode", "IpcMode", "UTSMode"):
        if hc.get(ns) == "host":
            issues.append(issue(
                f"Host namespace enabled: {ns}",
                "high",
                f"Avoid host namespace ({ns})"
            ))

    if hc.get("CgroupnsMode") == "host":
        issues.append(issue(
            "Host cgroup namespace enabled",
            "high",
            "Disable host cgroup namespace"
        ))

    if not hc.get("UsernsMode"):
        issues.append(issue(
            "User namespace remapping not enabled",
            "medium",
            "Enable userns-remap"
        ))

    for m in mounts:
        src = m.get("Source", "")
        dst = m.get("Destination", "")
        rw = m.get("RW", False)
        prop = m.get("Propagation")

        for p in DANGEROUS_MOUNTS:
            if p in (src, dst):
                issues.append(issue(
                    f"Dangerous mount: {p} (rw={rw})",
                    "critical" if rw or p == "/var/run/docker.sock" else "high",
                    f"Remove mount to {p}"
                ))

        if prop in ("shared", "rshared"):
            issues.append(issue(
                f"Dangerous mount propagation: {prop}",
                "high",
                "Use private mount propagation"
            ))

    if hc.get("Devices"):
        issues.append(issue(
            "Host devices exposed",
            "critical",
            "Remove --device mappings"
        ))

    return issues
