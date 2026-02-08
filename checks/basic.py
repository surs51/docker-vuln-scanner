from checks.utils import issue


def basic_scan(container):
    issues = []

    cfg = container.get("Config", {})
    hc = container.get("HostConfig", {})
    net = container.get("NetworkSettings", {})

    if cfg.get("User") in ("", "0"):
        issues.append(issue(
            "Container runs as root",
            "critical",
            "Use non-root USER"
        ))

    if hc.get("Privileged"):
        issues.append(issue(
            "Privileged container (full host access)",
            "critical",
            "Remove --privileged"
        ))
        return issues

    if not hc.get("ReadonlyRootfs", False):
        issues.append(issue(
            "Root filesystem is writable",
            "medium",
            "Enable --read-only"
        ))

    sec = hc.get("SecurityOpt") or []
    if "seccomp=unconfined" in sec:
        issues.append(issue(
            "Seccomp disabled",
            "high",
            "Enable seccomp profile"
        ))

    if any("apparmor=unconfined" in s for s in sec):
        issues.append(issue(
            "AppArmor disabled",
            "high",
            "Apply AppArmor profile"
        ))

    if not any(s.lower().startswith("no-new-privileges") for s in sec):
        issues.append(issue(
        "NoNewPrivileges not enabled",
        "medium",
        "Add --security-opt no-new-privileges"
        ))

    if hc.get("Memory", 0) == 0:
        issues.append(issue("No memory limit set", "low", "Set memory limit"))

    if hc.get("NanoCpus", 0) == 0:
        issues.append(issue("No CPU limit set", "low", "Set CPU limit"))

    if hc.get("PidsLimit") in (None, 0):
        issues.append(issue("No PID limit set", "low", "Set --pids-limit"))

    if not cfg.get("Healthcheck"):
        issues.append(issue(
            "No healthcheck configured",
            "low",
            "Define HEALTHCHECK"
        ))

    for m in container.get("Mounts", []):
        if m.get("Source") == "/var/run/docker.sock":
            issues.append(issue(
                "Docker socket mounted",
                "critical",
                "Remove docker.sock mount"
            ))

    ports = net.get("Ports") or {}
    for port, bindings in ports.items():
        if bindings:
            for b in bindings:
                if b.get("HostIp") == "0.0.0.0":
                    issues.append(issue(
                        f"Port {port} exposed to 0.0.0.0",
                        "medium",
                        "Bind to specific interface"
                    ))

    for env in cfg.get("Env") or []:
        e = env.lower()
        if any(k in e for k in ("password", "secret", "token", "key=")):
            issues.append(issue(
                f"Potential secret in ENV: {env.split('=')[0]}",
                "high",
                "Use secrets manager"
            ))

    return issues
