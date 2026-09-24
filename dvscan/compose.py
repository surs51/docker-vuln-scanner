import re
from pathlib import Path

from dvscan.model import (
    Mount,
    Port,
    Workload,
    normalize_caps,
    parse_bytes,
    parse_env,
    parse_security_opt,
)

DEFAULT_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


def find_default(directory="."):
    for name in DEFAULT_FILES:
        path = Path(directory) / name
        if path.is_file():
            return path
    return None


def image_ref(project, name, service):
    return service.get("image") or f"{project}-{name}"


def workload_from_compose(name, service, image=None):
    config = (image or {}).get("Config") or {}
    known = image is not None

    user = str(service.get("user") or "")
    if not user:
        user = (config.get("User") or "") if known else None

    env = parse_env(config.get("Env"))
    environment = service.get("environment") or {}
    if isinstance(environment, list):
        environment = parse_env(environment)
    env.update({key: "" if value is None else str(value) for key, value in environment.items()})

    limits = ((service.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    labels = service.get("labels") or {}
    if isinstance(labels, list):
        labels = parse_env(labels)

    return Workload(
        kind="service",
        name=name,
        image=service.get("image") or "",
        image_known=known,
        built=bool(service.get("build")),
        user=user,
        privileged=bool(service.get("privileged")),
        read_only=bool(service.get("read_only")),
        cap_add=normalize_caps(service.get("cap_add")),
        cap_drop=normalize_caps(service.get("cap_drop")),
        security_opt=parse_security_opt(service.get("security_opt")),
        namespaces={
            "pid": service.get("pid") or "",
            "net": service.get("network_mode") or "",
            "ipc": service.get("ipc") or "",
            "uts": service.get("uts") or "",
            "userns": service.get("userns_mode") or "",
            "cgroup": service.get("cgroup") or "",
        },
        mounts=_mounts(service.get("volumes")),
        devices=_devices(service.get("devices")),
        device_rules=list(service.get("device_cgroup_rules") or []),
        ports=_ports(service.get("ports")),
        env=env,
        healthcheck=_healthcheck(service.get("healthcheck"), config),
        memory=parse_bytes(service.get("mem_limit")) or parse_bytes(limits.get("memory")),
        cpu_limited=bool(
            _number(service.get("cpus")) or _number(limits.get("cpus"))
            or service.get("cpu_quota") or service.get("cpuset")
        ),
        pids_limit=int(_number(service.get("pids_limit")) or _number(limits.get("pids"))),
        oom_kill_disable=bool(service.get("oom_kill_disable")),
        log_driver=(service.get("logging") or {}).get("driver") or "",
        labels=labels,
    )


def dockerfiles(service):
    build = service.get("build")
    if not isinstance(build, dict) or not build.get("context") or build.get("dockerfile_inline"):
        return None
    context = Path(build["context"])
    dockerfile = context / (build.get("dockerfile") or "Dockerfile")
    return (dockerfile, context) if dockerfile.is_file() else None


def service_line(text, name):
    inside, indent = False, None
    key = re.compile(rf"[\"']?{re.escape(name)}[\"']?\s*:")
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            if inside:
                break
            inside = bool(re.match(r"services\s*:", line))
            continue
        if inside:
            depth = len(line) - len(line.lstrip())
            indent = depth if indent is None else indent
            if depth == indent and key.match(line.strip()):
                return number
    return None


def _mounts(volumes):
    mounts = []
    for volume in volumes or []:
        if not isinstance(volume, dict):
            continue
        mounts.append(Mount(
            source=volume.get("source") or "",
            target=volume.get("target") or "",
            read_only=bool(volume.get("read_only")),
            propagation=(volume.get("bind") or {}).get("propagation") or "",
            kind=volume.get("type") or "volume",
        ))
    return mounts


def _devices(devices):
    paths = []
    for device in devices or []:
        if isinstance(device, dict):
            paths.append(device.get("source") or "")
        else:
            paths.append(str(device).split(":")[0])
    return paths


def _ports(ports):
    result = []
    for port in ports or []:
        if not isinstance(port, dict):
            continue
        target = str(port.get("target") or "0").split("-")[0]
        if not target.isdigit():
            continue
        result.append(Port(
            int(target),
            port.get("protocol") or "tcp",
            port.get("host_ip") or "",
            str(port.get("published") or ""),
        ))
    return result


def _healthcheck(healthcheck, image_config):
    if not healthcheck:
        return (image_config.get("Healthcheck") or {}).get("Test")
    if healthcheck.get("disable"):
        return ["NONE"]
    test = healthcheck.get("test")
    if isinstance(test, str):
        return ["CMD-SHELL", test]
    return test or (image_config.get("Healthcheck") or {}).get("Test")


def _number(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0
