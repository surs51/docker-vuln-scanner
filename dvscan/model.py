from __future__ import annotations

import re
from dataclasses import dataclass, field

ALL_INTERFACES = {"", "0.0.0.0", "::", "[::]"}
LOCAL_REGISTRY_CIDRS = {"127.0.0.0/8", "::1/128"}
EXPOSED_API_WARNING = re.compile(r"API is accessible on (\S+) without encryption")


@dataclass
class Mount:
    source: str
    target: str
    read_only: bool = False
    propagation: str = ""
    kind: str = "bind"


@dataclass
class Port:
    port: int
    protocol: str = "tcp"
    host_ip: str = ""
    host_port: str = ""

    @property
    def public(self):
        return self.host_ip in ALL_INTERFACES

    def binding(self):
        ip = self.host_ip or "0.0.0.0"
        if ":" in ip and not ip.startswith("["):
            ip = f"[{ip}]"
        return f"{ip}:{self.host_port}" if self.host_port else f"{ip} (random host port)"


@dataclass
class Workload:
    kind: str
    name: str
    id: str = ""
    image: str = ""
    image_known: bool = True
    built: bool = False
    running: bool = True
    status: str = ""
    user: str | None = ""
    privileged: bool = False
    read_only: bool = False
    cap_add: set = field(default_factory=set)
    cap_drop: set = field(default_factory=set)
    security_opt: list = field(default_factory=list)
    apparmor_profile: str = ""
    namespaces: dict = field(default_factory=dict)
    mounts: list = field(default_factory=list)
    devices: list = field(default_factory=list)
    device_rules: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    publish_all: bool = False
    env: dict = field(default_factory=dict)
    healthcheck: list | None = None
    memory: int = 0
    cpu_limited: bool = False
    pids_limit: int = 0
    oom_kill_disable: bool = False
    log_driver: str = ""
    labels: dict = field(default_factory=dict)

    def opt(self, key):
        return [value for name, value in self.security_opt if name == key]


@dataclass
class HostInfo:
    version: str = ""
    os: str = ""
    runc: str = ""
    rootless: bool = False
    userns: bool = False
    seccomp_profile: str = ""
    insecure_registries: list = field(default_factory=list)
    exposed_api: list = field(default_factory=list)
    no_new_privileges: bool = False
    icc: bool | None = None
    lsm: bool | None = None
    socket_path: str = ""
    socket_mode: int | None = None
    docker_group: list = field(default_factory=list)
    writable_configs: list = field(default_factory=list)


def parse_env(entries):
    env = {}
    for entry in entries or []:
        name, _, value = str(entry).partition("=")
        if name:
            env[name] = value
    return env


def parse_security_opt(options):
    parsed = []
    for option in options or []:
        option = str(option).strip()
        cuts = [i for i in (option.find("="), option.find(":")) if i != -1]
        if cuts:
            cut = min(cuts)
            parsed.append((option[:cut].strip().lower(), option[cut + 1:].strip()))
        else:
            parsed.append((option.lower(), ""))
    return parsed


def normalize_caps(caps):
    return {str(c).strip().upper().removeprefix("CAP_") for c in caps or [] if str(c).strip()}


def parse_bytes(value):
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*", str(value), re.I)
    if not match:
        return 0
    return int(float(match.group(1)) * 1024 ** "bkmgt".index(match.group(2).lower() or "b"))


def is_root(user):
    return str(user).split(":")[0].strip() in ("", "0", "root")


def unpinned(ref):
    if not ref or "@" in ref:
        return False
    name = ref.rsplit("/", 1)[-1]
    tag = name.split(":", 1)[1] if ":" in name else ""
    return tag in ("", "latest")


def workload_from_inspect(data):
    config = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    state = data.get("State") or {}
    running = bool(state.get("Running"))

    mounts = [
        Mount(
            source=m.get("Source") or "",
            target=m.get("Destination") or "",
            read_only=not m.get("RW", True),
            propagation=m.get("Propagation") or "",
            kind=m.get("Type") or "bind",
        )
        for m in data.get("Mounts") or []
    ]

    pids = host.get("PidsLimit") or 0
    return Workload(
        kind="container",
        name=(data.get("Name") or "").lstrip("/") or data.get("Id", "")[:12],
        id=data.get("Id") or "",
        image=config.get("Image") or "",
        running=running,
        status=state.get("Status") or "",
        user=config.get("User") or "",
        privileged=bool(host.get("Privileged")),
        read_only=bool(host.get("ReadonlyRootfs")),
        cap_add=normalize_caps(host.get("CapAdd")),
        cap_drop=normalize_caps(host.get("CapDrop")),
        security_opt=parse_security_opt(host.get("SecurityOpt")),
        apparmor_profile=data.get("AppArmorProfile") or "",
        namespaces={
            "pid": host.get("PidMode") or "",
            "net": host.get("NetworkMode") or "",
            "ipc": host.get("IpcMode") or "",
            "uts": host.get("UTSMode") or "",
            "userns": host.get("UsernsMode") or "",
            "cgroup": host.get("CgroupnsMode") or "",
        },
        mounts=mounts,
        devices=[d.get("PathOnHost") or "" for d in host.get("Devices") or []],
        device_rules=list(host.get("DeviceCgroupRules") or []),
        ports=_inspect_ports(data, running),
        publish_all=bool(host.get("PublishAllPorts")),
        env=parse_env(config.get("Env")),
        healthcheck=(config.get("Healthcheck") or {}).get("Test"),
        memory=host.get("Memory") or 0,
        cpu_limited=bool(host.get("NanoCpus") or host.get("CpuQuota") or host.get("CpusetCpus")),
        pids_limit=pids if pids > 0 else 0,
        oom_kill_disable=bool(host.get("OomKillDisable")),
        log_driver=(host.get("LogConfig") or {}).get("Type") or "",
        labels=config.get("Labels") or {},
    )


def _inspect_ports(data, running):
    host = data.get("HostConfig") or {}
    live = (data.get("NetworkSettings") or {}).get("Ports") if running else None
    bindings = live or host.get("PortBindings") or {}

    ports, seen = [], set()
    for spec, entries in bindings.items():
        number, _, protocol = spec.partition("/")
        for entry in entries or []:
            port = Port(int(number), protocol or "tcp", entry.get("HostIp") or "", entry.get("HostPort") or "")
            key = (port.port, port.protocol, "*" if port.public else port.host_ip, port.host_port)
            if key not in seen:
                seen.add(key)
                ports.append(port)
    return ports


def host_from(version, info, daemon_config=None):
    info = info or {}
    server = (version or {}).get("Server") or {}
    components = {c.get("Name", "").lower(): c for c in server.get("Components") or []}
    runc = (components.get("runc") or {}).get("Version") or ""
    if not runc:
        commit = (info.get("RuncCommit") or {}).get("ID") or ""
        runc = commit.split("-")[0] if commit.startswith("v") else ""

    options = []
    for option in info.get("SecurityOptions") or []:
        options.append(dict(part.split("=", 1) for part in option.split(",") if "=" in part))
    names = {o.get("name") for o in options}
    seccomp = next((o.get("profile", "default") for o in options if o.get("name") == "seccomp"), "")

    registry = info.get("RegistryConfig") or {}
    insecure = [c for c in registry.get("InsecureRegistryCIDRs") or [] if c not in LOCAL_REGISTRY_CIDRS]
    for name, index in (registry.get("IndexConfigs") or {}).items():
        if not index.get("Secure", True) and not _local_registry(name):
            insecure.append(name)

    exposed = []
    for warning in info.get("Warnings") or []:
        match = EXPOSED_API_WARNING.search(warning)
        if match:
            exposed.append(match.group(1).rstrip("."))

    return HostInfo(
        version=server.get("Version") or info.get("ServerVersion") or "",
        os=info.get("OperatingSystem") or "",
        runc=runc,
        rootless="rootless" in names,
        userns="userns" in names,
        seccomp_profile=seccomp,
        insecure_registries=insecure,
        exposed_api=exposed,
        no_new_privileges=bool((daemon_config or {}).get("no-new-privileges")),
        lsm=bool(names & {"apparmor", "selinux"}) if options else None,
    )


def _local_registry(name):
    host = name.split("/")[0]
    return host.startswith(("localhost", "127.", "[::1]", "::1"))
