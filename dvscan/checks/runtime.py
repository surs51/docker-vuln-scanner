import re

from dvscan import rules as R
from dvscan.findings import Severity
from dvscan.model import is_root, unpinned
from dvscan.secrets import check_variable, insecure_setting

LOW, MEDIUM, HIGH, CRITICAL = Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL

RUNTIME_SOCKETS = {
    "docker.sock", "docker.sock.raw", "containerd.sock", "podman.sock",
    "crio.sock", "dockershim.sock", "cri-dockerd.sock",
}
SOCKET_DIRS = {"/run", "/var/run", "/run/containerd", "/var/run/containerd", "/run/podman", "/var/run/podman"}

SENSITIVE_PATHS = {
    "/": (CRITICAL, HIGH),
    "/etc": (CRITICAL, HIGH),
    "/root": (CRITICAL, HIGH),
    "/home": (HIGH, MEDIUM),
    "/proc": (CRITICAL, HIGH),
    "/sys": (CRITICAL, MEDIUM),
    "/dev": (CRITICAL, HIGH),
    "/boot": (CRITICAL, MEDIUM),
    "/lib/modules": (CRITICAL, LOW),
    "/usr": (CRITICAL, LOW),
    "/lib": (CRITICAL, LOW),
    "/bin": (CRITICAL, LOW),
    "/sbin": (CRITICAL, LOW),
    "/var/lib/docker": (CRITICAL, HIGH),
    "/var/lib/containerd": (CRITICAL, HIGH),
    "/var/lib/kubelet": (CRITICAL, HIGH),
    "/etc/kubernetes": (CRITICAL, HIGH),
    "/etc/docker": (CRITICAL, HIGH),
    "/etc/ssh": (CRITICAL, HIGH),
    "/etc/shadow": (CRITICAL, HIGH),
    "/etc/gshadow": (CRITICAL, HIGH),
    "/etc/sudoers": (CRITICAL, HIGH),
    "/etc/sudoers.d": (CRITICAL, HIGH),
    "/etc/passwd": (CRITICAL, None),
    "/var/log": (MEDIUM, None),
}
CREDENTIAL_DIRS = (".ssh", ".aws", ".kube", ".docker", ".gnupg", ".azure", ".config/gcloud")

RISKY_CAPS = {
    "SYS_MODULE": CRITICAL,
    "SYS_ADMIN": HIGH,
    "SYS_RAWIO": HIGH,
    "SYS_PTRACE": HIGH,
    "DAC_READ_SEARCH": HIGH,
    "BPF": HIGH,
    "MAC_ADMIN": HIGH,
    "MAC_OVERRIDE": HIGH,
    "NET_ADMIN": MEDIUM,
    "SYS_BOOT": MEDIUM,
    "SYS_TIME": MEDIUM,
    "SYSLOG": MEDIUM,
    "PERFMON": MEDIUM,
    "AUDIT_CONTROL": MEDIUM,
    "CHECKPOINT_RESTORE": MEDIUM,
}

NAMESPACES = {
    "pid": ("PID", "--pid=host", HIGH),
    "net": ("network", "--network=host", HIGH),
    "ipc": ("IPC", "--ipc=host", MEDIUM),
    "uts": ("UTS", "--uts=host", LOW),
    "cgroup": ("cgroup", "--cgroupns=host", LOW),
}

RAW_DEVICES = {"/dev/mem", "/dev/kmem", "/dev/port"}
DISK_DEVICE = re.compile(r"^/dev/(sd[a-z]|nvme\d|xvd[a-z]|vd[a-z]|hd[a-z]|dm-\d|md\d|loop\d|mmcblk\d|mapper/|disk/)")

SENSITIVE_PORTS = {
    2375: ("Docker API", CRITICAL),
    2376: ("Docker API (TLS)", HIGH),
    2379: ("etcd", CRITICAL),
    10250: ("kubelet API", HIGH),
    22: ("SSH", MEDIUM),
    23: ("Telnet", HIGH),
    3306: ("MySQL", HIGH),
    5432: ("PostgreSQL", HIGH),
    1433: ("SQL Server", HIGH),
    1521: ("Oracle", HIGH),
    6379: ("Redis", HIGH),
    11211: ("Memcached", HIGH),
    27017: ("MongoDB", HIGH),
    9200: ("Elasticsearch", HIGH),
    9300: ("Elasticsearch transport", HIGH),
    5984: ("CouchDB", HIGH),
    9042: ("Cassandra", HIGH),
    7474: ("Neo4j", HIGH),
    8086: ("InfluxDB", MEDIUM),
    9092: ("Kafka", HIGH),
    2181: ("ZooKeeper", HIGH),
    8500: ("Consul", HIGH),
    5672: ("RabbitMQ", MEDIUM),
    15672: ("RabbitMQ management", MEDIUM),
    5601: ("Kibana", MEDIUM),
    5900: ("VNC", HIGH),
    3389: ("RDP", HIGH),
}
WEB_PORTS = {80, 443}

SSHD = re.compile(r"(?:^|/)sshd(?:\s|:|$)")


def check_workload(w, host=None):
    checks = (
        _privileges, _security_profiles, _namespaces, _mounts, _devices,
        _ports, _environment, _user, _resources, _operations,
    )
    return [hit for check in checks for hit in check(w, host)]


def check_processes(commands):
    for command in commands:
        if SSHD.search(command):
            yield R.SSHD_RUNNING.hit("sshd is running inside the container")
            return


def env_hits(env, prefix=""):
    for name, value in env.items():
        problem = insecure_setting(name, value)
        if problem:
            yield R.INSECURE_ENV.hit(f"{prefix}{name}: {problem}")
            continue
        reason = check_variable(name, value)
        if reason:
            yield R.SECRET_IN_ENV.hit(f"{prefix}{name} {reason}")


def _privileges(w, host):
    if w.privileged:
        yield R.PRIVILEGED.hit("Runs with --privileged: every capability, every host device, no seccomp or AppArmor")
        return

    if "ALL" in w.cap_add:
        yield R.DANGEROUS_CAPABILITY.hit("Every capability added (--cap-add ALL)", CRITICAL)
    else:
        disabled = []
        if "unconfined" in w.opt("seccomp"):
            disabled.append("seccomp")
        if _apparmor_off(w):
            disabled.append("AppArmor")
        for cap in sorted(w.cap_add):
            severity = RISKY_CAPS.get(cap)
            if severity is None:
                continue
            detail = f"CAP_{cap} added"
            if cap == "SYS_PTRACE" and w.namespaces.get("pid") == "host":
                severity, detail = CRITICAL, f"{detail} together with the host PID namespace"
            elif cap == "SYS_ADMIN" and disabled:
                severity, detail = CRITICAL, f"{detail} with {' and '.join(disabled)} turned off"
            elif cap == "NET_ADMIN" and w.namespaces.get("net") == "host":
                severity, detail = HIGH, f"{detail} on the host network"
            yield R.DANGEROUS_CAPABILITY.hit(detail, severity)

    if "ALL" not in w.cap_drop:
        dropped = ", ".join(sorted(w.cap_drop))
        yield R.CAP_DROP.hit(f"Only {dropped} dropped, not ALL" if dropped else "Runs with Docker's default capability set")


def _security_profiles(w, host):
    if not w.privileged:
        if "unconfined" in w.opt("seccomp"):
            yield R.SECCOMP_DISABLED.hit("Runs with seccomp=unconfined")
        if _apparmor_off(w):
            yield R.APPARMOR_DISABLED.hit("Runs with apparmor=unconfined")
        if "disable" in w.opt("label"):
            yield R.SELINUX_DISABLED.hit("Runs with label=disable")
        if "unconfined" in w.opt("systempaths"):
            yield R.UNMASKED_PATHS.hit("Runs with systempaths=unconfined")

    blocked = any(v.lower() in ("", "true", "1") for v in w.opt("no-new-privileges"))
    if not blocked and not (host and host.no_new_privileges):
        yield R.NO_NEW_PRIVILEGES.hit("no-new-privileges is not set, so setuid binaries can raise privileges")


def _apparmor_off(w):
    return "unconfined" in w.opt("apparmor") or (w.apparmor_profile == "unconfined" and not w.privileged)


def _namespaces(w, host):
    for key, (label, flag, severity) in NAMESPACES.items():
        if w.namespaces.get(key) == "host":
            yield R.HOST_NAMESPACE.hit(f"Shares the host {label} namespace ({flag})", severity)
    if w.namespaces.get("userns") == "host" and (host is None or host.userns):
        yield R.HOST_NAMESPACE.hit("Opts out of user namespace remapping (--userns=host)", MEDIUM)


def _mounts(w, host):
    for mount in w.mounts:
        if mount.kind != "bind":
            continue
        source = _clean_path(mount.source)
        access = "read-only" if mount.read_only else "read-write"

        if _runtime_socket(source):
            note = " (read-only makes no difference for a socket)" if mount.read_only else ""
            yield R.DOCKER_SOCKET.hit(f"{source} mounted at {mount.target}{note}")
        else:
            severity = _sensitive(source, mount.read_only)
            if severity:
                yield R.SENSITIVE_MOUNT.hit(f"Host {source} mounted {access} at {mount.target}", severity)

        if mount.propagation in ("shared", "rshared"):
            yield R.MOUNT_PROPAGATION.hit(f"{source} mounted with {mount.propagation} propagation")


def _clean_path(path):
    path = re.sub(r"/+", "/", path.replace("\\", "/"))
    return path.rstrip("/") or "/"


def _runtime_socket(path):
    return path.rsplit("/", 1)[-1] in RUNTIME_SOCKETS or path in SOCKET_DIRS


def _sensitive(path, read_only):
    if path in SENSITIVE_PATHS:
        writable, readable = SENSITIVE_PATHS[path]
        return readable if read_only else writable
    if any(f"/{name}/" in path + "/" for name in CREDENTIAL_DIRS):
        return HIGH
    if not read_only and path.startswith(("/proc/", "/sys/")):
        return HIGH
    return None


def _devices(w, host):
    if w.privileged:
        return
    for device in w.devices:
        severity = CRITICAL if device in RAW_DEVICES or DISK_DEVICE.match(device) else MEDIUM
        yield R.HOST_DEVICE.hit(f"Host device {device} passed through", severity)
    for rule in w.device_rules:
        kind, _, rest = rule.strip().partition(" ")
        numbers, _, access = rest.strip().partition(" ")
        if kind == "a" or numbers == "*:*":
            severity = CRITICAL
        elif kind == "b" and "w" in access:
            severity = HIGH
        else:
            severity = MEDIUM
        yield R.HOST_DEVICE.hit(f"Device cgroup rule '{rule}' opens up host devices", severity)


def _ports(w, host):
    for port in w.ports:
        if not port.public:
            continue
        service = SENSITIVE_PORTS.get(port.port)
        if service:
            name, severity = service
            local = f"127.0.0.1:{port.host_port or port.port}:{port.port}"
            fix = (
                f"Publish it on localhost ({local}) or keep it on an internal network without publishing it. "
                "Docker's port rules bypass host firewalls such as ufw."
            )
            yield R.SENSITIVE_PORT.hit(f"{name} ({port.port}/{port.protocol}) published on {port.binding()}", severity, fix=fix)
        elif port.port not in WEB_PORTS:
            yield R.EXPOSED_PORT.hit(f"{port.port}/{port.protocol} published on {port.binding()}")
    if w.publish_all:
        yield R.PUBLISH_ALL.hit("Started with -P, so every EXPOSEd port is published on all interfaces")


def _environment(w, host):
    return env_hits(w.env)


def _user(w, host):
    if w.user is None:
        if not w.built:
            yield R.ROOT_USER.hit("No user set, and the image isn't available locally to check its default", MEDIUM)
        return
    if not is_root(w.user):
        return

    detail = "Runs as root (no user set)" if not w.user else f"Runs as root (user {w.user})"
    remapped = host is not None and (host.userns or host.rootless) and w.namespaces.get("userns") != "host"
    if remapped:
        yield R.ROOT_USER.hit(f"{detail}, mapped to an unprivileged user on the host", LOW)
    else:
        yield R.ROOT_USER.hit(detail)


def _resources(w, host):
    if not w.memory:
        yield R.NO_MEMORY_LIMIT.hit()
        if w.oom_kill_disable:
            yield R.OOM_KILL_DISABLED.hit()
    if not w.cpu_limited:
        yield R.NO_CPU_LIMIT.hit()
    if w.pids_limit <= 0:
        yield R.NO_PIDS_LIMIT.hit()


def _operations(w, host):
    if not w.read_only:
        yield R.WRITABLE_ROOTFS.hit()

    test = w.healthcheck or []
    if test and str(test[0]).upper() == "NONE":
        yield R.NO_HEALTHCHECK.hit("Healthcheck explicitly disabled")
    elif not test:
        if w.image_known:
            yield R.NO_HEALTHCHECK.hit()
        elif not w.built:
            yield R.NO_HEALTHCHECK.hit("No healthcheck in the compose file (image not available locally to check)")

    if w.image and not w.built and unpinned(w.image):
        yield R.LATEST_TAG.hit(f"Uses {w.image}, which is not pinned to a version")
    if w.log_driver == "none":
        yield R.NO_LOGGING.hit("Log driver is 'none'")
    if w.namespaces.get("net") in ("bridge", "default"):
        yield R.DEFAULT_BRIDGE.hit()
