from dvscan.findings import Rule, Severity

LOW, MEDIUM, HIGH, CRITICAL = Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL

RULES = {}


def rule(id, severity, level, title, fix):
    RULES[id] = Rule(id, severity, level, title, fix)
    return RULES[id]


RUNC_CVE = rule(
    "runc-cve", CRITICAL, "basic",
    "Container runtime with a known escape vulnerability",
    "Upgrade runc (usually shipped in the containerd.io or runc package) and restart your containers.",
)
DAEMON_TCP = rule(
    "daemon-tcp", CRITICAL, "basic",
    "Docker API exposed without TLS",
    "Stop listening on plain tcp://. Anyone who can reach that port has root on the host. "
    "Use the unix socket, DOCKER_HOST=ssh://..., or mutual TLS.",
)
SOCKET_PERMISSIONS = rule(
    "socket-permissions", CRITICAL, "basic",
    "Docker socket writable by every user",
    "Put the default back: root:docker and mode 660 (restarting docker.socket does this). "
    "Add trusted users to the docker group instead of opening the socket to everyone.",
)
DAEMON_CONFIG_WRITABLE = rule(
    "daemon-config-writable", HIGH, "basic",
    "Daemon configuration writable by non-root users",
    "Make it owned by root and not writable by group or others (chown root:root, chmod 644 for files, 755 for directories).",
)
DAEMON_SECCOMP = rule(
    "daemon-seccomp", HIGH, "basic",
    "Daemon runs containers without seccomp",
    "Remove \"seccomp-profile\": \"unconfined\" from daemon.json and restart dockerd.",
)
NO_LSM = rule(
    "no-lsm", MEDIUM, "full",
    "No AppArmor or SELinux on the host",
    "Enable AppArmor or SELinux so Docker can confine every container with its default profile.",
)
DOCKER_GROUP = rule(
    "docker-group", LOW, "full",
    "Users with root-equivalent access through the docker group",
    "Keep the docker group to people who really need it. Anyone in it can start a privileged container "
    "and become root on the host. Rootless Docker is the safer option for everyone else.",
)
INSECURE_REGISTRY = rule(
    "insecure-registry", MEDIUM, "full",
    "Insecure registry configured",
    "Serve the registry over TLS and remove it from insecure-registries in daemon.json.",
)
USERNS_REMAP = rule(
    "userns-remap", LOW, "paranoid",
    "User namespace remapping disabled",
    "Enable userns-remap in daemon.json or run Docker rootless, so root in a container is not root on the host.",
)
ICC = rule(
    "icc", LOW, "paranoid",
    "Containers on the default bridge can talk to each other",
    "Set \"icc\": false in daemon.json, or move containers onto user-defined networks.",
)

PRIVILEGED = rule(
    "privileged", CRITICAL, "basic",
    "Privileged container",
    "Remove --privileged (privileged: true) and grant only the specific capabilities or devices the workload needs.",
)
DOCKER_SOCKET = rule(
    "docker-socket", CRITICAL, "basic",
    "Container runtime socket mounted",
    "Remove the socket mount. If the container really needs the Docker API, put a socket proxy in front "
    "of it that only allows the calls it uses.",
)
SENSITIVE_MOUNT = rule(
    "sensitive-mount", HIGH, "basic",
    "Sensitive host path mounted",
    "Mount only the specific files or directories the container needs, read-only where possible.",
)
DANGEROUS_CAPABILITY = rule(
    "dangerous-capability", HIGH, "basic",
    "Dangerous capability added",
    "Remove the capability. Most workloads run fine with --cap-drop ALL plus one or two specific additions.",
)
HOST_NAMESPACE = rule(
    "host-namespace", HIGH, "basic",
    "Host namespace shared",
    "Drop the host namespace flag. Publish ports or mount volumes for whatever the container needs from the host.",
)
SECCOMP_DISABLED = rule(
    "seccomp-disabled", HIGH, "basic",
    "Seccomp disabled",
    "Remove seccomp=unconfined. If a syscall gets blocked, use a custom profile that allows just that syscall.",
)
APPARMOR_DISABLED = rule(
    "apparmor-disabled", HIGH, "basic",
    "AppArmor disabled",
    "Remove apparmor=unconfined, or write a profile tailored to the workload.",
)
SELINUX_DISABLED = rule(
    "selinux-disabled", HIGH, "basic",
    "SELinux separation disabled",
    "Remove label=disable and relabel volumes with :z or :Z instead.",
)
UNMASKED_PATHS = rule(
    "unmasked-paths", HIGH, "basic",
    "Kernel paths under /proc and /sys unmasked",
    "Remove systempaths=unconfined.",
)
HOST_DEVICE = rule(
    "host-device", HIGH, "basic",
    "Host device exposed",
    "Remove the device mapping, or narrow it to the exact device with the least access it needs (e.g. :r).",
)
MOUNT_PROPAGATION = rule(
    "mount-propagation", MEDIUM, "basic",
    "Shared mount propagation",
    "Use the default private propagation unless the container really has to see mounts made on the host.",
)
SECRET_IN_ENV = rule(
    "secret-in-env", HIGH, "basic",
    "Secret in environment variable",
    "Pass secrets as files instead (Docker/Compose secrets or a read-only mount). Environment variables "
    "show up in docker inspect, /proc and crash reports.",
)
INSECURE_ENV = rule(
    "insecure-env", HIGH, "basic",
    "Security feature turned off through the environment",
    "Remove the setting and configure authentication or certificates properly.",
)
SENSITIVE_PORT = rule(
    "sensitive-port", HIGH, "basic",
    "Sensitive service published on all interfaces",
    "Publish it on 127.0.0.1 (-p 127.0.0.1:5432:5432) or keep it on an internal network without publishing it. "
    "Docker's port rules bypass host firewalls such as ufw.",
)
ROOT_USER = rule(
    "root-user", HIGH, "basic",
    "Runs as root",
    "Add a non-root USER to the Dockerfile, or run with --user 1000:1000.",
)
NO_NEW_PRIVILEGES = rule(
    "no-new-privileges", MEDIUM, "full",
    "Privilege escalation not blocked",
    "Run with --security-opt no-new-privileges:true, or set \"no-new-privileges\": true in daemon.json.",
)
CAP_DROP = rule(
    "cap-drop", MEDIUM, "full",
    "Default capabilities kept",
    "Use --cap-drop ALL and add back only the capabilities the workload needs.",
)
WRITABLE_ROOTFS = rule(
    "writable-rootfs", MEDIUM, "full",
    "Writable root filesystem",
    "Run with --read-only and mount a tmpfs for the paths that need writes, like /tmp.",
)
OOM_KILL_DISABLED = rule(
    "oom-kill-disabled", MEDIUM, "full",
    "OOM killer disabled without a memory limit",
    "Set a memory limit or drop --oom-kill-disable, otherwise the container can take all of the host's memory.",
)
EXPOSED_PORT = rule(
    "exposed-port", LOW, "full",
    "Port published on all interfaces",
    "If it only needs to be reachable locally or through a reverse proxy, bind it to 127.0.0.1. "
    "Docker's port rules bypass host firewalls such as ufw.",
)
PUBLISH_ALL = rule(
    "publish-all", LOW, "full",
    "Every exposed port is published",
    "Replace -P with explicit -p mappings for the ports you actually want reachable.",
)
NO_MEMORY_LIMIT = rule(
    "no-memory-limit", LOW, "full",
    "No memory limit",
    "Set --memory (mem_limit or deploy.resources.limits.memory in Compose).",
)
NO_CPU_LIMIT = rule(
    "no-cpu-limit", LOW, "full",
    "No CPU limit",
    "Set --cpus (cpus or deploy.resources.limits.cpus in Compose).",
)
NO_PIDS_LIMIT = rule(
    "no-pids-limit", LOW, "full",
    "No PID limit",
    "Set --pids-limit so a fork bomb can't take down the host.",
)
NO_HEALTHCHECK = rule(
    "no-healthcheck", LOW, "full",
    "No healthcheck",
    "Add a HEALTHCHECK so a hung process gets noticed and restarted.",
)
LATEST_TAG = rule(
    "latest-tag", LOW, "full",
    "Image not pinned to a version",
    "Use a specific version tag, or better, pin by digest (image@sha256:...).",
)
NO_LOGGING = rule(
    "no-logging", LOW, "paranoid",
    "Logging disabled",
    "Use a real log driver so there is something to look at after an incident.",
)
DEFAULT_BRIDGE = rule(
    "default-bridge", LOW, "paranoid",
    "Attached to the default bridge network",
    "Put the container on a user-defined network so unrelated containers can't reach it.",
)
SSHD_RUNNING = rule(
    "sshd-running", MEDIUM, "paranoid",
    "SSH server running in container",
    "Take sshd out of the image and use docker exec when you need a shell.",
)

SECRET_IN_HISTORY = rule(
    "secret-in-history", HIGH, "full",
    "Secret in image history",
    "Anyone who can pull the image can read its history. Rebuild without the secret (RUN --mount=type=secret "
    "for build-time secrets) and rotate the credential.",
)
STALE_IMAGE = rule(
    "stale-image", LOW, "paranoid",
    "Image is more than a year old",
    "Rebuild on a current base image to pick up security fixes.",
)
VULNERABLE_PACKAGE = rule(
    "vulnerable-package", HIGH, "basic",
    "Package with a known vulnerability",
    "Upgrade the affected packages or rebuild on a patched base image. Accept a specific CVE with --ignore CVE-ID.",
)

SECRET_IN_DOCKERFILE = rule(
    "secret-in-dockerfile", HIGH, "basic",
    "Hardcoded secret in Dockerfile",
    "Take it out of the Dockerfile, rotate it, and inject it at runtime or with RUN --mount=type=secret at build time.",
)
SECRET_BUILD_ARG = rule(
    "secret-build-arg", MEDIUM, "full",
    "Secret passed as a build argument",
    "Build args end up in the image history. Use RUN --mount=type=secret,id=... instead.",
)
PIPE_TO_SHELL = rule(
    "pipe-to-shell", HIGH, "basic",
    "Remote script piped into a shell",
    "Download the script, check its checksum or signature, then run it.",
)
INSECURE_DOWNLOAD = rule(
    "insecure-download", HIGH, "basic",
    "TLS or signature verification disabled",
    "Drop the flag and fix the underlying problem: install the CA certificate or import the signing key.",
)
REMOTE_ADD = rule(
    "remote-add", MEDIUM, "full",
    "ADD downloads a remote file without a checksum",
    "Use ADD --checksum=sha256:... or download with curl and verify the checksum.",
)
WORLD_WRITABLE = rule(
    "world-writable", MEDIUM, "full",
    "World-writable permissions",
    "Give ownership to the runtime user (COPY --chown or chown) instead of making files writable by everyone.",
)
SUDO = rule(
    "sudo", LOW, "full",
    "sudo used in RUN",
    "Build steps already run as root until USER is set. Drop sudo and keep it out of the image.",
)
COPY_CONTEXT = rule(
    "copy-context", MEDIUM, "full",
    "Whole build context copied without a .dockerignore",
    "Add a .dockerignore that excludes .git, .env files, credentials and local build output.",
)
SSH_PORT = rule(
    "ssh-port", MEDIUM, "full",
    "SSH port exposed",
    "Don't run SSH inside containers. Use docker exec instead.",
)
ADD_LOCAL = rule(
    "add-local", LOW, "paranoid",
    "ADD used where COPY would do",
    "Use COPY for local files. ADD quietly extracts archives and fetches URLs.",
)
