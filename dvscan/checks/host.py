import re
import stat

from dvscan import rules as R
from dvscan.findings import Severity

RUNC_ADVISORIES = (
    (
        "CVE-2024-21626",
        "a leaked file descriptor lets a container reach the host filesystem",
        ("1.1.12",),
    ),
    (
        "CVE-2025-31133, CVE-2025-52565, CVE-2025-52881",
        "mount races let a container write to host /proc files and break out",
        ("1.2.8", "1.3.3", "1.4.0-rc.3"),
    ),
)
UPSTREAM_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:-rc\.?\d+)?")


def check_host(host):
    yield from _runc(host.runc)
    for address in host.exposed_api:
        yield R.DAEMON_TCP.hit(f"Docker API answers on {address} without TLS")
    if host.socket_mode is not None and host.socket_mode & stat.S_IWOTH:
        mode = stat.filemode(host.socket_mode)
        yield R.SOCKET_PERMISSIONS.hit(f"{host.socket_path} is {mode}, so any local user controls Docker")
    for path in host.writable_configs:
        yield R.DAEMON_CONFIG_WRITABLE.hit(f"{path} can be changed by non-root users")
    if host.seccomp_profile == "unconfined":
        yield R.DAEMON_SECCOMP.hit("Daemon default seccomp profile is 'unconfined'")
    if host.lsm is False:
        yield R.NO_LSM.hit("Neither AppArmor nor SELinux is active, containers rely on seccomp and capabilities alone")
    if host.docker_group and not host.rootless:
        yield R.DOCKER_GROUP.hit(f"In the docker group: {', '.join(host.docker_group)}")
    for registry in host.insecure_registries:
        yield R.INSECURE_REGISTRY.hit(f"{registry} is trusted without TLS verification")
    if not (host.userns or host.rootless):
        yield R.USERNS_REMAP.hit("Neither userns-remap nor rootless mode is enabled")
    if host.icc:
        yield R.ICC.hit()


def parse_version(text):
    match = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?(?:-rc\.?(\d+))?", (text or "").strip())
    if not match:
        return None
    major, minor, patch, rc = match.groups()
    pre = (0, int(rc)) if rc else (1, 0)
    return int(major), int(minor), int(patch or 0), pre


def affected(version, fixed_in):
    fixes = sorted(parse_version(f) for f in fixed_in)
    for fix in fixes:
        if version[:2] == fix[:2]:
            return version < fix
    return version[:2] < fixes[0][:2]


def _runc(version):
    parsed = parse_version(version)
    if not parsed:
        return
    for cves, summary, fixed_in in RUNC_ADVISORIES:
        if not affected(parsed, fixed_in):
            continue
        detail = f"runc {version} is affected by {cves}: {summary}"
        severity = Severity.CRITICAL
        if not UPSTREAM_VERSION.fullmatch(version.strip()):
            detail += " (distribution build, the fix may be backported; check your vendor's advisory)"
            severity = Severity.HIGH
        fix = f"Upgrade runc to {' / '.join(fixed_in)} or newer and restart your containers."
        yield R.RUNC_CVE.hit(detail, severity, fix=fix)
