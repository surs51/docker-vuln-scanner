import pytest

from dvscan.checks.host import affected, check_host, parse_version
from dvscan.findings import Severity
from dvscan.model import HostInfo, host_from

LATEST = ("1.2.8", "1.3.3", "1.4.0-rc.3")


@pytest.mark.parametrize("version, fixed_in, expected", [
    ("1.1.11", ("1.1.12",), True),
    ("1.1.12", ("1.1.12",), False),
    ("1.0.0-rc93", ("1.1.12",), True),
    ("1.2.0", ("1.1.12",), False),
    ("1.1.14", LATEST, True),
    ("1.2.7", LATEST, True),
    ("1.2.8", LATEST, False),
    ("1.3.2", LATEST, True),
    ("1.3.3", LATEST, False),
    ("1.4.0-rc.2", LATEST, True),
    ("1.4.0-rc.3", LATEST, False),
    ("1.4.0", LATEST, False),
    ("1.5.1", LATEST, False),
])
def test_runc_version_ranges(version, fixed_in, expected):
    assert affected(parse_version(version), fixed_in) is expected


def test_distribution_runc_builds_are_downgraded():
    hits = list(check_host(HostInfo(runc="1.1.7-0ubuntu1~22.04.2", userns=True)))
    assert {h.rule.id for h in hits} == {"runc-cve"}
    assert all(h.severity == Severity.HIGH and "backported" in h.detail for h in hits)


def test_patched_host_is_clean():
    assert list(check_host(HostInfo(runc="1.3.3", userns=True, icc=False))) == []


def test_host_from_docker_info():
    version = {"Server": {"Version": "27.3.1", "Components": [{"Name": "runc", "Version": "1.2.8"}]}}
    info = {
        "OperatingSystem": "Debian GNU/Linux 12 (bookworm)",
        "SecurityOptions": ["name=apparmor", "name=seccomp,profile=unconfined", "name=rootless"],
        "RegistryConfig": {
            "InsecureRegistryCIDRs": ["127.0.0.0/8", "10.0.0.0/8"],
            "IndexConfigs": {
                "localhost:5000": {"Secure": False},
                "registry.lan": {"Secure": False},
                "docker.io": {"Secure": True},
            },
        },
        "Warnings": [
            "WARNING: API is accessible on http://0.0.0.0:2375 without encryption.\n"
            "         Access to the remote API is equivalent to root access on the host."
        ],
    }
    host = host_from(version, info, {"no-new-privileges": True})

    assert host.runc == "1.2.8" and host.rootless and not host.userns
    assert host.seccomp_profile == "unconfined"
    assert host.insecure_registries == ["10.0.0.0/8", "registry.lan"]
    assert host.exposed_api == ["http://0.0.0.0:2375"]
    assert host.no_new_privileges
    assert sorted(h.rule.id for h in check_host(host)) == [
        "daemon-seccomp", "daemon-tcp", "insecure-registry", "insecure-registry",
    ]


def test_local_host_problems():
    host = HostInfo(
        userns=True,
        lsm=False,
        socket_path="/var/run/docker.sock",
        socket_mode=0o140666,
        writable_configs=["/etc/docker/daemon.json"],
        docker_group=["deploy", "kali"],
    )
    assert [(h.rule.id, h.detail) for h in check_host(host)] == [
        ("socket-permissions", "/var/run/docker.sock is srw-rw-rw-, so any local user controls Docker"),
        ("daemon-config-writable", "/etc/docker/daemon.json can be changed by non-root users"),
        ("no-lsm", "Neither AppArmor nor SELinux is active, containers rely on seccomp and capabilities alone"),
        ("docker-group", "In the docker group: deploy, kali"),
    ]


def test_default_socket_permissions_are_fine():
    assert list(check_host(HostInfo(userns=True, socket_path="/var/run/docker.sock", socket_mode=0o140660))) == []


@pytest.mark.parametrize("options, lsm", [
    (["name=apparmor", "name=seccomp,profile=builtin"], True),
    (["name=selinux"], True),
    (["name=seccomp,profile=builtin", "name=cgroupns"], False),
    ([], None),
])
def test_lsm_detection(options, lsm):
    assert host_from({}, {"SecurityOptions": options}).lsm is lsm


def test_runc_version_from_commit_when_components_are_missing():
    host = host_from({}, {"RuncCommit": {"ID": "v1.1.12-0-g51d5e94"}})
    assert host.runc == "v1.1.12"
