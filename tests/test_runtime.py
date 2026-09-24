import pytest

from dvscan.checks.runtime import check_processes
from dvscan.findings import Severity
from dvscan.model import HostInfo
from helpers import bind, find, ids, inspect, ports, scan


def test_hardened_container_is_clean():
    assert scan(inspect()) == []


@pytest.mark.parametrize("user", ["", "0", "root", "0:0", "root:root"])
def test_root_users(user):
    assert ids(scan(inspect({"User": user}))) == ["root-user"]


@pytest.mark.parametrize("user", ["1000", "app", "1000:1000", "nobody:nogroup"])
def test_non_root_users(user):
    assert scan(inspect({"User": user})) == []


def test_root_is_low_risk_with_userns_remap():
    [hit] = find(scan(inspect({"User": ""}), HostInfo(userns=True)), "root-user")
    assert hit.severity == Severity.LOW


def test_opting_out_of_userns_keeps_root_high():
    hits = scan(inspect({"User": ""}, {"UsernsMode": "host"}), HostInfo(userns=True))
    assert find(hits, "root-user")[0].severity == Severity.HIGH
    assert "host-namespace" in ids(hits)


def test_privileged_does_not_repeat_what_it_implies():
    hits = scan(inspect(host={
        "Privileged": True,
        "CapAdd": ["SYS_ADMIN"],
        "CapDrop": None,
        "SecurityOpt": ["seccomp=unconfined", "no-new-privileges"],
        "Devices": [{"PathOnHost": "/dev/sda"}],
    }))
    assert ids(hits) == ["privileged"]


def test_capabilities_are_normalized():
    hits = scan(inspect(host={"CapAdd": ["CAP_SYS_ADMIN", "net_admin"]}))
    assert [h.detail for h in find(hits, "dangerous-capability")] == ["CAP_NET_ADMIN added", "CAP_SYS_ADMIN added"]


def test_cap_add_all_is_critical():
    [hit] = find(scan(inspect(host={"CapAdd": ["ALL"]})), "dangerous-capability")
    assert hit.severity == Severity.CRITICAL


def test_ptrace_with_host_pid_is_critical():
    hits = scan(inspect(host={"CapAdd": ["SYS_PTRACE"], "PidMode": "host"}))
    assert find(hits, "dangerous-capability")[0].severity == Severity.CRITICAL


def test_sys_admin_without_seccomp_is_critical():
    hits = scan(inspect(host={"CapAdd": ["SYS_ADMIN"], "SecurityOpt": ["seccomp=unconfined", "no-new-privileges"]}))
    [hit] = find(hits, "dangerous-capability")
    assert hit.severity == Severity.CRITICAL and "seccomp turned off" in hit.detail


def test_partial_cap_drop_is_reported():
    [hit] = find(scan(inspect(host={"CapDrop": ["NET_RAW"]})), "cap-drop")
    assert "NET_RAW" in hit.detail


@pytest.mark.parametrize("option, expected", [
    ("seccomp=unconfined", "seccomp-disabled"),
    ("seccomp:unconfined", "seccomp-disabled"),
    ("apparmor=unconfined", "apparmor-disabled"),
    ("label:disable", "selinux-disabled"),
    ("systempaths=unconfined", "unmasked-paths"),
])
def test_security_options(option, expected):
    assert ids(scan(inspect(host={"SecurityOpt": [option, "no-new-privileges"]}))) == [expected]


def test_custom_seccomp_profile_is_fine():
    profile = 'seccomp={"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}'
    assert scan(inspect(host={"SecurityOpt": [profile, "no-new-privileges"]})) == []


def test_no_new_privileges_false_does_not_count():
    assert ids(scan(inspect(host={"SecurityOpt": ["no-new-privileges:false"]}))) == ["no-new-privileges"]


def test_daemon_wide_no_new_privileges():
    assert scan(inspect(host={"SecurityOpt": None}), HostInfo(no_new_privileges=True)) == []


@pytest.mark.parametrize("source", ["/var/run/docker.sock", "/run/user/1000/docker.sock", "/run", "/var/run/"])
def test_runtime_sockets(source):
    assert ids(scan(inspect(Mounts=[bind(source, rw=False)]))) == ["docker-socket"]


@pytest.mark.parametrize("source, rw, severity", [
    ("/", True, Severity.CRITICAL),
    ("/", False, Severity.HIGH),
    ("/etc", False, Severity.HIGH),
    ("//etc//", True, Severity.CRITICAL),
    ("/home/deploy/.ssh", False, Severity.HIGH),
    ("/proc/sys", True, Severity.HIGH),
])
def test_sensitive_mounts(source, rw, severity):
    [hit] = scan(inspect(Mounts=[bind(source, rw=rw)]))
    assert hit.rule.id == "sensitive-mount" and hit.severity == severity


@pytest.mark.parametrize("source", ["/etc/nginx/conf.d", "/srv/app/data", "/etc/passwd", "/proc/cpuinfo"])
def test_ordinary_mounts(source):
    assert scan(inspect(Mounts=[bind(source, rw=False)])) == []


def test_named_volumes_are_not_host_paths():
    volume = {"Type": "volume", "Source": "/var/lib/docker/volumes/x/_data", "Destination": "/data", "RW": True}
    assert scan(inspect(Mounts=[volume])) == []


def test_shared_propagation():
    assert ids(scan(inspect(Mounts=[bind("/srv/data", propagation="rshared")]))) == ["mount-propagation"]


def test_database_on_all_interfaces():
    hits = scan(inspect(NetworkSettings={"Ports": ports("5432/tcp", ("0.0.0.0", "5432"), ("::", "5432"))}))
    assert ids(hits) == ["sensitive-port"]
    assert "127.0.0.1:5432:5432" in hits[0].fix


def test_database_on_localhost():
    assert scan(inspect(NetworkSettings={"Ports": ports("5432/tcp", ("127.0.0.1", "5432"))})) == []


def test_remapped_sensitive_port_is_matched_on_the_container_port():
    [hit] = scan(inspect(NetworkSettings={"Ports": ports("6379/tcp", ("0.0.0.0", "16379"))}))
    assert hit.rule.id == "sensitive-port" and "0.0.0.0:16379" in hit.detail


def test_web_ports_are_expected_to_be_public():
    assert scan(inspect(NetworkSettings={"Ports": ports("443/tcp", ("0.0.0.0", "443"))})) == []


def test_other_public_ports():
    assert ids(scan(inspect(NetworkSettings={"Ports": ports("3000/tcp", ("", "3000"))}))) == ["exposed-port"]


def test_stopped_container_falls_back_to_port_bindings():
    data = inspect(
        host={"PortBindings": ports("6379/tcp", ("", "6379"))},
        State={"Running": False, "Status": "exited"},
    )
    assert ids(scan(data)) == ["sensitive-port"]


def test_resource_limits():
    hits = scan(inspect(host={"Memory": 0, "NanoCpus": 0, "PidsLimit": -1}))
    assert ids(hits) == ["no-cpu-limit", "no-memory-limit", "no-pids-limit"]


def test_cpu_quota_counts_as_a_limit():
    assert scan(inspect(host={"NanoCpus": 0, "CpuQuota": 50000})) == []


def test_oom_killer_disabled_without_memory_limit():
    assert "oom-kill-disabled" in ids(scan(inspect(host={"Memory": 0, "OomKillDisable": True})))


def test_disabled_healthcheck():
    [hit] = scan(inspect({"Healthcheck": {"Test": ["NONE"]}}))
    assert hit.rule.id == "no-healthcheck" and "disabled" in hit.detail


@pytest.mark.parametrize("image", ["nginx", "nginx:latest", "registry.local:5000/app"])
def test_unpinned_images(image):
    assert ids(scan(inspect({"Image": image}))) == ["latest-tag"]


@pytest.mark.parametrize("image", ["nginx:1.27", "registry.local:5000/app:2.1", "nginx@sha256:" + "a" * 64])
def test_pinned_images(image):
    assert scan(inspect({"Image": image})) == []


def test_device_passthrough():
    hits = scan(inspect(host={
        "Devices": [{"PathOnHost": "/dev/sda"}, {"PathOnHost": "/dev/snd"}],
        "DeviceCgroupRules": ["a *:* rwm"],
    }))
    assert [h.severity for h in hits] == [Severity.CRITICAL, Severity.MEDIUM, Severity.CRITICAL]


def test_host_network_and_default_bridge():
    assert ids(scan(inspect(host={"NetworkMode": "host"}))) == ["host-namespace"]
    assert ids(scan(inspect(host={"NetworkMode": "bridge"}))) == ["default-bridge"]


def test_secrets_and_insecure_settings_in_env():
    env = ["DB_PASSWORD=hunter2", "DB_PASSWORD_FILE=/run/secrets/db", "POSTGRES_HOST_AUTH_METHOD=trust"]
    hits = scan(inspect({"Env": env}))
    assert [(h.rule.id, h.detail) for h in hits] == [
        ("secret-in-env", "DB_PASSWORD looks like a credential"),
        ("insecure-env", "POSTGRES_HOST_AUTH_METHOD: PostgreSQL accepts logins without a password"),
    ]


def test_sshd_process():
    assert [h.rule.id for h in check_processes(["nginx: master process", "/usr/sbin/sshd -D"])] == ["sshd-running"]
    assert list(check_processes(["sshd-exporter --port 9100"])) == []
