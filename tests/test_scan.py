import os
from argparse import Namespace

import pytest

from dvscan import scan
from dvscan.findings import Report
from dvscan.model import HostInfo
from helpers import bind, inspect

IMAGE_ID = "sha256:" + "1" * 64
original = scan.inspect_local_files


class FakeDocker:
    def __init__(self, containers=(), images=(), images_by_ref=None, compose=None):
        self.containers = list(containers)
        self.images = list(images)
        self.images_by_ref = images_by_ref or {}
        self.compose = compose

    def version(self):
        return {"Server": {"Version": "27.3.1", "Components": [{"Name": "runc", "Version": "1.3.3"}]}}

    def info(self):
        return {
            "OperatingSystem": "Ubuntu 24.04",
            "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin", "name=userns"],
        }

    def network_options(self, name):
        return {"com.docker.network.bridge.enable_icc": "false"}

    def container_ids(self, include_stopped=False):
        return [c["Id"] for c in self.containers if include_stopped or c["State"]["Running"]]

    def inspect(self, refs, kind="container", errors=None):
        pool = self.containers if kind == "container" else self.images
        return [item for item in pool if item["Id"] in refs]

    def processes(self, container):
        return ["/usr/sbin/sshd -D"]

    def history(self, image):
        return [{"CreatedBy": "RUN |1 GITHUB_TOKEN=ghp_" + "x" * 36 + " /bin/sh -c make"}]

    def inspect_image(self, ref):
        return self.images_by_ref.get(ref)

    def compose_config(self, files):
        return self.compose


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(scan, "_api_answers", lambda *args: False)
    monkeypatch.setattr(scan, "_daemon_config", dict)
    monkeypatch.setattr(scan, "inspect_local_files", lambda *args: None)
    monkeypatch.delenv("DOCKER_HOST", raising=False)


def host_args(**overrides):
    values = {"containers": [], "all": False, "cve": False, "scanner": None, "ignore_unfixed": False}
    values.update(overrides)
    return Namespace(**values)


def run(fn, docker, args, mode="full"):
    report = Report(mode)
    fn(docker, args, report)
    report.apply_filters()
    return report


def fleet():
    web = inspect(Image=IMAGE_ID)
    stopped = inspect({"User": ""}, Id="e" * 64, Name="/old", State={"Running": False, "Status": "exited"})
    image = {"Id": IMAGE_ID, "RepoTags": ["nginx:1.27"], "Created": "2026-09-01T00:00:00Z", "Config": {}}
    return FakeDocker([web, stopped], [image])


def test_host_scan():
    report = run(scan.scan_host, fleet(), host_args(), mode="paranoid")
    assert {t.name: [h.rule.id for h in t.hits] for t in report.targets} == {
        "Docker 27.3.1 on Ubuntu 24.04, runc 1.3.3": [],
        "web": ["sshd-running"],
        "nginx:1.27": ["secret-in-history"],
    }
    assert report.targets[2].used_by == ["web"]


def test_stopped_containers_on_request():
    report = run(scan.scan_host, fleet(), host_args(all=True))
    old = next(t for t in report.targets if t.name == "old")
    assert old.status == "exited" and [h.rule.id for h in old.hits] == ["root-user"]


def test_labels_can_accept_a_risk():
    portainer = inspect(
        {"Labels": {"dvscan.ignore": "docker-socket"}},
        Mounts=[bind("/var/run/docker.sock", "/var/run/docker.sock")],
    )
    report = run(scan.scan_host, FakeDocker([portainer]), host_args())
    assert report.ignored == 1 and report.worst() is None


def test_empty_host_says_so():
    report = run(scan.scan_host, FakeDocker(), host_args())
    assert report.notes == ["No containers on this host, so only the daemon was checked."]


def test_empty_host_points_at_stopped_containers():
    stopped = inspect(State={"Running": False, "Status": "exited"})
    report = run(scan.scan_host, FakeDocker([stopped]), host_args())
    assert report.notes == ["No running containers. 1 stopped container can be scanned with -a."]


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX permissions")
def test_local_file_permissions(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_text("")
    sock.chmod(0o666)
    config = tmp_path / "daemon.json"
    config.write_text("{}")
    config.chmod(0o666)

    host = HostInfo()
    original(host, str(sock), files=[str(config), str(tmp_path / "missing.json")])
    assert host.socket_mode & 0o002
    assert host.writable_configs == [str(config)]


def test_plain_tcp_docker_host(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.5:2375")
    monkeypatch.delenv("DOCKER_TLS_VERIFY", raising=False)
    monkeypatch.delenv("DOCKER_TLS", raising=False)
    report = run(scan.scan_host, FakeDocker(), host_args())
    assert [h.detail for h in report.targets[0].hits] == ["Docker API answers on tcp://10.0.0.5:2375 without TLS"]


def test_compose_scan(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Dockerfile").write_text("FROM python:3.12\nCMD python\n")
    compose_file = tmp_path / "compose.yaml"
    compose_file.write_text("services:\n  api:\n    build: ./app\n  cache:\n    image: redis:7.4\n")
    config = {
        "name": "demo",
        "services": {
            "api": {"build": {"context": str(tmp_path / "app"), "dockerfile": "Dockerfile"}, "user": "1000"},
            "cache": {"image": "redis:7.4", "ports": [{"target": 6379, "published": "6379", "protocol": "tcp"}]},
        },
    }
    docker = FakeDocker(images_by_ref={"redis:7.4": {"Config": {"User": ""}}}, compose=config)

    report = run(scan.scan_compose, docker, Namespace(files=[str(compose_file)]), mode="basic")
    found = {(t.kind, t.line): sorted(h.rule.id for h in t.hits) for t in report.targets}
    assert found == {
        ("service", 2): [],
        ("service", 4): ["root-user", "sensitive-port"],
        ("dockerfile", None): ["root-user"],
    }


def test_missing_compose_file(tmp_path):
    with pytest.raises(scan.ScanError, match="not found"):
        scan.scan_compose(FakeDocker(), Namespace(files=[str(tmp_path / "nope.yaml")]), Report("full"))
