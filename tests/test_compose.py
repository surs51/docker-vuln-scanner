from dvscan.checks.runtime import check_workload
from dvscan.compose import service_line, workload_from_compose

HARDENED = {
    "image": "app:1.0",
    "user": "1000",
    "read_only": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "mem_limit": "268435456",
    "cpus": 0.5,
    "pids_limit": 100,
    "healthcheck": {"test": ["CMD", "true"]},
}


def lint(service, image=None):
    return sorted(h.rule.id for h in check_workload(workload_from_compose("web", service, image)))


def test_hardened_service():
    assert lint(HARDENED) == []


def test_deploy_limits_count():
    service = {k: v for k, v in HARDENED.items() if k not in ("mem_limit", "cpus", "pids_limit")}
    service["deploy"] = {"resources": {"limits": {"memory": "512M", "cpus": "1.5", "pids": 50}}}
    assert lint(service) == []


def test_user_falls_back_to_the_local_image():
    service = dict(HARDENED, user="")
    assert lint(service, {"Config": {"User": "nginx"}}) == []
    assert lint(service, {"Config": {"User": ""}}) == ["root-user"]


def test_unknown_image_user_is_reported_with_less_confidence():
    hits = check_workload(workload_from_compose("web", dict(HARDENED, user=""), None))
    assert [(h.rule.id, str(h.severity)) for h in hits] == [("root-user", "medium")]


def test_built_services_leave_image_checks_to_the_dockerfile():
    service = dict(HARDENED, user="", build={"context": "."})
    del service["healthcheck"]
    assert lint(service) == []


def test_ports_volumes_and_privileges():
    service = dict(
        HARDENED,
        ports=[
            {"target": 6379, "published": "6379", "protocol": "tcp"},
            {"target": 8080, "published": "8080", "host_ip": "127.0.0.1"},
        ],
        volumes=[{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock", "read_only": True}],
        devices=["/dev/kmsg:/dev/kmsg"],
        privileged=True,
    )
    assert lint(service) == ["docker-socket", "privileged", "sensitive-port"]


def test_healthcheck_can_be_disabled():
    assert lint(dict(HARDENED, healthcheck={"disable": True})) == ["no-healthcheck"]


def test_service_line_skips_nested_keys():
    text = (
        "services:\n"
        "  web:\n"
        "    depends_on:\n"
        "      db:\n"
        "        condition: service_healthy\n"
        "  db:\n"
        "    image: postgres:16\n"
        "volumes:\n"
        "  db:\n"
    )
    assert service_line(text, "db") == 6
    assert service_line(text, "web") == 2
    assert service_line(text, "missing") is None
