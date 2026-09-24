import copy

from dvscan.checks.runtime import check_workload
from dvscan.model import workload_from_inspect

HARDENED = {
    "Id": "f" * 64,
    "Name": "/web",
    "Image": "sha256:" + "0" * 64,
    "Platform": "linux",
    "AppArmorProfile": "docker-default",
    "State": {"Running": True, "Status": "running"},
    "Config": {
        "User": "1000",
        "Image": "nginx:1.27",
        "Env": ["PATH=/usr/local/bin:/usr/bin"],
        "Healthcheck": {"Test": ["CMD", "true"]},
        "Labels": {},
    },
    "HostConfig": {
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "Memory": 268435456,
        "NanoCpus": 500000000,
        "PidsLimit": 100,
        "NetworkMode": "app_default",
        "LogConfig": {"Type": "json-file"},
    },
    "Mounts": [],
    "NetworkSettings": {"Ports": {}},
}


def inspect(config=None, host=None, **fields):
    data = copy.deepcopy(HARDENED)
    data["Config"].update(config or {})
    data["HostConfig"].update(host or {})
    data.update(fields)
    return data


def scan(data, host=None):
    return check_workload(workload_from_inspect(data), host)


def ids(hits):
    return sorted(hit.rule.id for hit in hits)


def find(hits, rule_id):
    return [hit for hit in hits if hit.rule.id == rule_id]


def bind(source, target="/mnt", rw=True, propagation="rprivate"):
    return {"Type": "bind", "Source": source, "Destination": target, "RW": rw, "Propagation": propagation}


def ports(spec, *bindings):
    return {spec: [{"HostIp": ip, "HostPort": port} for ip, port in bindings]}
