import json
import os
import socket
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    import grp
except ImportError:
    grp = None

from dvscan import cve
from dvscan.checks.dockerfile import scan_dockerfile
from dvscan.checks.host import check_host
from dvscan.checks.image import check_age, check_history, check_image_config
from dvscan.checks.runtime import check_processes, check_workload
from dvscan.compose import dockerfiles, find_default, image_ref, service_line, workload_from_compose
from dvscan.docker import DockerError
from dvscan.findings import MODES, Target
from dvscan.model import host_from, workload_from_inspect

DAEMON_CONFIGS = ("/etc/docker/daemon.json", "~/.config/docker/daemon.json")
DAEMON_FILES = (
    "/etc/docker",
    "/etc/docker/daemon.json",
    "/etc/default/docker",
    "/etc/sysconfig/docker",
    "/lib/systemd/system/docker.service",
    "/lib/systemd/system/docker.socket",
    "/usr/lib/systemd/system/docker.service",
    "/usr/lib/systemd/system/docker.socket",
    "/etc/systemd/system/docker.service",
    "/etc/systemd/system/docker.service.d",
    "/etc/systemd/system/docker.socket",
)
DEFAULT_SOCKET = "/var/run/docker.sock"
WORKERS = 8


class ScanError(Exception):
    pass


def scan_host(docker, args, report):
    scanner = _cve_scanner(args)
    host = load_host(docker)
    report.meta.update(docker=host.version, os=host.os, runc=host.runc)
    report.add(Target("host", _host_label(host))).hits = list(check_host(host))

    ids = args.containers or docker.container_ids(include_stopped=args.all)
    if not ids:
        report.notes.append(_empty_host_note(docker, args.all))
    containers = []
    for data in docker.inspect(ids, errors=report.errors):
        if (data.get("Platform") or "linux") != "linux":
            report.errors.append(f"skipped {data.get('Name', '').lstrip('/')}: only Linux containers are supported")
        else:
            containers.append(data)
    workloads = [workload_from_inspect(data) for data in containers]

    processes = {}
    if report.mode == "paranoid":
        processes = _gather(docker.processes, [w.id for w in workloads if w.running], report.errors)

    images = {}
    for data, workload in zip(containers, workloads):
        target = report.add(Target(
            "container", workload.name,
            ref=workload.id[:12],
            image=workload.image,
            status="" if workload.running else workload.status,
        ))
        target.ignore = label_ignores(workload.labels)
        target.hits = check_workload(workload, host) + list(check_processes(processes.get(workload.id, [])))
        entry = images.setdefault(data.get("Image") or workload.image, {"name": workload.image, "used_by": []})
        entry["used_by"].append(workload.name)

    entries = []
    for data in docker.inspect(list(images), kind="image", errors=report.errors):
        entry = images.get(data.get("Id")) or {"name": data.get("Id", ""), "used_by": []}
        entries.append((entry["name"], data, entry["used_by"]))
    _check_images(docker, args, report, entries, scanner, from_containers=True)


def scan_images(docker, args, report):
    scanner = _cve_scanner(args)
    docker.version()
    entries = []
    for ref in args.images:
        data = docker.inspect_image(ref)
        if data is None:
            report.errors.append(f"image {ref} isn't available locally (docker pull {ref} first)")
        else:
            entries.append((ref, data, []))
    if not entries:
        raise ScanError("none of the given images could be found locally")
    _check_images(docker, args, report, entries, scanner, from_containers=False)


def scan_dockerfiles(docker, args, report):
    for path in [Path(p) for p in args.paths] or [Path("Dockerfile")]:
        if path.is_dir():
            path = path / "Dockerfile"
        if not path.is_file():
            raise ScanError(f"{path} not found")
        _add_dockerfile(report, path)


def scan_compose(docker, args, report):
    files = [Path(f) for f in args.files]
    if not files:
        default = find_default()
        if default is None:
            raise ScanError("no compose file given, and none found in the current directory")
        files = [default]
    for path in files:
        if not path.is_file():
            raise ScanError(f"{path} not found")

    config = docker.compose_config(files) or {}
    project = config.get("name") or ""
    services = config.get("services") or {}
    text = files[0].read_text(encoding="utf-8", errors="replace")

    refs = {name: image_ref(project, name, service) for name, service in services.items()}
    images = _gather(docker.inspect_image, sorted(set(refs.values())), [])

    builds = {}
    for name, service in services.items():
        workload = workload_from_compose(name, service, images.get(refs[name]))
        target = report.add(Target(
            "service", name,
            image=workload.image,
            file=str(files[0]),
            line=service_line(text, name),
        ))
        target.ignore = label_ignores(workload.labels)
        target.hits = check_workload(workload)
        found = dockerfiles(service)
        if found:
            builds.setdefault(found[0].resolve(), found[1])

    for dockerfile, context in builds.items():
        _add_dockerfile(report, dockerfile, context)


def load_host(docker):
    version = docker.version()
    info = docker.info()
    docker_host = os.environ.get("DOCKER_HOST", "")
    local = not docker_host or docker_host.startswith(("unix://", "npipe://"))
    host = host_from(version, info, _daemon_config() if local else {})

    try:
        options = docker.network_options("bridge")
        host.icc = str(options.get("com.docker.network.bridge.enable_icc", "true")).lower() == "true"
    except DockerError:
        pass

    if docker_host.startswith("tcp://") and not (os.environ.get("DOCKER_TLS_VERIFY") or os.environ.get("DOCKER_TLS")):
        host.exposed_api.append(docker_host)
    elif local and not host.exposed_api and _api_answers("127.0.0.1", 2375):
        host.exposed_api.append("tcp://127.0.0.1:2375")

    if local and os.name == "posix":
        socket_path = docker_host[len("unix://"):] if docker_host.startswith("unix://") else DEFAULT_SOCKET
        inspect_local_files(host, socket_path)
    return host


def inspect_local_files(host, socket_path, files=DAEMON_FILES):
    try:
        host.socket_mode = os.stat(socket_path).st_mode
        host.socket_path = socket_path
    except OSError:
        pass

    for path in files:
        try:
            info = os.stat(path)
        except OSError:
            continue
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            continue
        group_writable = info.st_mode & stat.S_IWGRP and info.st_gid != 0
        if info.st_uid != 0 or info.st_mode & stat.S_IWOTH or group_writable:
            host.writable_configs.append(path)

    if grp is not None:
        try:
            host.docker_group = sorted(grp.getgrnam("docker").gr_mem)
        except KeyError:
            pass


def label_ignores(labels):
    raw = (labels or {}).get("dvscan.ignore") or ""
    return {part.strip() for part in raw.split(",") if part.strip()}


def _check_images(docker, args, report, entries, scanner, from_containers):
    deep = MODES.index(report.mode) >= MODES.index("full")
    ids = [data.get("Id") for _, data, _ in entries]
    histories = _gather(docker.history, ids, report.errors) if deep else {}

    for name, data, used_by in entries:
        target = report.add(Target("image", name, ref=_short(data.get("Id", "")), quiet=from_containers))
        target.used_by = used_by
        hits = [] if from_containers else list(check_image_config(name, data))
        hits += check_history(histories.get(data.get("Id"), []))
        hits += check_age(data.get("Created"))
        if scanner:
            ref = next(iter(data.get("RepoTags") or []), None) or data.get("Id")
            _progress(f"Scanning {ref} with {scanner[0]}...")
            try:
                hits += cve.scan_image(ref, *scanner, ignore_unfixed=args.ignore_unfixed)
            except cve.CveError as e:
                report.errors.append(str(e))
        target.hits = hits


def _empty_host_note(docker, include_stopped):
    stopped = 0 if include_stopped else len(docker.container_ids(include_stopped=True))
    if stopped:
        return f"No running containers. {stopped} stopped container{'s' if stopped != 1 else ''} can be scanned with -a."
    return "No containers on this host, so only the daemon was checked."


def _host_label(host):
    label = f"Docker {host.version}"
    if host.os:
        label += f" on {host.os}"
    if host.runc:
        label += f", runc {host.runc}"
    return label


def _add_dockerfile(report, path, context=None):
    hits, ignores = scan_dockerfile(path, context)
    target = report.add(Target("dockerfile", _display(path), file=str(path)))
    target.hits, target.line_ignores = hits, ignores


def _cve_scanner(args):
    if not getattr(args, "cve", False):
        return None
    try:
        return cve.find_scanner(args.scanner)
    except cve.CveError as e:
        raise ScanError(str(e)) from None


def _daemon_config():
    for candidate in DAEMON_CONFIGS:
        try:
            return json.loads(Path(candidate).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return {}


def _api_answers(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n")
            reply = b""
            while len(reply) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                reply += chunk
    except OSError:
        return False
    return b"ApiVersion" in reply


def _gather(fn, items, errors):
    results = {}
    if not items:
        return results
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(items))) as pool:
        futures = {item: pool.submit(fn, item) for item in items}
        for item, future in futures.items():
            try:
                results[item] = future.result()
            except DockerError as e:
                errors.append(f"{_short(item)}: {e}")
    return results


def _short(ref):
    ref = str(ref or "")
    bare = ref.removeprefix("sha256:")
    return bare[:12] if len(bare) == 64 else ref


def _display(path):
    try:
        relative = os.path.relpath(path)
    except ValueError:
        return str(path)
    return str(path) if relative.startswith("..") else relative


def _progress(message):
    if sys.stderr.isatty():
        print(message, file=sys.stderr)
