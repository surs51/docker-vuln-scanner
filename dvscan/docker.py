import json
import subprocess

BATCH = 50


class DockerError(Exception):
    pass


class Docker:
    def __init__(self, binary="docker", timeout=60):
        self.binary = binary
        self.timeout = timeout

    def _exec(self, args, timeout=None):
        command = [self.binary, *args]
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout,
            )
        except FileNotFoundError:
            raise DockerError(f"'{self.binary}' was not found. Is Docker installed and on your PATH?") from None
        except subprocess.TimeoutExpired:
            raise DockerError(f"'{' '.join(command)}' timed out after {timeout or self.timeout}s") from None

    def run(self, *args, timeout=None):
        proc = self._exec(args, timeout)
        if proc.returncode != 0:
            raise DockerError(explain(proc.stderr, args))
        return proc.stdout

    def json(self, *args, timeout=None):
        output = self.run(*args, timeout=timeout)
        try:
            return json.loads(output or "null")
        except ValueError:
            raise DockerError(f"couldn't parse the output of 'docker {' '.join(args)}'") from None

    def version(self):
        return self.json("version", "--format", "{{json .}}")

    def info(self):
        return self.json("info", "--format", "{{json .}}")

    def container_ids(self, include_stopped=False):
        args = ["ps", "-q", "--no-trunc"] + (["-a"] if include_stopped else [])
        return self.run(*args).split()

    def inspect(self, refs, kind="container", errors=None):
        results = []
        refs = list(refs)
        for start in range(0, len(refs), BATCH):
            proc = self._exec(["inspect", "--type", kind, *refs[start:start + BATCH]])
            if proc.stdout.strip():
                try:
                    results.extend(json.loads(proc.stdout))
                except ValueError:
                    pass
            if proc.returncode != 0 and errors is not None:
                errors.extend(line.strip() for line in proc.stderr.splitlines() if line.strip())
        return results

    def inspect_image(self, ref):
        try:
            data = self.json("image", "inspect", ref)
        except DockerError:
            return None
        return data[0] if data else None

    def history(self, image):
        output = self.run("history", "--no-trunc", "--format", "{{json .}}", image)
        return [json.loads(line) for line in output.splitlines() if line.strip()]

    def processes(self, container):
        lines = self.run("top", container).splitlines()
        if not lines:
            return []
        header = lines[0]
        column = header.find("CMD")
        if column == -1:
            column = header.find("COMMAND")
        return [line[column:].strip() if column >= 0 else line for line in lines[1:]]

    def network_options(self, name):
        return self.json("network", "inspect", name, "--format", "{{json .Options}}") or {}

    def compose_config(self, files):
        args = ["compose"]
        for path in files:
            args += ["-f", str(path)]
        try:
            return self.json(*args, "config", "--format", "json", timeout=120)
        except DockerError as e:
            if "is not a docker command" in str(e) or "unknown command" in str(e):
                raise DockerError("scanning compose files needs Docker Compose v2 ('docker compose')") from None
            raise


def explain(stderr, args):
    text = (stderr or "").strip()
    lowered = text.lower()
    if "permission denied" in lowered and "docker" in lowered:
        return "permission denied talking to the Docker daemon. Run with sudo or add your user to the docker group."
    if "cannot connect to the docker daemon" in lowered or "is the docker daemon running" in lowered:
        return "can't reach the Docker daemon. Is it running?"
    if "error during connect" in lowered:
        return "can't reach the Docker daemon (error during connect). Is Docker running?"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    errors = [line for line in lines if "level=warn" not in line and not line.lower().startswith("warn")]
    if errors or lines:
        return (errors or lines)[0]
    return f"'docker {' '.join(args)}' failed"
