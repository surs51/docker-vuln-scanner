# Docker Vulnerability Scanner

`dvscan` looks for the mistakes that actually get Docker hosts compromised: privileged containers, a mounted Docker socket, Redis published on `0.0.0.0`, passwords sitting in environment variables or image history, a runc with a known container escape, a daemon API listening on TCP without TLS.

It scans a live host, and it also checks Dockerfiles and Compose files before anything is deployed, so it fits into CI. All you need is Python 3.9+ and the Docker CLI. There are no other dependencies.

## What it checks

- **Host and daemon**: runc versions with known escapes (CVE-2024-21626, CVE-2025-31133/52565/52881), the Docker API exposed over TCP without TLS, a world-writable `docker.sock`, daemon config and systemd units that non-root users can edit, who holds root-equivalent access through the `docker` group, missing AppArmor/SELinux, seccomp turned off daemon-wide, insecure registries, userns-remap, and inter-container traffic on the default bridge.
- **Containers**: privileged mode, runtime sockets (Docker, containerd, Podman, CRI-O), sensitive host paths (`/`, `/etc`, `/proc`, `~/.ssh`, ...), dangerous capabilities, host namespaces, seccomp/AppArmor/SELinux turned off, host devices, databases and admin ports published on all interfaces, secrets and insecure settings in environment variables, running as root, missing hardening, and missing resource limits.
- **Images**: secrets baked into the build history (build args end up there), images over a year old, and known CVEs through trivy or grype if you have one installed.
- **Dockerfiles**: running as root, `curl | sh`, disabled TLS or signature checks, hardcoded secrets and secret build args, unpinned base images, `ADD` from a URL without a checksum, `chmod 777`, and `COPY . .` without a `.dockerignore`.
- **Compose files**: the same runtime checks as for containers, before you deploy, plus the Dockerfiles of any services that get built.

`dvscan rules` lists all 52 checks with their severity and the mode they belong to.

## Install

```bash
pipx install git+https://github.com/surs51/docker-vuln-scanner
```

Or run it from a clone without installing anything:

```bash
git clone https://github.com/surs51/docker-vuln-scanner.git
cd docker-vuln-scanner
python3 scanner.py
```

## Usage

```bash
dvscan                                  # daemon, running containers and their images
dvscan paranoid                         # same, with every check turned on
dvscan host -a web db                   # only these containers, stopped ones included
dvscan image myapp:1.4 --cve            # a local image, including known CVEs
dvscan dockerfile ./Dockerfile
dvscan compose compose.yaml compose.prod.yaml
```

You only need `sudo` if your user can't talk to the Docker daemon (i.e. isn't in the `docker` group).

### Modes

| Mode | Adds |
| --- | --- |
| `basic` | Anything that hands over the host or leaks credentials: privileged containers, sockets, sensitive mounts, capabilities, exposed databases, secrets, root |
| `full` (default) | Hardening: read-only rootfs, no-new-privileges, dropped capabilities, resource limits, healthchecks, pinned images, build history |
| `paranoid` | Defense in depth: userns-remap, default bridge, icc, sshd inside containers, logging, stale images |

### Options

```
-m, --mode MODE         basic, full or paranoid
-f, --format FORMAT     text, json or sarif
-o, --output FILE       write the report to a file
--min-severity LEVEL    hide anything below low, medium, high or critical
--fail-on LEVEL         exit with 1 if anything at LEVEL or above is found
--ignore IDS            skip rule or CVE IDs, e.g. --ignore no-cpu-limit,CVE-2024-6119
--cve                   look up known CVEs with trivy or grype (host and image scans)
--ignore-unfixed        with --cve, skip vulnerabilities that have no fix yet
--docker BIN            docker binary to call, also settable with DVSCAN_DOCKER
```

Exit codes: `0` means the scan ran, `1` means something at or above `--fail-on` turned up, and `2` means the scan couldn't run at all (Docker missing, daemon down, file not found).

## Accepting a risk

Some containers legitimately need things that are normally dangerous. Portainer needs the Docker socket, and node-exporter needs `/proc` and `/sys`. Label them and dvscan will leave those checks alone:

```bash
docker run -d --label dvscan.ignore=docker-socket \
  -v /var/run/docker.sock:/var/run/docker.sock portainer/portainer-ce:2.21.4
```

The same label works in Compose under `labels:`. In a Dockerfile, put a comment on the line above the instruction:

```dockerfile
# dvscan ignore=pipe-to-shell
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y
```

Ignored findings are still counted in the summary, so you can see they exist.

## CI

Check the Dockerfile and Compose file on every pull request, and get the results as annotations in GitHub code scanning:

```yaml
name: dvscan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: pipx install git+https://github.com/surs51/docker-vuln-scanner
      - run: dvscan dockerfile Dockerfile -f sarif -o dvscan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: dvscan.sarif
      - run: dvscan compose compose.yaml --fail-on high
```

## PoC

#### Docker set-up

```bash
docker run -d \
  --name nginx-insecure \
  -p 8080:80 \
  nginx
```

```bash
docker run -d \
  --name nginx-secure \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 256m \
  --cpus 0.5 \
  --pids-limit 64 \
  --tmpfs /tmp \
  -p 8081:8082 \
  nginxinc/nginx-unprivileged
```

#### Scan & output

```
$ dvscan
dvscan 2.0.0 - mode: full

[!] host Docker 27.3.1 on Ubuntu 24.04.1 LTS, runc 1.1.14
    CRITICAL  runc 1.1.14 is affected by CVE-2025-31133, CVE-2025-52565, CVE-2025-52881: mount races let a container write to host /proc files and break out [runc-cve]
              -> Upgrade runc to 1.2.8 / 1.3.3 / 1.4.0-rc.3 or newer and restart your containers.

[!] container nginx-insecure (3f2a9c1b7d0e, nginx)
    HIGH      Runs as root (no user set) [root-user]
              -> Add a non-root USER to the Dockerfile, or run with --user 1000:1000.
    MEDIUM    Runs with Docker's default capability set [cap-drop]
              -> Use --cap-drop ALL and add back only the capabilities the workload needs.
    MEDIUM    no-new-privileges is not set, so setuid binaries can raise privileges [no-new-privileges]
              -> Run with --security-opt no-new-privileges:true, or set "no-new-privileges": true in
                 daemon.json.
    MEDIUM    Writable root filesystem [writable-rootfs]
              -> Run with --read-only and mount a tmpfs for the paths that need writes, like /tmp.
    LOW       Uses nginx, which is not pinned to a version [latest-tag]
              -> Use a specific version tag, or better, pin by digest (image@sha256:...).
    LOW       No CPU limit [no-cpu-limit]
              -> Set --cpus (cpus or deploy.resources.limits.cpus in Compose).
    LOW       No healthcheck [no-healthcheck]
              -> Add a HEALTHCHECK so a hung process gets noticed and restarted.
    LOW       No memory limit [no-memory-limit]
              -> Set --memory (mem_limit or deploy.resources.limits.memory in Compose).
    LOW       No PID limit [no-pids-limit]
              -> Set --pids-limit so a fork bomb can't take down the host.

[!] container nginx-secure (a91d0c33e2b4, nginxinc/nginx-unprivileged)
    LOW       8082/tcp published on 0.0.0.0:8081 [exposed-port]
              -> If it only needs to be reachable locally or through a reverse proxy, bind it to
                 127.0.0.1. Docker's port rules bypass host firewalls such as ufw.
    LOW       Uses nginxinc/nginx-unprivileged, which is not pinned to a version [latest-tag]
              -> Use a specific version tag, or better, pin by digest (image@sha256:...).
    LOW       No healthcheck [no-healthcheck]
              -> Add a HEALTHCHECK so a hung process gets noticed and restarted.

Summary: 3 targets, 13 findings: 1 critical, 1 high, 3 medium, 8 low
```

> **Note:** Published ports bind to all interfaces (`0.0.0.0`) unless you give an address, and Docker writes its own iptables rules, so `ufw` and similar firewalls won't block them. Port 80/443 on a web server is expected. A database on `0.0.0.0` usually isn't.

## Test lab

`lab/up.sh` starts a set of deliberately broken containers next to a hardened one: privileged, a mounted Docker socket, Redis and Postgres on `0.0.0.0`, a secret baked into image history, sshd running inside a container. Run it in a throwaway VM, never on a real server.

```bash
bash lab/up.sh
python3 scanner.py paranoid
python3 scanner.py dockerfile lab/Dockerfile
python3 scanner.py compose lab/compose.yaml
bash lab/down.sh
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

The checks work on plain `docker inspect` JSON, so the tests don't need Docker running.
