# Docker Vulnerability Scanner (Python)

A Python-based security scanner for Docker containers that detects vulnerabilities, misconfigurations, and insecure practices. Designed for developers, DevOps engineers, and security teams, it provides actionable recommendations to harden your containers, and saves from human errors.


## Features

- Scan running Docker containers
- Detect Critical, High, Medium, and Low severity issues
- Provide remediation advice for each finding
- Human-readable CLI output
- Can be integrated into CI/CD pipelines

## Requirements

- Python 3.8+
- Docker installed and running
- Linux, macOS, or Windows (WSL2 recommended)
- sudo privileges (required to inspect containers)

## Installation

Clone the repository:

```bash
git clone https://github.com/surs51/docker-vuln-scanner.git
cd docker-vuln-scanner
```

## Usage

```bash
sudo python3 scanner.py paranoid > log.txt
```

> **Note** By default, published ports are exposed to all interfaces (0.0.0.0), and user namespace remapping is disabled unless configured in the Docker daemon. The scanner flags these cases.

## PoC

#### Docker set-up
```bash
docker run -d                                                                               
  --name nginx-insecure
  -p 8080:80
  nginx
```
```bash
docker run -d                                                                                          
  --name nginx-secure
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --memory 256m
  --cpus 0.5
  --pids-limit 64
  --tmpfs /tmp
  -p 8081:8082
  nginxinc/nginx-unprivileged
```

#### Scan & Scan Output
```bash
sudo python3 scanner.py paranoid
[+] Scan mode: paranoid
[+] Containers scanned: 2

[!] container: nginx-secure
    - MEDIUM: Port 8082/tcp exposed to 0.0.0.0
      -> FIX: Bind to specific interface
    - MEDIUM: User namespace remapping not enabled
      -> FIX: Enable userns-remap
    - LOW: No healthcheck configured
      -> FIX: Define HEALTHCHECK

[!] container: nginx-insecure
    - CRITICAL: Container runs as root
      -> FIX: Use non-root USER
    - MEDIUM: Root filesystem is writable
      -> FIX: Enable --read-only
    - MEDIUM: NoNewPrivileges not enabled
      -> FIX: Add --security-opt no-new-privileges
    - MEDIUM: Port 80/tcp exposed to 0.0.0.0
      -> FIX: Bind to specific interface
    - MEDIUM: No Linux capabilities dropped
      -> FIX: Drop all capabilities and add back only required ones
    - MEDIUM: User namespace remapping not enabled
      -> FIX: Enable userns-remap
    - LOW: No memory limit set
      -> FIX: Set memory limit
    - LOW: No CPU limit set
      -> FIX: Set CPU limit
    - LOW: No PID limit set
      -> FIX: Set --pids-limit
    - LOW: No healthcheck configured
      -> FIX: Define HEALTHCHECK

Scan complete.
```
