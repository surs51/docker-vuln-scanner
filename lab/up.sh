#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

start() {
  local name=$1
  shift
  docker run -d --name "$name" "$@" >/dev/null
  echo "started $name"
}

bash down.sh
docker network create dvscan-lab >/dev/null
docker build -q --build-arg NPM_TOKEN=lab-not-a-real-token -t dvscan-lab/leaky:1.0 . >/dev/null
echo "built dvscan-lab/leaky:1.0"

start lab-privileged --privileged alpine:3.20 sleep infinity
start lab-socket -v /var/run/docker.sock:/var/run/docker.sock:ro alpine:3.20 sleep infinity
start lab-escape --pid host --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  -v /etc:/host/etc alpine:3.20 sleep infinity
start lab-redis -p 6379:6379 redis:7.4
start lab-postgres -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16
start lab-leaky -p 2222:22 dvscan-lab/leaky:1.0
start lab-sshd alpine:3.20 \
  sh -c "apk add --no-cache openssh >/dev/null && ssh-keygen -A >/dev/null && exec /usr/sbin/sshd -D"
start lab-accepted --label dvscan.ignore=docker-socket \
  -v /var/run/docker.sock:/var/run/docker.sock:ro alpine:3.20 sleep infinity
start lab-hardened --network dvscan-lab --read-only --cap-drop ALL \
  --security-opt no-new-privileges --memory 128m --cpus 0.5 --pids-limit 64 \
  --user 999 --health-cmd "redis-cli ping" redis:7.4

echo
echo "Lab is up. Scan it with: python3 scanner.py paranoid"
