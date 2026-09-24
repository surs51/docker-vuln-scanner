#!/usr/bin/env bash

docker rm -f lab-privileged lab-socket lab-escape lab-redis lab-postgres \
  lab-leaky lab-sshd lab-accepted lab-hardened >/dev/null 2>&1
docker network rm dvscan-lab >/dev/null 2>&1
docker rmi dvscan-lab/leaky:1.0 >/dev/null 2>&1
exit 0
