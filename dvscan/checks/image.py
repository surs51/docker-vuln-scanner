import re
from datetime import datetime, timezone

from dvscan import rules as R
from dvscan.checks.runtime import env_hits
from dvscan.model import is_root, parse_env, unpinned
from dvscan.secrets import check_variable, find_tokens

NOP_PREFIX = re.compile(r"^/bin/sh -c #\(nop\)\s*")
BUILD_ARGS = re.compile(r"^(?:RUN\s+)?\|(\d+)\s+(.*)$", re.S)
MAX_AGE_DAYS = 365


def check_image_config(ref, data):
    config = data.get("Config") or {}
    user = config.get("User") or ""
    if is_root(user):
        yield R.ROOT_USER.hit("Image runs as root (no USER set)" if not user else f"Image runs as root (USER {user})")

    yield from env_hits(parse_env(config.get("Env")), prefix="ENV ")

    test = (config.get("Healthcheck") or {}).get("Test") or []
    if not test or str(test[0]).upper() == "NONE":
        yield R.NO_HEALTHCHECK.hit("Image has no HEALTHCHECK")

    if unpinned(ref):
        yield R.LATEST_TAG.hit(f"{ref} is not pinned to a version")

    if "22/tcp" in (config.get("ExposedPorts") or {}):
        yield R.SSH_PORT.hit("Image EXPOSEs port 22")


def check_history(entries):
    seen = set()
    for entry in entries:
        command = NOP_PREFIX.sub("", (entry.get("CreatedBy") or "").strip())
        if command.upper().startswith("ENV "):
            continue
        for detail in _history_secrets(command):
            if detail not in seen:
                seen.add(detail)
                yield R.SECRET_IN_HISTORY.hit(detail)


def _history_secrets(command):
    if command.upper().startswith("ARG "):
        name, _, value = command[4:].strip().partition("=")
        reason = check_variable(name, value)
        if reason:
            yield f"ARG {name} default {reason}"
        return

    match = BUILD_ARGS.match(command)
    if match:
        count = int(match.group(1))
        parts = match.group(2).split(" ")
        command = " ".join(parts[count:])
        for pair in parts[:count]:
            name, _, value = pair.partition("=")
            reason = check_variable(name, value)
            if reason:
                yield f"Build argument {name} {reason}"

    for label in find_tokens(command):
        yield f"A layer's build command contains {label}"


def check_age(created, now=None):
    try:
        built = datetime.strptime((created or "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return
    if built.year < 2000:
        return
    days = ((now or datetime.now(timezone.utc)) - built).days
    if days > MAX_AGE_DAYS:
        yield R.STALE_IMAGE.hit(f"Built {days} days ago ({built:%Y-%m-%d})")
