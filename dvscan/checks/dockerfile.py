from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from dvscan import rules as R
from dvscan.model import is_root, unpinned
from dvscan.secrets import check_variable, find_tokens, insecure_setting, secret_name

DIRECTIVE = re.compile(r"#\s*([a-zA-Z]+)\s*=\s*(\S+)\s*$")
IGNORE = re.compile(r"#\s*dvscan\s+ignore\s*=\s*(.+)$", re.I)
HEREDOC = re.compile(r"<<(-?)([\"']?)([A-Za-z_][\w-]*)\2")

NON_ROOT_BASES = ("nonroot", "unprivileged", "rootless")
ARCHIVES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst")
REMOTE = ("http://", "https://")

INTERPRETER = r"(?:/\S*/)?(?:(?:ba|z|da|k|a)?sh|python[\d.]*|perl|ruby|node|php)\b"
PIPE_TO_SHELL = (
    re.compile(r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?" + INTERPRETER),
    re.compile(r"\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?\$\(\s*(?:curl|wget)\b"),
    re.compile(r"<\(\s*(?:curl|wget)\b"),
)
INSECURE_FLAGS = (
    ("curl --insecure", re.compile(r"\bcurl\b[^|;&\n]*?\s(?:-[a-zA-Z]*k[a-zA-Z]*|--insecure)(?=\s|$)")),
    ("wget --no-check-certificate", re.compile(r"\bwget\b[^|;&\n]*?\s--no-check-certificate\b")),
    ("pip --trusted-host", re.compile(r"\bpip[\d.]*\b[^|;&\n]*?\s--trusted-host\b")),
    ("strict-ssl false", re.compile(r"\b(?:npm|yarn|pnpm)\b[^|;&\n]*strict-ssl[\s=]+false\b")),
    ("git http.sslVerify=false", re.compile(r"http\.sslverify[\s=]+false\b", re.I)),
    ("unauthenticated apt packages", re.compile(r"--allow-unauthenticated\b|--allow-insecure-repositories\b|\[trusted=yes\]")),
    ("apk --allow-untrusted", re.compile(r"--allow-untrusted\b")),
    ("disabled GPG checks", re.compile(r"--nogpgcheck\b|\bgpgcheck\s*=\s*0\b")),
    ("a plain-HTTP package index", re.compile(r"--(?:index-url|extra-index-url|registry)[\s=]+http://")),
)
CHMOD = re.compile(r"\bchmod\s+(?:-\S+\s+)*(?:0?[0-7]{2}[2367]|[ugoa]*[oa][ugoa]*[+=][rwxXst]*w[rwxXst]*)(?=\s|$)")
SUDO = re.compile(r"(?:^|&&|\|\||[;|(]|\bthen|\bdo)\s*sudo\s")
URL_CREDENTIALS = re.compile(r"://[^/@\s]+@")


@dataclass
class Instruction:
    line: int
    keyword: str
    value: str
    heredocs: list = field(default_factory=list)
    ignore: set = field(default_factory=set)

    @property
    def text(self):
        return "\n".join([self.value, *self.heredocs])


@dataclass(eq=False)
class Stage:
    base: str
    alias: str
    line: int
    parent: Stage | None = None
    user: str | None = None
    user_line: int | None = None
    healthcheck: bool | None = None
    healthcheck_line: int | None = None

    def lineage(self):
        stage = self
        while stage is not None:
            yield stage
            stage = stage.parent

    def origin(self):
        return list(self.lineage())[-1].base


def scan_dockerfile(path, context=None):
    path = Path(path)
    instructions = parse(path.read_text(encoding="utf-8-sig", errors="replace"))
    context = Path(context) if context else path.parent

    hits, seen = [], set()
    for hit in check_instructions(instructions, context, path):
        key = (hit.rule.id, hit.line, hit.detail)
        if key not in seen:
            seen.add(key)
            hits.append(hit)
    ignores = {ins.line: ins.ignore for ins in instructions if ins.ignore}
    return hits, ignores


def parse(text):
    lines = text.splitlines()
    escape = "\\"
    for raw in lines:
        match = DIRECTIVE.match(raw.strip())
        if not match:
            break
        if match.group(1).lower() == "escape":
            escape = match.group(2)

    instructions, pending_ignore = [], set()
    i = 0
    while i < len(lines):
        number, line = i + 1, lines[i].strip()
        i += 1
        if not line:
            continue
        if line.startswith("#"):
            match = IGNORE.match(line)
            if match:
                pending_ignore |= {r.strip() for r in match.group(1).split(",") if r.strip()}
            continue

        parts = []
        while line.endswith(escape):
            parts.append(line[:-1].strip())
            line = ""
            while i < len(lines):
                candidate = lines[i].strip()
                i += 1
                if candidate and not candidate.startswith("#"):
                    line = candidate
                    break
        parts.append(line)

        pieces = " ".join(p for p in parts if p).split(None, 1)
        keyword = pieces[0].upper()
        value = pieces[1].strip() if len(pieces) > 1 else ""
        instruction = Instruction(number, keyword, value, ignore=pending_ignore)
        pending_ignore = set()

        if keyword in ("RUN", "COPY", "ADD"):
            for dash, _, delimiter in HEREDOC.findall(value):
                body = []
                while i < len(lines):
                    raw = lines[i]
                    i += 1
                    if (raw.lstrip("\t") if dash else raw).strip() == delimiter:
                        break
                    body.append(raw)
                instruction.heredocs.append("\n".join(body))
        instructions.append(instruction)
    return instructions


def check_instructions(instructions, context=None, dockerfile=None):
    stages, aliases, build_args = [], {}, []

    for ins in instructions:
        stage = stages[-1] if stages else None
        keyword = ins.keyword

        if keyword == "FROM":
            stage = _stage(ins, aliases)
            stages.append(stage)
            if stage.alias:
                aliases[stage.alias.lower()] = stage
            if stage.parent is None and _pullable(stage.base) and unpinned(stage.base):
                yield R.LATEST_TAG.hit(f"FROM {stage.base} is not pinned to a version", line=ins.line)
        elif keyword == "USER" and stage:
            words = _words(ins.value)
            stage.user, stage.user_line = (words[0] if words else ""), ins.line
        elif keyword == "HEALTHCHECK" and stage:
            stage.healthcheck, stage.healthcheck_line = not ins.value.upper().startswith("NONE"), ins.line
        elif keyword == "ENV":
            yield from _env(ins)
        elif keyword == "ARG":
            for name, value in _pairs(ins.value):
                reason = check_variable(name, value)
                if reason:
                    yield R.SECRET_IN_DOCKERFILE.hit(f"ARG {name} default {reason}", line=ins.line)
                elif secret_name(name):
                    build_args.append((stage, name, ins.line))
        elif keyword == "RUN":
            yield from _run(ins)
        elif keyword in ("ADD", "COPY"):
            yield from _copy(ins, context, dockerfile)
        elif keyword == "EXPOSE":
            if any(p.split("/")[0] == "22" for p in ins.value.split()):
                yield R.SSH_PORT.hit("EXPOSE 22 (SSH)", line=ins.line)

        if keyword not in ("ENV", "ARG"):
            for label in find_tokens(ins.text):
                yield R.SECRET_IN_DOCKERFILE.hit(f"{keyword} contains {label}", line=ins.line)

    if not stages:
        return
    final = stages[-1]
    lineage = list(final.lineage())

    for stage, name, line in build_args:
        if any(stage is s for s in lineage):
            yield R.SECRET_BUILD_ARG.hit(f"ARG {name} looks like a secret and build args are kept in the image history", line=line)

    user, line = next(((s.user, s.user_line) for s in lineage if s.user is not None), (None, None))
    if user is None:
        if not any(word in final.origin().lower() for word in NON_ROOT_BASES):
            yield R.ROOT_USER.hit("No USER in the final stage, so the image runs as root", line=final.line)
    elif is_root(user):
        yield R.ROOT_USER.hit(f"Final stage runs as USER {user}", line=line)

    healthcheck, line = next(((s.healthcheck, s.healthcheck_line) for s in lineage if s.healthcheck is not None), (None, None))
    if healthcheck is None:
        yield R.NO_HEALTHCHECK.hit("No HEALTHCHECK in the final stage", line=final.line)
    elif not healthcheck:
        yield R.NO_HEALTHCHECK.hit("HEALTHCHECK NONE turns off the base image's healthcheck", line=line)


def _stage(ins, aliases):
    _, words = _split_flags(_words(ins.value))
    base = words[0] if words else ""
    alias = words[2] if len(words) >= 3 and words[1].lower() == "as" else ""
    return Stage(base, alias, ins.line, parent=aliases.get(base.lower()))


def _pullable(base):
    return bool(base) and base.lower() != "scratch" and "$" not in base


def _env(ins):
    for name, value in _pairs(ins.value):
        problem = insecure_setting(name, value)
        if problem:
            yield R.INSECURE_ENV.hit(f"ENV {name}: {problem}", line=ins.line)
            continue
        reason = check_variable(name, value)
        if reason:
            yield R.SECRET_IN_DOCKERFILE.hit(f"ENV {name} {reason}", line=ins.line)


def _run(ins):
    text = _command(ins)
    if any(pattern.search(text) for pattern in PIPE_TO_SHELL):
        yield R.PIPE_TO_SHELL.hit("Downloads a script and pipes it straight into an interpreter", line=ins.line)
    for label, pattern in INSECURE_FLAGS:
        if pattern.search(text):
            yield R.INSECURE_DOWNLOAD.hit(f"Uses {label}", line=ins.line)
    if CHMOD.search(text):
        yield R.WORLD_WRITABLE.hit("chmod makes files writable by everyone", line=ins.line)
    if SUDO.search(text):
        yield R.SUDO.hit(line=ins.line)


def _copy(ins, context, dockerfile):
    flags, words = _split_flags(_words(ins.value))
    if ins.heredocs or len(words) < 2:
        return
    sources = words[:-1]

    if ins.keyword == "ADD":
        remote = [s for s in sources if s.startswith(REMOTE)]
        if remote and "checksum" not in flags:
            yield R.REMOTE_ADD.hit(f"ADD {URL_CREDENTIALS.sub('://***@', remote[0])} has no --checksum", line=ins.line)
        if not remote and not any(s.lower().endswith(ARCHIVES) or s.startswith("git@") for s in sources):
            yield R.ADD_LOCAL.hit(line=ins.line)

    whole_context = any(s in (".", "./", "*", "./*") for s in sources)
    if context is not None and whole_context and "from" not in flags and not _has_dockerignore(context, dockerfile):
        detail = f"{ins.keyword} {' '.join(sources)} copies the whole build context and there is no .dockerignore"
        yield R.COPY_CONTEXT.hit(detail, line=ins.line)


def _has_dockerignore(context, dockerfile):
    candidates = [Path(context) / ".dockerignore"]
    if dockerfile:
        dockerfile = Path(dockerfile)
        candidates.append(dockerfile.with_name(dockerfile.name + ".dockerignore"))
    return any(p.is_file() for p in candidates)


def _command(ins):
    if ins.value.startswith("["):
        try:
            return " ".join(str(part) for part in json.loads(ins.value))
        except (ValueError, TypeError):
            pass
    return ins.text


def _words(value):
    if value.startswith("["):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(p) for p in parsed]
        except ValueError:
            pass
    try:
        return shlex.split(value)
    except ValueError:
        return value.split()


def _split_flags(words):
    flags = {}
    while words and words[0].startswith("--"):
        name, _, value = words.pop(0)[2:].partition("=")
        flags[name.lower()] = value
    return flags, words


def _pairs(value):
    words = _words(value)
    if not words:
        return []
    if "=" not in words[0]:
        return [(words[0], " ".join(words[1:]) or None)]
    return [tuple(w.split("=", 1)) if "=" in w else (w, None) for w in words]
