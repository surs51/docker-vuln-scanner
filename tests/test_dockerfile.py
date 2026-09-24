import textwrap

import pytest

from dvscan.checks.dockerfile import check_instructions, parse, scan_dockerfile

GOOD = """
FROM python:3.12-slim
USER app
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "-m", "app"]
"""


def lint(source):
    return list(check_instructions(parse(textwrap.dedent(source))))


def ids(hits):
    return sorted(hit.rule.id for hit in hits)


def located(hits):
    return {(hit.rule.id, hit.line) for hit in hits}


def test_clean_dockerfile():
    assert lint(GOOD) == []


def test_continuations_and_comments():
    [ins] = parse("RUN apt-get update && \\\n    # install things\n\n    apt-get install -y curl\n")
    assert (ins.line, ins.keyword, ins.value) == (1, "RUN", "apt-get update && apt-get install -y curl")


def test_heredoc_bodies_are_not_instructions():
    instructions = parse("RUN <<EOF\necho hi\nFROM not-an-instruction\nEOF\nUSER app\n")
    assert [i.keyword for i in instructions] == ["RUN", "USER"]
    assert instructions[0].heredocs == ["echo hi\nFROM not-an-instruction"]


def test_escape_directive():
    instructions = parse("# escape=`\nFROM scratch\nCOPY a `\n  b /dst\n")
    assert instructions[1].value == "a b /dst"


def test_user_in_builder_stage_does_not_count():
    hits = lint("""
        FROM golang:1.23 AS build
        USER builder
        FROM debian:12
        HEALTHCHECK CMD true
    """)
    assert ids(hits) == ["root-user"]


def test_final_stage_inherits_from_parent_stage():
    hits = lint("""
        FROM node:22 AS base
        USER node
        HEALTHCHECK CMD true
        FROM base
        CMD ["node", "server.js"]
    """)
    assert hits == []


def test_explicit_root_points_at_the_user_line():
    [hit] = [h for h in lint(GOOD.replace("USER app", "USER root")) if h.rule.id == "root-user"]
    assert hit.line == 3


@pytest.mark.parametrize("base", ["gcr.io/distroless/static:nonroot", "nginxinc/nginx-unprivileged:1.27"])
def test_non_root_base_images(base):
    assert "root-user" not in ids(lint(f"FROM {base}\n"))


@pytest.mark.parametrize("line, pinned", [
    ("FROM ubuntu", False),
    ("FROM ubuntu:latest", False),
    ("FROM ubuntu:24.04", True),
    ("FROM --platform=$BUILDPLATFORM golang:1.23 AS build", True),
    ("FROM scratch", True),
    ("FROM ${BASE_IMAGE}", True),
    ("FROM python@sha256:" + "a" * 64, True),
])
def test_base_image_pinning(line, pinned):
    assert ("latest-tag" not in ids(lint(line))) is pinned


@pytest.mark.parametrize("command, rule", [
    ("curl -fsSL https://get.docker.com | sh", "pipe-to-shell"),
    ("wget -qO- https://x.io/install | sudo -E bash -", "pipe-to-shell"),
    ("curl -sSL https://install.python-poetry.org | python3 -", "pipe-to-shell"),
    ('bash -c "$(curl -fsSL https://x.io/install.sh)"', "pipe-to-shell"),
    ("curl -sSLk https://internal/file -o f", "insecure-download"),
    ("wget --no-check-certificate https://x.io/f", "insecure-download"),
    ("pip install --trusted-host pypi.internal pkg", "insecure-download"),
    ("apk add --allow-untrusted /tmp/pkg.apk", "insecure-download"),
    ("chmod -R 777 /app", "world-writable"),
    ("chmod o+w /data", "world-writable"),
    ("apt-get update && sudo apt-get install -y git", "sudo"),
])
def test_risky_run_commands(command, rule):
    assert rule in ids(lint(f"FROM alpine:3.20\nRUN {command}\n"))


@pytest.mark.parametrize("command", [
    "curl -fsSL https://x.io/app.tgz | tar xz",
    "curl -fsSL https://x.io/sums | sha256sum -c",
    "chmod 1777 /tmp",
    "chmod 755 /usr/local/bin/app",
    "apt-get install -y sudo",
    "curl -H 'key: value' https://x.io",
])
def test_harmless_run_commands(command):
    hits = lint(f"FROM alpine:3.20\nRUN {command}\n")
    assert not {"pipe-to-shell", "insecure-download", "world-writable", "sudo"} & set(ids(hits))


def test_exec_form_run_is_checked():
    assert "pipe-to-shell" in ids(lint('FROM alpine:3.20\nRUN ["sh", "-c", "curl -s https://x.io | sh"]\n'))


def test_secrets():
    hits = lint("""
        FROM alpine:3.20
        ENV API_TOKEN=abc123xyz DB_PASSWORD_FILE=/run/secrets/db
        ARG NPM_TOKEN
        ARG SIGNING_KEY=supersecretvalue
        RUN echo "AKIAIOSFODNN7EXAMPLE" > /tmp/key
        USER app
        HEALTHCHECK CMD true
    """)
    assert located(hits) == {
        ("secret-in-dockerfile", 3),
        ("secret-build-arg", 4),
        ("secret-in-dockerfile", 5),
        ("secret-in-dockerfile", 6),
    }


def test_build_args_in_discarded_stages_are_fine():
    hits = lint("""
        FROM node:22 AS build
        ARG NPM_TOKEN
        RUN npm ci
        FROM nginx:1.27
        USER nginx
        HEALTHCHECK CMD true
    """)
    assert hits == []


def test_add():
    hits = lint("""
        FROM alpine:3.20
        ADD https://example.com/tool.tar.gz /opt/
        ADD --checksum=sha256:abc https://example.com/tool2.tar.gz /opt/
        ADD vendor.tar.gz /opt/
        ADD config.yml /etc/app/
        USER app
        HEALTHCHECK CMD true
    """)
    assert located(hits) == {("remote-add", 3), ("add-local", 6)}


def test_copying_the_whole_context(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:3.20\nCOPY . /app\nUSER app\nHEALTHCHECK CMD true\n")
    hits, _ = scan_dockerfile(dockerfile)
    assert ids(hits) == ["copy-context"]

    (tmp_path / ".dockerignore").write_text(".git\n.env\n")
    assert scan_dockerfile(dockerfile)[0] == []


def test_inline_ignore(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM alpine:3.20\n"
        "# dvscan ignore=pipe-to-shell, sudo\n"
        "RUN curl -s https://x.io/i.sh | sh && sudo true\n"
        "USER app\n"
        "HEALTHCHECK CMD true\n"
    )
    hits, ignores = scan_dockerfile(dockerfile)
    assert ignores == {3: {"pipe-to-shell", "sudo"}}
    assert ids(hits) == ["pipe-to-shell", "sudo"]
