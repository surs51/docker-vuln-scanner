import json

import pytest

from dvscan import cli


@pytest.mark.parametrize("argv, expected", [
    ([], ["host"]),
    (["paranoid"], ["host", "--mode", "paranoid"]),
    (["basic", "--format", "json"], ["host", "--mode", "basic", "--format", "json"]),
    (["--format", "json"], ["host", "--format", "json"]),
    (["--version"], ["--version"]),
    (["dockerfile", "Dockerfile"], ["dockerfile", "Dockerfile"]),
])
def test_default_and_legacy_arguments(argv, expected):
    assert cli.normalize(argv) == expected


@pytest.fixture
def dockerfile(tmp_path):
    path = tmp_path / "Dockerfile"
    path.write_text("FROM alpine:3.20\nRUN curl -fsSL https://x.io/i.sh | sh\nUSER app\nHEALTHCHECK CMD true\n")
    return str(path)


def test_exit_codes(dockerfile, capsys):
    assert cli.main(["dockerfile", dockerfile, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["high"] == 1
    assert cli.main(["dockerfile", dockerfile, "--fail-on", "high"]) == 1
    assert cli.main(["dockerfile", dockerfile, "--fail-on", "critical"]) == 0
    assert cli.main(["dockerfile", dockerfile, "--fail-on", "low", "--ignore", "pipe-to-shell"]) == 0


def test_report_file(dockerfile, tmp_path):
    out = tmp_path / "report.sarif"
    assert cli.main(["dockerfile", dockerfile, "-f", "sarif", "-o", str(out)]) == 0
    assert [r["ruleId"] for r in json.loads(out.read_text())["runs"][0]["results"]] == ["pipe-to-shell"]


def test_missing_docker_binary(capsys):
    assert cli.main(["host", "--docker", "no-such-docker-binary"]) == 2
    assert "was not found" in capsys.readouterr().err


def test_rules_listing(capsys):
    assert cli.main(["rules"]) == 0
    assert "docker-socket" in capsys.readouterr().out
