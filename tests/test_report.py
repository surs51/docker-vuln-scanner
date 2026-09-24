import json

from dvscan import rules as R
from dvscan.findings import Report, Severity, Target
from dvscan.output import render_json, render_sarif, render_text


def sample(mode="full"):
    report = Report(mode)
    report.add(Target("host", "Docker 27.3.1")).hits = [R.USERNS_REMAP.hit(), R.RUNC_CVE.hit("runc 1.1.11 is affected")]

    web = report.add(Target("container", "web", ref="abc123", image="nginx:1.27", ignore={"exposed-port"}))
    web.hits = [R.ROOT_USER.hit(), R.EXPOSED_PORT.hit("8080/tcp published"), R.NO_CPU_LIMIT.hit()]

    dockerfile = report.add(Target("dockerfile", "Dockerfile", file="Dockerfile", line_ignores={4: {"sudo"}}))
    dockerfile.hits = [R.SUDO.hit(line=4), R.PIPE_TO_SHELL.hit(line=7)]

    report.add(Target("image", "nginx:1.27", quiet=True)).hits = [R.STALE_IMAGE.hit()]
    return report


def filtered(*args, mode="full"):
    report = sample(mode)
    report.apply_filters(*args)
    return report


def test_mode_levels_and_ignores():
    report = filtered()
    assert [[h.rule.id for h in t.hits] for t in report.targets] == [
        ["runc-cve"], ["root-user", "no-cpu-limit"], ["pipe-to-shell"],
    ]
    assert report.ignored == 2


def test_min_severity_and_ignore_list():
    report = filtered({"runc-cve"}, Severity.HIGH, mode="paranoid")
    assert [(t.name, [h.rule.id for h in t.hits]) for t in report.targets] == [
        ("Docker 27.3.1", []), ("web", ["root-user"]), ("Dockerfile", ["pipe-to-shell"]),
    ]
    assert report.worst() == Severity.HIGH


def test_json():
    data = json.loads(render_json(filtered()))
    assert data["summary"] == {"critical": 1, "high": 2, "medium": 0, "low": 1, "total": 4, "ignored": 2}
    web = data["targets"][1]
    assert web["id"] == "abc123" and web["findings"][0]["rule"] == "root-user"


def test_sarif():
    run = json.loads(render_sarif(filtered()))["runs"][0]
    rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert all(rules[r["ruleIndex"]] == r["ruleId"] for r in run["results"])

    pipe = next(r for r in run["results"] if r["ruleId"] == "pipe-to-shell")
    location = pipe["locations"][0]["physicalLocation"]
    assert location["region"]["startLine"] == 7 and location["artifactLocation"]["uri"] == "Dockerfile"

    runc = next(r for r in run["results"] if r["ruleId"] == "runc-cve")
    assert runc["level"] == "error" and "logicalLocations" in runc["locations"][0]


def test_text():
    text = render_text(filtered())
    assert "[!] container web (abc123, nginx:1.27)" in text
    assert "line 7: " in text
    assert text.endswith("Summary: 3 targets, 4 findings: 1 critical, 2 high, 1 low (2 ignored)")
    assert "\033[" not in text


def test_text_mentions_the_severity_floor_for_clean_targets():
    text = render_text(filtered(set(), Severity.CRITICAL))
    assert "[+] container web (abc123, nginx:1.27) - nothing at critical or above" in text
