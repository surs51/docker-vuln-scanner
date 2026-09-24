import json
import subprocess

import pytest

from dvscan import cve

OPENSSL = {
    "VulnerabilityID": "CVE-2024-0001",
    "PkgName": "openssl",
    "InstalledVersion": "3.0.2",
    "FixedVersion": "3.0.13",
    "Severity": "CRITICAL",
}
TRIVY = {"Results": [{"Vulnerabilities": [OPENSSL, dict(OPENSSL)]}, {"Vulnerabilities": None}]}
GRYPE = {
    "matches": [{
        "vulnerability": {"id": "GHSA-35jh-r3h4-6jhm", "severity": "Negligible", "fix": {"versions": []}},
        "artifact": {"name": "lodash", "version": "4.17.20"},
    }]
}


def replies(stdout, code=0, stderr=""):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, code, stdout=stdout, stderr=stderr)
    return run


def test_trivy(monkeypatch):
    monkeypatch.setattr(cve.subprocess, "run", replies(json.dumps(TRIVY)))
    [hit] = cve.scan_image("app:1", "trivy", "trivy")
    assert hit.vuln_id == "CVE-2024-0001" and str(hit.severity) == "critical"
    assert hit.detail == "CVE-2024-0001 in openssl 3.0.2 (fixed in 3.0.13)"


def test_grype(monkeypatch):
    monkeypatch.setattr(cve.subprocess, "run", replies(json.dumps(GRYPE)))
    [hit] = cve.scan_image("app:1", "grype", "grype")
    assert str(hit.severity) == "low" and hit.detail.endswith("(no fix yet)")


def test_scanner_failure(monkeypatch):
    monkeypatch.setattr(cve.subprocess, "run", replies("", code=1, stderr="FATAL image not found\n"))
    with pytest.raises(cve.CveError, match="image not found"):
        cve.scan_image("app:1", "trivy", "trivy")


def test_missing_scanner(monkeypatch):
    monkeypatch.setattr(cve.shutil, "which", lambda name: None)
    with pytest.raises(cve.CveError, match="trivy or grype"):
        cve.find_scanner()
