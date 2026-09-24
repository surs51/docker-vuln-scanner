import json
import shutil
import subprocess

from dvscan import rules as R
from dvscan.findings import Severity

SCANNERS = ("trivy", "grype")


class CveError(Exception):
    pass


def find_scanner(preferred=None):
    for name in [preferred] if preferred else SCANNERS:
        path = shutil.which(name)
        if path:
            return name, path
    if preferred:
        raise CveError(f"{preferred} was not found on PATH")
    raise CveError("--cve needs trivy or grype installed and on PATH")


def scan_image(ref, scanner, path, ignore_unfixed=False, timeout=900):
    if scanner == "trivy":
        command = [path, "image", "--quiet", "--format", "json", "--scanners", "vuln", ref]
        if ignore_unfixed:
            command.insert(2, "--ignore-unfixed")
    else:
        command = [path, ref, "-o", "json", "-q"]
        if ignore_unfixed:
            command.append("--only-fixed")

    try:
        proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CveError(f"{scanner} timed out on {ref}") from None
    if proc.returncode != 0:
        message = next((line for line in proc.stderr.splitlines() if line.strip()), "unknown error")
        raise CveError(f"{scanner} failed on {ref}: {message.strip()}")

    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        raise CveError(f"couldn't parse {scanner} output for {ref}") from None

    vulns = parse_trivy(data) if scanner == "trivy" else parse_grype(data)
    return [_hit(v) for v in vulns]


def parse_trivy(data):
    seen, vulns = set(), []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
            if key in seen:
                continue
            seen.add(key)
            vulns.append({
                "id": v.get("VulnerabilityID") or "",
                "package": v.get("PkgName") or "",
                "installed": v.get("InstalledVersion") or "",
                "fixed": v.get("FixedVersion") or "",
                "severity": v.get("Severity") or "unknown",
            })
    return vulns


def parse_grype(data):
    seen, vulns = set(), []
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        key = (vuln.get("id"), artifact.get("name"), artifact.get("version"))
        if key in seen:
            continue
        seen.add(key)
        vulns.append({
            "id": vuln.get("id") or "",
            "package": artifact.get("name") or "",
            "installed": artifact.get("version") or "",
            "fixed": ", ".join((vuln.get("fix") or {}).get("versions") or []),
            "severity": vuln.get("severity") or "unknown",
        })
    return vulns


def _hit(vuln):
    try:
        severity = Severity.parse(vuln["severity"])
    except ValueError:
        severity = Severity.LOW
    detail = f"{vuln['id']} in {vuln['package']} {vuln['installed']}".strip()
    detail += f" (fixed in {vuln['fixed']})" if vuln["fixed"] else " (no fix yet)"
    return R.VULNERABLE_PACKAGE.hit(detail, severity, vuln_id=vuln["id"])
