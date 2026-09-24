import json
import os
import shutil
import textwrap
from pathlib import Path

from dvscan import __version__
from dvscan import rules as R
from dvscan.findings import Severity

HOMEPAGE = "https://github.com/surs51/docker-vuln-scanner"
COLORS = {Severity.CRITICAL: "1;31", Severity.HIGH: "31", Severity.MEDIUM: "33", Severity.LOW: "36"}
SARIF_LEVELS = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
SARIF_SCORES = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}
MAX_VULNS_SHOWN = 15


def render(report, fmt, color=False):
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    return render_text(report, color)


def supports_color(stream):
    if os.environ.get("NO_COLOR") or not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_ansi()
    return os.environ.get("TERM") != "dumb"


class Paint:
    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, code):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


def render_text(report, color=False):
    paint = Paint(color)
    width = max(70, min(shutil.get_terminal_size((100, 20)).columns, 120))
    lines = [paint(f"dvscan {__version__}", "1") + f" - mode: {report.mode}", ""]
    clean = " - no issues" if report.min_severity == Severity.LOW else f" - nothing at {report.min_severity} or above"

    for target in report.targets:
        if not target.hits:
            lines.append(paint("[+] ", "32") + _label(target) + paint(clean, "2"))
            continue

        lines.append(paint("[!] ", "31") + paint(_label(target), "1"))
        hits, vulns = [], 0
        for hit in sorted(target.hits, key=lambda h: (-h.severity, h.rule.id, h.line or 0)):
            if hit.rule is R.VULNERABLE_PACKAGE:
                vulns += 1
                if vulns > MAX_VULNS_SHOWN:
                    continue
            hits.append(hit)
        hidden = max(0, vulns - MAX_VULNS_SHOWN)

        for index, hit in enumerate(hits):
            where = f"line {hit.line}: " if hit.line else ""
            severity = f"{str(hit.severity).upper():<10}"
            lines.append(f"    {paint(severity, COLORS[hit.severity])}{where}{hit.detail} {paint('[' + hit.rule.id + ']', '2')}")
            following = hits[index + 1] if index + 1 < len(hits) else None
            if following is None or following.rule is not hit.rule or following.fix != hit.fix:
                wrapped = textwrap.wrap(hit.fix, width - 17) or [""]
                lines.append(" " * 14 + paint("-> ", "2") + wrapped[0])
                lines.extend(" " * 17 + part for part in wrapped[1:])
        if hidden:
            lines.append(f"    ... and {hidden} more vulnerabilities (use --format json to see them all)")
        lines.append("")

    counts = report.counts()
    total = sum(counts.values())
    scanned = f"{len(report.targets)} target{'s' if len(report.targets) != 1 else ''}"
    if total:
        parts = [paint(f"{n} {name}", COLORS[Severity.parse(name)]) for name, n in counts.items() if n]
        summary = f"{scanned}, {total} finding{'s' if total != 1 else ''}: " + ", ".join(parts)
    else:
        summary = f"{scanned}, no findings"
    if report.ignored:
        summary += paint(f" ({report.ignored} ignored)", "2")
    for note in report.notes:
        lines.append(paint("[i] ", "36") + note)
    if lines[-1]:
        lines.append("")
    lines.append(paint("Summary: ", "1") + summary)

    for error in report.errors:
        lines.append(paint(f"warning: {error}", "33"))
    return "\n".join(lines)


def render_json(report):
    counts = report.counts()
    document = {
        "tool": {"name": "dvscan", "version": __version__},
        "mode": report.mode,
        "scanned_at": report.meta.get("scanned_at"),
        "environment": {k: report.meta[k] for k in ("docker", "os", "runc") if report.meta.get(k)},
        "summary": {**counts, "total": sum(counts.values()), "ignored": report.ignored},
        "targets": [_target_json(t) for t in report.targets],
        "notes": report.notes,
        "errors": report.errors,
    }
    return json.dumps(document, indent=2)


def _target_json(target):
    data = {"kind": target.kind, "name": target.name}
    for key in ("ref", "image", "file", "line", "status"):
        value = getattr(target, key)
        if value:
            data["id" if key == "ref" else key] = value
    if target.used_by:
        data["used_by"] = target.used_by
    data["findings"] = [_hit_json(h) for h in sorted(target.hits, key=lambda h: -h.severity)]
    return data


def _hit_json(hit):
    data = {
        "rule": hit.rule.id,
        "severity": str(hit.severity),
        "title": hit.rule.title,
        "message": hit.detail,
        "fix": hit.fix,
    }
    if hit.line:
        data["line"] = hit.line
    if hit.vuln_id:
        data["vulnerability"] = hit.vuln_id
    return data


def render_sarif(report):
    rules, results = {}, []
    for target, hit in report.findings():
        worst = rules.get(hit.rule.id, (hit.rule, hit.severity))[1]
        rules[hit.rule.id] = (hit.rule, max(worst, hit.severity))

        subject = "" if target.file else f"{target.kind} {target.name}: "
        result = {
            "ruleId": hit.rule.id,
            "level": SARIF_LEVELS[hit.severity],
            "message": {"text": f"{subject}{hit.detail}. {hit.fix}"},
        }
        if target.file:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(target.file)},
                    "region": {"startLine": hit.line or target.line or 1},
                }
            }]
        else:
            result["locations"] = [{
                "logicalLocations": [{
                    "name": target.name,
                    "fullyQualifiedName": f"{target.kind}/{target.name}",
                    "kind": "resource",
                }]
            }]
        results.append(result)

    ordered = list(rules)
    for result in results:
        result["ruleIndex"] = ordered.index(result["ruleId"])

    driver_rules = []
    for rule, severity in rules.values():
        driver_rules.append({
            "id": rule.id,
            "name": "".join(part.capitalize() for part in rule.id.split("-")),
            "shortDescription": {"text": rule.title},
            "help": {"text": rule.fix},
            "defaultConfiguration": {"level": SARIF_LEVELS[severity]},
            "properties": {"security-severity": SARIF_SCORES[severity], "tags": ["security", "docker"]},
        })

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dvscan",
                "version": __version__,
                "informationUri": HOMEPAGE,
                "rules": driver_rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(document, indent=2)


def _label(target):
    if target.kind == "host":
        return f"host {target.name}"
    if target.kind == "container":
        details = ", ".join(part for part in (target.ref, target.image) if part)
        status = f" [{target.status}]" if target.status else ""
        return f"container {target.name} ({details}){status}"
    if target.kind == "image":
        used = f" (used by {', '.join(target.used_by)})" if target.used_by else ""
        return f"image {target.name}{used}"
    if target.kind == "service":
        where = f"{target.file}:{target.line}" if target.line else target.file
        return f"service {target.name} ({where})"
    return f"{target.kind} {target.name}"


def _uri(path):
    try:
        relative = os.path.relpath(path)
    except ValueError:
        return Path(path).resolve().as_uri()
    if relative.startswith(".."):
        return Path(path).resolve().as_uri()
    return relative.replace(os.sep, "/")


def _enable_windows_ansi():
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False
