import argparse
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from dvscan import __version__, scan
from dvscan.docker import Docker, DockerError
from dvscan.findings import MODES, Report, Severity
from dvscan.output import render, supports_color
from dvscan.rules import RULES

COMMANDS = {
    "host": scan.scan_host,
    "image": scan.scan_images,
    "dockerfile": scan.scan_dockerfiles,
    "compose": scan.scan_compose,
}


def severity(value):
    try:
        return Severity.parse(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-m", "--mode", choices=MODES, default="full",
                        help="how thorough to be (default: full)")
    common.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text",
                        help="report format (default: text)")
    common.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    common.add_argument("--min-severity", type=severity, default=Severity.LOW, metavar="LEVEL",
                        help="hide findings below LEVEL")
    common.add_argument("--fail-on", type=severity, metavar="LEVEL",
                        help="exit with status 1 if anything at LEVEL or above is found")
    common.add_argument("--ignore", action="append", default=[], metavar="IDS",
                        help="comma-separated rule or CVE IDs to skip, can be repeated")
    common.add_argument("--no-color", action="store_true", help="disable colored output")
    common.add_argument("--docker", default=os.environ.get("DVSCAN_DOCKER", "docker"), metavar="BIN",
                        help="docker binary to call (default: docker)")
    common.add_argument("--debug", action="store_true", help="print a traceback when something goes wrong")

    cves = argparse.ArgumentParser(add_help=False)
    cves.add_argument("--cve", action="store_true", help="also look for known CVEs with trivy or grype")
    cves.add_argument("--scanner", choices=("trivy", "grype"), help="which CVE scanner to use")
    cves.add_argument("--ignore-unfixed", action="store_true", help="skip CVEs that have no fix yet")

    parser = argparse.ArgumentParser(
        prog="dvscan",
        description="Security scanner for Docker hosts, containers, images, Dockerfiles and Compose files.",
        epilog="Running dvscan with no command is the same as 'dvscan host'.",
    )
    parser.add_argument("--version", action="version", version=f"dvscan {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.required = True

    host = commands.add_parser("host", parents=[common, cves],
                               help="scan the Docker daemon, running containers and their images")
    host.add_argument("containers", nargs="*", metavar="CONTAINER", help="only scan these containers")
    host.add_argument("-a", "--all", action="store_true", help="include stopped containers")

    image = commands.add_parser("image", parents=[common, cves], help="scan local images")
    image.add_argument("images", nargs="+", metavar="IMAGE")

    dockerfile = commands.add_parser("dockerfile", parents=[common], help="lint Dockerfiles")
    dockerfile.add_argument("paths", nargs="*", metavar="PATH", help="Dockerfiles or directories (default: ./Dockerfile)")

    compose = commands.add_parser("compose", parents=[common], help="check a Compose project before deploying it")
    compose.add_argument("files", nargs="*", metavar="FILE", help="compose files, merged in order (default: ./compose.yaml)")

    commands.add_parser("rules", help="list every check dvscan runs")
    return parser


def normalize(argv):
    if not argv:
        return ["host"]
    if argv[0] in MODES:
        return ["host", "--mode", argv[0], *argv[1:]]
    if argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        return ["host", *argv]
    return argv


def list_rules():
    width = max(len(rule_id) for rule_id in RULES)
    lines = [f"{'RULE':<{width}}  SEVERITY  MODE      TITLE"]
    for rule in RULES.values():
        lines.append(f"{rule.id:<{width}}  {str(rule.severity):<8}  {rule.level:<8}  {rule.title}")
    return "\n".join(lines)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    args = build_parser().parse_args(normalize(sys.argv[1:] if argv is None else list(argv)))

    if args.command == "rules":
        print(list_rules())
        return 0

    report = Report(args.mode)
    report.meta["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        COMMANDS[args.command](Docker(args.docker), args, report)
    except (DockerError, scan.ScanError, OSError) as e:
        print(f"dvscan: {e}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return 2
    except KeyboardInterrupt:
        print("dvscan: interrupted", file=sys.stderr)
        return 130
    except Exception as e:
        if args.debug:
            raise
        print(f"dvscan: unexpected error: {e} (run with --debug for the traceback)", file=sys.stderr)
        return 2

    ignore = {part.strip() for chunk in args.ignore for part in chunk.split(",") if part.strip()}
    report.apply_filters(ignore, args.min_severity)

    color = not args.output and not args.no_color and args.format == "text" and supports_color(sys.stdout)
    output = render(report, args.format, color)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    if args.format != "text" or args.output:
        for error in report.errors:
            print(f"warning: {error}", file=sys.stderr)

    worst = report.worst()
    if args.fail_on is not None and worst is not None and worst >= args.fail_on:
        return 1
    return 0
