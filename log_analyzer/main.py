# CLI entry point: wires parser -> detectors -> reporter pipeline

import argparse
import sys
from pathlib import Path

# Ensure sibling modules (parsers, detectors, reporters, models, config)
# are importable regardless of the working directory the script is invoked from.
sys.path.insert(0, str(Path(__file__).parent))

import config
from detectors import brute_force, failed_login
from parsers import auth_parser, web_parser
from reporters import console_reporter, json_reporter

_PARSERS = {
    "auth": auth_parser.parse,
    "web":  web_parser.parse,
}

_REPORTERS = {
    "console": console_reporter.report,
    "json":    json_reporter.report,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Parse auth or web logs and detect suspicious activity.",
    )
    p.add_argument(
        "--file",
        required=True,
        metavar="PATH",
        help="Path to the log file to analyze.",
    )
    p.add_argument(
        "--type",
        required=True,
        choices=config.SUPPORTED_LOG_TYPES,
        dest="log_type",
        help="Log format to parse: 'auth' (/var/log/auth.log) or 'web' (Apache/Nginx).",
    )
    p.add_argument(
        "--reporter",
        default="console",
        choices=list(_REPORTERS.keys()),
        help="Output format: 'console' (default) or 'json'.",
    )
    p.add_argument(
        "--threshold",
        type=int,
        default=None,
        metavar="N",
        help=(
            f"Override MAX_FAILED_LOGINS (default: {config.MAX_FAILED_LOGINS}). "
            "Sets the per-IP failed-login count before an alert is raised."
        ),
    )
    return p


def main() -> None:
    args = build_parser().parse_args()

    # Apply optional threshold override before detectors read config
    if args.threshold is not None:
        config.MAX_FAILED_LOGINS = args.threshold

    # Resolve and validate the log file path
    log_path = Path(args.file)
    if not log_path.is_file():
        print(f"error: file not found: {log_path}", file=sys.stderr)
        sys.exit(2)

    # Parse
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    parse = _PARSERS[args.log_type]
    entries = parse(lines)

    # Detect — run both detectors and merge results
    alerts = failed_login.detect(entries) + brute_force.detect(entries)
    alerts.sort(key=lambda a: a.timestamp)

    # Report
    report = _REPORTERS[args.reporter]
    report(alerts)

    # Summary (always to stderr so it doesn't corrupt JSON output)
    high_count = sum(1 for a in alerts if a.severity == "high")
    print(
        f"\n--- {len(alerts)} alert(s) total | {high_count} high-severity ---",
        file=sys.stderr,
    )

    # Exit 1 if any high-severity alerts found (useful in CI / shell pipelines)
    sys.exit(1 if high_count > 0 else 0)


if __name__ == "__main__":
    main()
