# CLI entry point: wires parser -> detectors -> reporter pipeline

import argparse
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

# Ensure sibling modules (parsers, detectors, reporters, models, config)
# are importable regardless of the working directory the script is invoked from.
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

# Project root (one level above log_analyzer/)
_ROOT = _HERE.parent


def _load_module_from_path(name: str, path: Path) -> ModuleType:
    """Load a Python module directly from an absolute file path.

    Used for root-level workspace modules (auth/, parsers/, detectors/) that live
    outside log_analyzer/ and share directory names with packages that already
    exist inside log_analyzer/ — making normal package imports ambiguous.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # register so transitive imports resolve correctly
    spec.loader.exec_module(mod)
    return mod

import config
from detectors import brute_force, failed_login
from parsers import auth_parser, web_parser
from reporters import console_reporter, json_reporter

_REPORTERS = {
    "console": console_reporter.report,
    "json":    json_reporter.report,
}

# All valid log types: file-based ones handled by _FILE_PARSERS,
# workspace handled separately via the Admin SDK.
_FILE_LOG_TYPES = ["auth", "web"]
_ALL_LOG_TYPES  = _FILE_LOG_TYPES + ["workspace"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Parse auth, web, or Google Workspace logs and detect suspicious activity.",
    )
    p.add_argument(
        "--file",
        default=None,
        metavar="PATH",
        help="Path to the log file to analyze. Required for --type auth and --type web.",
    )
    p.add_argument(
        "--type",
        required=True,
        choices=_ALL_LOG_TYPES,
        dest="log_type",
        help=(
            "Log source to analyze: "
            "'auth' (/var/log/auth.log), "
            "'web' (Apache/Nginx access log), or "
            "'workspace' (Google Workspace Admin SDK — ignores --file)."
        ),
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
    p.add_argument(
        "--lookback",
        type=int,
        default=6,
        metavar="HOURS",
        help=(
            "Hours of history to fetch when --type is workspace (default: 6). "
            "Has no effect for file-based log types."
        ),
    )
    return p


def _run_file_pipeline(args: argparse.Namespace) -> tuple[list, str]:
    """Parse a local log file and run auth/web detectors. Returns (alerts, source_label)."""
    if args.file is None:
        print(
            f"error: --file is required when --type is '{args.log_type}'",
            file=sys.stderr,
        )
        sys.exit(2)

    log_path = Path(args.file)
    if not log_path.is_file():
        print(f"error: file not found: {log_path}", file=sys.stderr)
        sys.exit(2)

    file_parsers = {
        "auth": auth_parser.parse,
        "web":  web_parser.parse,
    }

    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    entries = file_parsers[args.log_type](lines)

    alerts = failed_login.detect(entries) + brute_force.detect(entries)
    return alerts, str(log_path)


def _run_workspace_pipeline(args: argparse.Namespace) -> tuple[list, str]:
    """Fetch Workspace events via the Admin SDK and run all four workspace detectors.
    Returns (alerts, source_label).
    """
    # Load by file path so the root-level auth/, parsers/, detectors/ directories
    # don't collide with the same-named packages inside log_analyzer/.
    try:
        google_auth    = _load_module_from_path("google_auth",          _ROOT / "auth"      / "google_auth.py")
        ws_parser      = _load_module_from_path("workspace_parser",     _ROOT / "parsers"   / "workspace_parser.py")
        ws_detectors   = _load_module_from_path("workspace_detectors",  _ROOT / "detectors" / "workspace_detectors.py")
    except ImportError as e:
        print(
            f"error: Google Workspace dependencies not available: {e}\n"
            "Run: pip install -r requirements.txt",
            file=sys.stderr,
        )
        sys.exit(2)

    get_reports_service  = google_auth.get_reports_service
    workspace_parse      = ws_parser.parse
    detect_failed_logins = ws_detectors.detect_failed_logins
    detect_brute_force   = ws_detectors.detect_brute_force
    detect_suspicious_oauth = ws_detectors.detect_suspicious_oauth
    detect_admin_changes = ws_detectors.detect_admin_changes

    try:
        service = get_reports_service()
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"error: authentication failed: {e}", file=sys.stderr)
        sys.exit(2)

    entries = workspace_parse(service, lookback_hours=args.lookback)

    alerts = (
        detect_failed_logins(entries)
        + detect_brute_force(entries)
        + detect_suspicious_oauth(entries)
        + detect_admin_changes(entries)
    )

    source_label = f"Google Workspace (last {args.lookback}h)"
    return alerts, source_label


def main() -> None:
    args = build_parser().parse_args()

    # Apply optional threshold override before any detector reads config
    if args.threshold is not None:
        config.MAX_FAILED_LOGINS = args.threshold

    # Dispatch to the appropriate pipeline
    if args.log_type == "workspace":
        alerts, source_label = _run_workspace_pipeline(args)
    else:
        alerts, source_label = _run_file_pipeline(args)

    alerts.sort(key=lambda a: a.timestamp)

    # Report
    report = _REPORTERS[args.reporter]
    report(alerts)

    # Summary — always to stderr so it never corrupts JSON output
    high_count = sum(1 for a in alerts if a.severity == "high")
    print(
        f"\n--- source: {source_label} | "
        f"{len(alerts)} alert(s) total | "
        f"{high_count} high-severity ---",
        file=sys.stderr,
    )

    # Exit 1 if any high-severity alerts found (useful in CI / shell pipelines)
    sys.exit(1 if high_count > 0 else 0)


if __name__ == "__main__":
    main()
