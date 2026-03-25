# Runs the Workspace detection pipeline on a recurring interval and appends alerts to JSONL

import importlib.util
import json
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

# ── Paths ─────────────────────────────────────────────────────────────────────

_ROOT        = Path(__file__).parent
_LOG_DIR     = _ROOT / "logs"
_ALERT_LOG   = _LOG_DIR / "alerts.json"

# ── Settings ──────────────────────────────────────────────────────────────────

# How often to run the pipeline (seconds). 6 hours = 21600.
RUN_INTERVAL_SECONDS: int = 6 * 60 * 60

# How far back each run fetches Workspace events (hours).
LOOKBACK_HOURS: int = 6


# ── Module loader ─────────────────────────────────────────────────────────────

def _load(name: str, path: Path) -> ModuleType:
    """Load a module by absolute file path and register it in sys.modules."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Ensure log_analyzer/ siblings (models, config, etc.) are importable
sys.path.insert(0, str(_ROOT / "log_analyzer"))

_google_auth      = _load("google_auth",         _ROOT / "auth"      / "google_auth.py")
_workspace_parser = _load("workspace_parser",    _ROOT / "parsers"   / "workspace_parser.py")
_ws_detectors     = _load("workspace_detectors", _ROOT / "detectors" / "workspace_detectors.py")


# ── Serialisation ─────────────────────────────────────────────────────────────

def _alert_to_jsonl(alert, fetched_at: str) -> str:
    """Serialise a single Alert to a JSONL string including fetched_at."""
    return json.dumps({
        "fetched_at":  fetched_at,
        "severity":    alert.severity,
        "description": alert.description,
        "source_ip":   alert.source_ip,
        "timestamp":   alert.timestamp.isoformat(),
        "triggering_entries": [
            {
                "timestamp":   e.timestamp.isoformat(),
                "source_ip":   e.source_ip,
                "log_type":    e.log_type,
                "raw_message": e.raw_message,
            }
            for e in alert.triggering_entries
        ],
    })


# ── Core run ──────────────────────────────────────────────────────────────────

def run_once() -> int:
    """Execute one full pipeline run. Returns the number of alerts written."""
    service = _google_auth.get_reports_service()
    entries = _workspace_parser.parse(service, lookback_hours=LOOKBACK_HOURS)

    alerts = (
        _ws_detectors.detect_failed_logins(entries)
        + _ws_detectors.detect_brute_force(entries)
        + _ws_detectors.detect_suspicious_oauth(entries)
        + _ws_detectors.detect_admin_changes(entries)
    )
    alerts.sort(key=lambda a: a.timestamp)

    if not alerts:
        return 0

    fetched_at = datetime.now(timezone.utc).isoformat()
    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    with _ALERT_LOG.open("a", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(_alert_to_jsonl(alert, fetched_at) + "\n")

    return len(alerts)


# ── Scheduler loop ────────────────────────────────────────────────────────────

def _fmt(dt: datetime) -> str:
    """Format a UTC datetime for status line output."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def main() -> None:
    print(f"Workspace log scheduler starting — interval: every {RUN_INTERVAL_SECONDS // 3600}h")
    print(f"Alert log: {_ALERT_LOG}")

    while True:
        run_start = datetime.now(timezone.utc)
        print(f"\n[{_fmt(run_start)}] Starting pipeline run...")

        try:
            count = run_once()
            run_end  = datetime.now(timezone.utc)
            elapsed  = (run_end - run_start).total_seconds()
            next_run = datetime.fromtimestamp(
                run_end.timestamp() + RUN_INTERVAL_SECONDS, tz=timezone.utc
            )
            print(
                f"[{_fmt(run_end)}] Run complete — "
                f"{count} alert(s) written in {elapsed:.1f}s | "
                f"next run at {_fmt(next_run)}"
            )

        except Exception:
            run_end  = datetime.now(timezone.utc)
            next_run = datetime.fromtimestamp(
                run_end.timestamp() + RUN_INTERVAL_SECONDS, tz=timezone.utc
            )
            print(
                f"[{_fmt(run_end)}] ERROR — run failed. "
                f"Waiting until {_fmt(next_run)} before retrying.\n"
                f"{traceback.format_exc()}",
                file=sys.stderr,
            )

        time.sleep(RUN_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
