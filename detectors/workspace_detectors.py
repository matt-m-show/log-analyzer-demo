# Detectors for Google Workspace audit log events (log_type="workspace")

import sys
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "log_analyzer"))

import logging
import re

import config
from models import Alert, LogEntry

_log = logging.getLogger(__name__)

# Matches client_id=<value> anywhere in raw_message
_CLIENT_ID_RE = re.compile(r"client_id=([^\s|,]+)")


def detect_failed_logins(entries: list[LogEntry]) -> list[Alert]:
    """Return a low-severity Alert for each Workspace login_failure event.

    Operates on entries with log_type 'workspace' whose raw_message contains
    'login_failure'. One Alert is emitted per entry. IPs in config.SAFE_IPS
    are skipped.
    """
    safe_ips = set(config.SAFE_IPS)
    alerts: list[Alert] = []

    for entry in entries:
        if entry.log_type != "workspace":
            continue
        if entry.source_ip in safe_ips:
            continue
        if "login_failure" not in entry.raw_message:
            continue

        alerts.append(
            Alert(
                severity="low",
                description=f"Workspace failed login from {entry.source_ip}",
                source_ip=entry.source_ip,
                timestamp=entry.timestamp,
                triggering_entries=(entry,),
            )
        )

    return alerts


def detect_brute_force(entries: list[LogEntry]) -> list[Alert]:
    """Return a high-severity Alert for each IP exceeding BRUTE_FORCE_ATTEMPT_THRESHOLD
    Workspace login_failure events within a sliding window of BRUTE_FORCE_WINDOW_SECONDS.

    Uses the same sliding-window algorithm as detectors/brute_force.py. One Alert
    is emitted per offending IP, containing all entries in the first breaching window.
    IPs in config.SAFE_IPS are skipped.
    """
    safe_ips = set(config.SAFE_IPS)
    window = timedelta(seconds=config.BRUTE_FORCE_WINDOW_SECONDS)
    threshold = config.BRUTE_FORCE_ATTEMPT_THRESHOLD

    # Collect workspace login_failure entries per IP
    by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.log_type != "workspace":
            continue
        if entry.source_ip in safe_ips:
            continue
        if "login_failure" not in entry.raw_message:
            continue
        by_ip[entry.source_ip].append(entry)

    for ip_entries in by_ip.values():
        ip_entries.sort(key=lambda e: e.timestamp)

    alerts: list[Alert] = []

    for ip, ip_entries in by_ip.items():
        for i, anchor in enumerate(ip_entries):
            window_entries = [
                e for e in ip_entries[i:]
                if e.timestamp - anchor.timestamp <= window
            ]
            if len(window_entries) >= threshold:
                alerts.append(
                    Alert(
                        severity="high",
                        description=(
                            f"Workspace brute force detected from {ip}: "
                            f"{len(window_entries)} failed login attempts "
                            f"within {config.BRUTE_FORCE_WINDOW_SECONDS}s"
                        ),
                        source_ip=ip,
                        timestamp=anchor.timestamp,
                        triggering_entries=tuple(window_entries),
                    )
                )
                break  # One alert per IP — stop after the first breaching window

    return alerts


def detect_suspicious_oauth(entries: list[LogEntry]) -> list[Alert]:
    """Return a medium-severity Alert for each Workspace OAuth token grant event
    whose client_id is not in WORKSPACE_OAUTH_WHITELIST.

    Extracts client_id from raw_message using the pattern client_id=<value>.
    Whitelisted client IDs are silently skipped with a debug log line.
    """
    whitelist: dict[str, str] = {
        entry["client_id"]: entry["app_name"]
        for entry in config.WORKSPACE_OAUTH_WHITELIST
    }
    alerts: list[Alert] = []

    for entry in entries:
        if entry.log_type != "workspace":
            continue
        if "authorize" not in entry.raw_message:
            continue

        # Extract client_id from raw_message; treat missing as unknown
        match = _CLIENT_ID_RE.search(entry.raw_message)
        client_id = match.group(1) if match else ""

        if client_id and client_id in whitelist:
            _log.debug(
                "Skipping whitelisted OAuth client %s (%s) from %s",
                client_id, whitelist[client_id], entry.source_ip,
            )
            continue

        alerts.append(
            Alert(
                severity="medium",
                description=(
                    f"Suspicious OAuth grant from {entry.source_ip}: "
                    f"client_id={client_id or 'unknown'}"
                ),
                source_ip=entry.source_ip,
                timestamp=entry.timestamp,
                triggering_entries=(entry,),
            )
        )

    return alerts


def detect_admin_changes(entries: list[LogEntry]) -> list[Alert]:
    """Return a high-severity Alert for each Workspace Admin activity event.

    Flags entries with log_type 'workspace' whose raw_message starts with 'admin |',
    which corresponds to events fetched from the Admin SDK 'admin' application.
    All admin activity is flagged regardless of source IP, since admin changes
    should always be reviewed.
    """
    alerts: list[Alert] = []

    for entry in entries:
        if entry.log_type != "workspace":
            continue
        if not entry.raw_message.startswith("admin |"):
            continue

        alerts.append(
            Alert(
                severity="high",
                description=(
                    f"Workspace admin change from {entry.source_ip}: "
                    f"{entry.raw_message}"
                ),
                source_ip=entry.source_ip,
                timestamp=entry.timestamp,
                triggering_entries=(entry,),
            )
        )

    return alerts
