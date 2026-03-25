# Fetches Google Workspace audit log events via the Admin SDK and returns LogEntry objects

import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "log_analyzer"))

from models import LogEntry

logger = logging.getLogger(__name__)

# Applications supported by the Admin SDK Reports API activities endpoint
DEFAULT_APPLICATIONS = ["login", "drive", "admin", "token"]

# RFC 3339 format expected by the Admin SDK startTime / endTime parameters
_SDK_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

# ISO 8601 format returned by the Admin SDK in event id.time fields
_EVENT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_EVENT_TIME_FORMAT_NO_MS = "%Y-%m-%dT%H:%M:%SZ"


def _parse_event_timestamp(raw: str) -> datetime | None:
    """Parse an Admin SDK event timestamp string into a UTC datetime.

    Returns None if the string is missing or does not match either expected format.
    """
    if not raw:
        return None
    for fmt in (_EVENT_TIME_FORMAT, _EVENT_TIME_FORMAT_NO_MS):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _format_raw_message(app: str, event: dict) -> str:
    """Build a human-readable raw_message string from an Admin SDK event dict.

    Format: '<app> | <eventName> | key=value key=value ...'
    Only the first event in the events list is used; parameters are flattened
    to key=value pairs sorted by key name for consistency.
    """
    events = event.get("events", [])
    if not events:
        return f"{app} | (no event data)"

    ev = events[0]
    event_name = ev.get("name", "unknown")

    params = ev.get("parameters", [])
    param_parts = []
    for p in sorted(params, key=lambda x: x.get("name", "")):
        name = p.get("name", "")
        # Parameters carry their value under one of several typed keys
        value = (
            p.get("value")
            or p.get("intValue")
            or p.get("boolValue")
            or p.get("multiValue")
            or ""
        )
        if isinstance(value, list):
            value = ",".join(str(v) for v in value)
        param_parts.append(f"{name}={value}")

    params_str = " ".join(param_parts) if param_parts else "(no parameters)"
    return f"{app} | {event_name} | {params_str}"


def parse(
    service,
    applications: list[str] | None = None,
    lookback_hours: int = 6,
) -> list[LogEntry]:
    """Fetch Workspace audit log events and return them as LogEntry objects.

    Paginates through all result pages for each application within the lookback
    window. Events with missing or malformed timestamps are silently skipped.
    Results are sorted by timestamp ascending.

    Args:
        service:         Authenticated Admin SDK Reports API service object from
                         auth.google_auth.get_reports_service().
        applications:    List of Admin SDK application names to query.
                         Defaults to DEFAULT_APPLICATIONS.
        lookback_hours:  How many hours back from now to fetch events (default 6).

    Returns:
        List of LogEntry objects sorted by timestamp ascending.
    """
    if applications is None:
        applications = DEFAULT_APPLICATIONS

    start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    start_str = start_time.strftime(_SDK_TIME_FORMAT)

    entries: list[LogEntry] = []

    for app in applications:
        logger.debug("Fetching Workspace audit events for application: %s", app)
        page_token = None

        while True:
            try:
                request = service.activities().list(
                    userKey="all",
                    applicationName=app,
                    startTime=start_str,
                    maxResults=1000,   # maximum page size allowed by the API
                    pageToken=page_token,
                )
                response = request.execute()
            except Exception as e:
                logger.warning("Failed to fetch events for application '%s': %s", app, e)
                break

            for event in response.get("items", []):
                raw_ts = event.get("id", {}).get("time", "")
                timestamp = _parse_event_timestamp(raw_ts)
                if timestamp is None:
                    logger.debug("Skipping event with unparseable timestamp: %r", raw_ts)
                    continue

                source_ip = event.get("ipAddress") or "unknown"
                raw_message = _format_raw_message(app, event)

                entries.append(
                    LogEntry(
                        timestamp=timestamp,
                        source_ip=source_ip,
                        log_type="workspace",
                        raw_message=raw_message,
                    )
                )

            page_token = response.get("nextPageToken")
            if not page_token:
                break

    entries.sort(key=lambda e: e.timestamp)
    return entries
