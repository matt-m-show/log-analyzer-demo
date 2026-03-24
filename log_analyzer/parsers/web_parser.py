# Parses Apache/Nginx combined access log format into LogEntry objects

import re
from datetime import datetime, timezone
from typing import Iterable

from models import LogEntry

# Matches Apache/Nginx combined log format lines, e.g.:
#   192.168.1.105 - - [24/Mar/2026:03:12:45 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"
_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)'                          # client IP
    r'\s+\S+\s+\S+'                          # ident and auth (usually - -)
    r'\s+\[(?P<time>[^\]]+)\]'               # [timestamp]
    r'\s+"(?P<method>\S+)'                   # "METHOD
    r'\s+(?P<path>\S+)'                      # /path
    r'\s+\S+"'                               # HTTP/x.x"
    r'\s+(?P<status>\d{3})'                  # status code
    r'\s+\S+'                                # response size
    r'\s+"[^"]*"'                            # referrer
    r'\s+"(?P<user_agent>[^"]*)"'            # "User-Agent"
)

_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse(lines: Iterable[str]) -> list[LogEntry]:
    """Parse an iterable of combined-format access log lines and return LogEntry objects.

    Lines that do not match the combined log format are silently skipped.
    Timestamps are converted to UTC at parse time.
    raw_message contains a formatted summary: METHOD path status "User-Agent".
    """
    entries: list[LogEntry] = []

    for line in lines:
        line = line.rstrip("\n")
        match = _COMBINED_PATTERN.match(line)
        if not match:
            continue

        try:
            timestamp = datetime.strptime(
                match.group("time"), _TIMESTAMP_FORMAT
            ).astimezone(timezone.utc)
        except ValueError:
            continue

        method = match.group("method")
        path = match.group("path")
        status = match.group("status")
        user_agent = match.group("user_agent")

        entries.append(
            LogEntry(
                timestamp=timestamp,
                source_ip=match.group("ip"),
                log_type="web",
                raw_message=f'{method} {path} {status} "{user_agent}"',
            )
        )

    return entries
