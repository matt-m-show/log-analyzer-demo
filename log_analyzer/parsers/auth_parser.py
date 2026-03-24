# Parses /var/log/auth.log format into LogEntry objects

import re
from datetime import datetime, timezone
from typing import Iterable

from models import LogEntry

# Matches SSH accepted/failed password lines, e.g.:
#   Mar 24 03:12:45 webserver sshd[8821]: Failed password for invalid user admin from 192.168.1.105 port 54321 ssh2
#   Mar 24 03:15:01 webserver sshd[8900]: Accepted password for deploy from 10.0.0.5 port 22 ssh2
_SSH_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted) password for (?:invalid user )?"
    r"\S+\s+from\s+(?P<ip>\S+)"
)

# auth.log omits the year; use the current UTC year as a best-effort default
_CURRENT_YEAR = datetime.now(timezone.utc).year


def parse(lines: Iterable[str]) -> list[LogEntry]:
    """Parse an iterable of auth.log lines and return matching LogEntry objects.

    Lines that do not match the expected SSH format are silently skipped.
    Timestamps are returned in UTC (year assumed to be the current year).
    """
    entries: list[LogEntry] = []

    for line in lines:
        line = line.rstrip("\n")
        match = _SSH_PATTERN.match(line)
        if not match:
            continue

        try:
            timestamp = datetime.strptime(
                f"{_CURRENT_YEAR} {match.group('month')} {match.group('day')} {match.group('time')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        entries.append(
            LogEntry(
                timestamp=timestamp,
                source_ip=match.group("ip"),
                log_type="auth",
                raw_message=line,
            )
        )

    return entries
