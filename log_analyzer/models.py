# Shared frozen dataclasses: LogEntry and Alert

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEntry:
    """A single parsed line from a log file, normalized into a common structure."""

    timestamp: datetime
    source_ip: str
    log_type: str        # "auth" or "web"
    raw_message: str


@dataclass(frozen=True)
class Alert:
    """A suspicious pattern detected by a detector, ready to be reported."""

    severity: str        # "low", "medium", or "high"
    description: str
    source_ip: str
    timestamp: datetime
    triggering_entries: tuple[LogEntry, ...]
