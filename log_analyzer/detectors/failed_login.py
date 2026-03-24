# Detects individual failed login events and emits low-severity alerts

import config
from models import Alert, LogEntry


def detect(entries: list[LogEntry]) -> list[Alert]:
    """Return a low-severity Alert for each failed login entry not from a safe IP.

    Detection is based on the presence of "Failed" in raw_message, which is set
    by auth_parser for SSH failed-password lines.
    """
    safe_ips = set(config.SAFE_IPS)
    alerts: list[Alert] = []

    for entry in entries:
        if entry.source_ip in safe_ips:
            continue
        if "Failed" not in entry.raw_message:
            continue

        alerts.append(
            Alert(
                severity="low",
                description=f"Failed login attempt from {entry.source_ip}",
                source_ip=entry.source_ip,
                timestamp=entry.timestamp,
                triggering_entries=(entry,),
            )
        )

    return alerts
