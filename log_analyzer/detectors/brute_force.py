# Detects brute force attempts by tracking failed logins per IP over time

from collections import defaultdict
from datetime import timedelta

import config
from models import Alert, LogEntry


def detect(entries: list[LogEntry]) -> list[Alert]:
    """Return a high-severity Alert for each IP that exceeds BRUTE_FORCE_ATTEMPT_THRESHOLD
    failed logins within a sliding window of BRUTE_FORCE_WINDOW_SECONDS.

    One alert is emitted per offending IP, containing all entries in the window
    that first caused the threshold to be crossed.
    """
    safe_ips = set(config.SAFE_IPS)
    window = timedelta(seconds=config.BRUTE_FORCE_WINDOW_SECONDS)
    threshold = config.BRUTE_FORCE_ATTEMPT_THRESHOLD

    # Collect failed entries per IP, sorted by timestamp ascending
    by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.source_ip in safe_ips:
            continue
        if "Failed" not in entry.raw_message:
            continue
        by_ip[entry.source_ip].append(entry)

    for ip_entries in by_ip.values():
        ip_entries.sort(key=lambda e: e.timestamp)

    alerts: list[Alert] = []

    for ip, ip_entries in by_ip.items():
        # Slide a window starting at each entry; stop once the threshold is crossed
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
                            f"Brute force detected from {ip}: "
                            f"{len(window_entries)} failed attempts "
                            f"within {config.BRUTE_FORCE_WINDOW_SECONDS}s"
                        ),
                        source_ip=ip,
                        timestamp=anchor.timestamp,
                        triggering_entries=tuple(window_entries),
                    )
                )
                break  # One alert per IP — stop after the first breaching window

    return alerts
