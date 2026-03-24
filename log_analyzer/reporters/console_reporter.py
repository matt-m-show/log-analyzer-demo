# Formats and prints Alert objects to stdout

from models import Alert

_SEVERITY_LABEL = {
    "low":    "[ LOW  ]",
    "medium": "[MEDIUM]",
    "high":   "[ HIGH ]",
}


def report(alerts: list[Alert]) -> None:
    """Print a human-readable summary of each alert to stdout."""
    if not alerts:
        print("No alerts detected.")
        return

    for alert in alerts:
        label = _SEVERITY_LABEL.get(alert.severity, f"[{alert.severity.upper()}]")
        print(
            f"{label} {alert.timestamp.isoformat()} | "
            f"{alert.description} | "
            f"{len(alert.triggering_entries)} triggering "
            f"{'entry' if len(alert.triggering_entries) == 1 else 'entries'}"
        )
