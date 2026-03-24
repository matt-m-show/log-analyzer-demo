# Serializes Alert objects to JSON output

import json
import sys

from models import Alert


def _alert_to_dict(alert: Alert) -> dict:
    return {
        "severity": alert.severity,
        "description": alert.description,
        "source_ip": alert.source_ip,
        "timestamp": alert.timestamp.isoformat(),
        "triggering_entries": [
            {
                "timestamp": entry.timestamp.isoformat(),
                "source_ip": entry.source_ip,
                "log_type": entry.log_type,
                "raw_message": entry.raw_message,
            }
            for entry in alert.triggering_entries
        ],
    }


def report(alerts: list[Alert]) -> None:
    """Serialize alerts to JSON and print to stdout, one JSON array per call."""
    print(json.dumps([_alert_to_dict(a) for a in alerts], indent=2), file=sys.stdout)
