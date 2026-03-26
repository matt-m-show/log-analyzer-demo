# Unit tests for console_reporter and json_reporter

import io
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import Alert, LogEntry
from reporters import console_reporter, json_reporter

# ── Shared fixtures ───────────────────────────────────────────────────────────

_TS = datetime(2026, 3, 24, 9, 3, 57, tzinfo=timezone.utc)

_ENTRY = LogEntry(
    timestamp=_TS,
    source_ip="192.168.1.105",
    log_type="auth",
    raw_message="Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2",
)

_HIGH_ALERT = Alert(
    severity="high",
    description="Brute force detected from 192.168.1.105",
    source_ip="192.168.1.105",
    timestamp=_TS,
    triggering_entries=(_ENTRY,),
)

_LOW_ALERT = Alert(
    severity="low",
    description="Failed login attempt from 10.0.0.2",
    source_ip="10.0.0.2",
    timestamp=_TS,
    triggering_entries=(_ENTRY,),
)


# ── TestConsoleReporter ───────────────────────────────────────────────────────

class TestConsoleReporter(unittest.TestCase):

    def _capture(self, alerts: list[Alert]) -> str:
        """Run console_reporter.report and return everything printed to stdout."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            console_reporter.report(alerts)
            return mock_out.getvalue()

    def test_high_alert_output_contains_severity(self):
        output = self._capture([_HIGH_ALERT])
        self.assertIn("HIGH", output.upper())

    def test_high_alert_output_contains_description(self):
        output = self._capture([_HIGH_ALERT])
        self.assertIn("Brute force detected from 192.168.1.105", output)

    def test_high_alert_output_contains_timestamp(self):
        output = self._capture([_HIGH_ALERT])
        self.assertIn("2026-03-24", output)

    def test_low_alert_output_contains_severity(self):
        output = self._capture([_LOW_ALERT])
        self.assertIn("LOW", output.upper())

    def test_low_alert_output_contains_description(self):
        output = self._capture([_LOW_ALERT])
        self.assertIn("Failed login attempt from 10.0.0.2", output)

    def test_empty_list_no_alert_lines(self):
        output = self._capture([])
        # Should not contain any severity labels
        self.assertNotIn("[ HIGH ]", output)
        self.assertNotIn("[ LOW  ]", output)
        self.assertNotIn("[MEDIUM]", output)

    def test_multiple_alerts_all_printed(self):
        output = self._capture([_HIGH_ALERT, _LOW_ALERT])
        self.assertIn("Brute force detected from 192.168.1.105", output)
        self.assertIn("Failed login attempt from 10.0.0.2", output)

    def test_triggering_entry_count_in_output(self):
        output = self._capture([_HIGH_ALERT])
        # _HIGH_ALERT has 1 triggering entry
        self.assertIn("1", output)


# ── TestJsonReporter ──────────────────────────────────────────────────────────

class TestJsonReporter(unittest.TestCase):

    def _capture(self, alerts: list[Alert]) -> str:
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            json_reporter.report(alerts)
            return mock_out.getvalue()

    def _parsed(self, alerts: list[Alert]) -> list[dict]:
        return json.loads(self._capture(alerts))

    def test_output_is_valid_json(self):
        raw = self._capture([_HIGH_ALERT])
        try:
            json.loads(raw)
        except json.JSONDecodeError as e:
            self.fail(f"Output is not valid JSON: {e}")

    def test_empty_list_produces_empty_json_array(self):
        data = self._parsed([])
        self.assertEqual(data, [])

    def test_single_alert_produces_one_element_array(self):
        data = self._parsed([_HIGH_ALERT])
        self.assertEqual(len(data), 1)

    def test_multiple_alerts_all_present(self):
        data = self._parsed([_HIGH_ALERT, _LOW_ALERT])
        self.assertEqual(len(data), 2)
        descriptions = {d["description"] for d in data}
        self.assertIn("Brute force detected from 192.168.1.105", descriptions)
        self.assertIn("Failed login attempt from 10.0.0.2", descriptions)

    def test_timestamp_is_iso_8601_string(self):
        data = self._parsed([_HIGH_ALERT])
        ts = data[0]["timestamp"]
        self.assertIsInstance(ts, str)
        # Must be parseable as an ISO 8601 datetime
        parsed = datetime.fromisoformat(ts)
        self.assertEqual(parsed.year, 2026)
        self.assertEqual(parsed.month, 3)
        self.assertEqual(parsed.day, 24)

    def test_severity_field_present(self):
        data = self._parsed([_HIGH_ALERT])
        self.assertIn("severity", data[0])
        self.assertEqual(data[0]["severity"], "high")

    def test_description_field_present(self):
        data = self._parsed([_HIGH_ALERT])
        self.assertIn("description", data[0])

    def test_source_ip_field_present(self):
        data = self._parsed([_HIGH_ALERT])
        self.assertIn("source_ip", data[0])
        self.assertEqual(data[0]["source_ip"], "192.168.1.105")

    def test_triggering_entries_field_present(self):
        data = self._parsed([_HIGH_ALERT])
        self.assertIn("triggering_entries", data[0])
        self.assertIsInstance(data[0]["triggering_entries"], list)

    def test_triggering_entry_has_expected_fields(self):
        data = self._parsed([_HIGH_ALERT])
        entry = data[0]["triggering_entries"][0]
        for field in ("timestamp", "source_ip", "log_type", "raw_message"):
            self.assertIn(field, entry)

    def test_triggering_entry_timestamp_is_iso_string(self):
        data = self._parsed([_HIGH_ALERT])
        entry_ts = data[0]["triggering_entries"][0]["timestamp"]
        self.assertIsInstance(entry_ts, str)
        datetime.fromisoformat(entry_ts)  # raises if not valid ISO 8601


if __name__ == "__main__":
    unittest.main()
