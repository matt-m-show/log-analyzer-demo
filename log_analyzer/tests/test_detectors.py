# Unit tests for failed_login, brute_force, and workspace_detectors

import importlib.util
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
# Add log_analyzer/ so config, models, and log_analyzer detectors are importable
_LOG_ANALYZER = Path(__file__).parent.parent
_ROOT         = _LOG_ANALYZER.parent
sys.path.insert(0, str(_LOG_ANALYZER))

# Load workspace_detectors from the root-level detectors/ directory by path,
# since it lives outside the log_analyzer package.
def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_ws_det = _load("workspace_detectors", _ROOT / "detectors" / "workspace_detectors.py")

import config
from detectors import brute_force, failed_login
from models import Alert, LogEntry

# ── Helpers ───────────────────────────────────────────────────────────────────

_BASE_TS = datetime(2026, 3, 24, 9, 0, 0, tzinfo=timezone.utc)


def _auth_entry(raw_message: str, source_ip: str = "10.0.0.1",
                offset_s: int = 0) -> LogEntry:
    return LogEntry(
        timestamp=_BASE_TS + timedelta(seconds=offset_s),
        source_ip=source_ip,
        log_type="auth",
        raw_message=raw_message,
    )


def _ws_entry(raw_message: str, source_ip: str = "10.0.0.1",
              offset_s: int = 0) -> LogEntry:
    return LogEntry(
        timestamp=_BASE_TS + timedelta(seconds=offset_s),
        source_ip=source_ip,
        log_type="workspace",
        raw_message=raw_message,
    )


def _failed(ip: str = "10.0.0.1", offset_s: int = 0) -> LogEntry:
    return _auth_entry("Failed password for invalid user admin", ip, offset_s)


def _ws_failed(ip: str = "10.0.0.1", offset_s: int = 0) -> LogEntry:
    return _ws_entry("login | login_failure | user@example.com", ip, offset_s)


# ── TestFailedLoginDetector ───────────────────────────────────────────────────

class TestFailedLoginDetector(unittest.TestCase):

    def setUp(self):
        # Ensure SAFE_IPS is empty for each test
        self._orig_safe_ips = config.SAFE_IPS
        config.SAFE_IPS = []

    def tearDown(self):
        config.SAFE_IPS = self._orig_safe_ips

    def test_failed_login_produces_low_alert(self):
        alerts = failed_login.detect([_failed()])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "low")

    def test_successful_login_produces_no_alert(self):
        entry = _auth_entry("Accepted password for alice from 10.0.0.1 port 22 ssh2")
        alerts = failed_login.detect([entry])
        self.assertEqual(alerts, [])

    def test_safe_ip_skipped(self):
        config.SAFE_IPS = ["192.168.1.105"]
        alerts = failed_login.detect([_failed(ip="192.168.1.105")])
        self.assertEqual(alerts, [])

    def test_multiple_failed_logins_produce_one_alert_each(self):
        entries = [_failed(offset_s=i) for i in range(3)]
        alerts = failed_login.detect(entries)
        self.assertEqual(len(alerts), 3)
        for a in alerts:
            self.assertEqual(a.severity, "low")

    def test_alert_source_ip_matches_entry(self):
        alerts = failed_login.detect([_failed(ip="1.2.3.4")])
        self.assertEqual(alerts[0].source_ip, "1.2.3.4")

    def test_alert_triggering_entries_contains_entry(self):
        entry = _failed()
        alerts = failed_login.detect([entry])
        self.assertIn(entry, alerts[0].triggering_entries)

    def test_returns_alert_objects(self):
        alerts = failed_login.detect([_failed()])
        self.assertIsInstance(alerts[0], Alert)

    def test_empty_input(self):
        self.assertEqual(failed_login.detect([]), [])


# ── TestBruteForceDetector ────────────────────────────────────────────────────

class TestBruteForceDetector(unittest.TestCase):

    def setUp(self):
        self._orig_safe_ips  = config.SAFE_IPS
        self._orig_threshold = config.BRUTE_FORCE_ATTEMPT_THRESHOLD
        self._orig_window    = config.BRUTE_FORCE_WINDOW_SECONDS
        config.SAFE_IPS                  = []
        config.BRUTE_FORCE_ATTEMPT_THRESHOLD = 3
        config.BRUTE_FORCE_WINDOW_SECONDS    = 60

    def tearDown(self):
        config.SAFE_IPS                      = self._orig_safe_ips
        config.BRUTE_FORCE_ATTEMPT_THRESHOLD = self._orig_threshold
        config.BRUTE_FORCE_WINDOW_SECONDS    = self._orig_window

    def _entries(self, count: int, ip: str = "10.0.0.1",
                 spacing_s: int = 5) -> list[LogEntry]:
        return [_failed(ip=ip, offset_s=i * spacing_s) for i in range(count)]

    def test_below_threshold_no_alert(self):
        # threshold = 3; send 2
        alerts = brute_force.detect(self._entries(2))
        self.assertEqual(alerts, [])

    def test_at_threshold_produces_alert(self):
        alerts = brute_force.detect(self._entries(3))
        self.assertEqual(len(alerts), 1)

    def test_exceeding_threshold_produces_one_alert_per_ip(self):
        alerts = brute_force.detect(self._entries(10))
        self.assertEqual(len(alerts), 1)

    def test_alert_is_high_severity(self):
        alerts = brute_force.detect(self._entries(3))
        self.assertEqual(alerts[0].severity, "high")

    def test_triggering_entries_contains_threshold_entries(self):
        entries = self._entries(3)
        alerts = brute_force.detect(entries)
        self.assertEqual(len(alerts[0].triggering_entries), 3)
        for e in entries:
            self.assertIn(e, alerts[0].triggering_entries)

    def test_entries_outside_window_do_not_trigger(self):
        # spacing of 40s each; entries[0]→entries[2] span 80s > window of 60s
        alerts = brute_force.detect(self._entries(3, spacing_s=40))
        self.assertEqual(alerts, [])

    def test_safe_ip_skipped(self):
        config.SAFE_IPS = ["10.0.0.1"]
        alerts = brute_force.detect(self._entries(10))
        self.assertEqual(alerts, [])

    def test_two_ips_each_exceeding_threshold_produce_two_alerts(self):
        entries = self._entries(3, ip="1.1.1.1") + self._entries(3, ip="2.2.2.2")
        alerts = brute_force.detect(entries)
        self.assertEqual(len(alerts), 2)
        ips = {a.source_ip for a in alerts}
        self.assertIn("1.1.1.1", ips)
        self.assertIn("2.2.2.2", ips)

    def test_successful_logins_not_counted(self):
        entries = self._entries(2)
        entries.append(_auth_entry("Accepted password for alice", offset_s=5))
        alerts = brute_force.detect(entries)
        self.assertEqual(alerts, [])

    def test_empty_input(self):
        self.assertEqual(brute_force.detect([]), [])


# ── TestWorkspaceDetectors ────────────────────────────────────────────────────

class TestWorkspaceDetectors(unittest.TestCase):

    def setUp(self):
        self._orig_safe_ips  = config.SAFE_IPS
        self._orig_threshold = config.BRUTE_FORCE_ATTEMPT_THRESHOLD
        self._orig_window    = config.BRUTE_FORCE_WINDOW_SECONDS
        config.SAFE_IPS                      = []
        config.BRUTE_FORCE_ATTEMPT_THRESHOLD = 3
        config.BRUTE_FORCE_WINDOW_SECONDS    = 60

    def tearDown(self):
        config.SAFE_IPS                      = self._orig_safe_ips
        config.BRUTE_FORCE_ATTEMPT_THRESHOLD = self._orig_threshold
        config.BRUTE_FORCE_WINDOW_SECONDS    = self._orig_window

    # ── detect_failed_logins ──────────────────────────────────────────────

    def test_ws_failed_login_produces_low_alert(self):
        alerts = _ws_det.detect_failed_logins([_ws_failed()])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "low")

    def test_ws_failed_login_non_workspace_ignored(self):
        entry = _auth_entry("login_failure from 10.0.0.1")
        alerts = _ws_det.detect_failed_logins([entry])
        self.assertEqual(alerts, [])

    def test_ws_failed_login_safe_ip_skipped(self):
        config.SAFE_IPS = ["10.0.0.1"]
        alerts = _ws_det.detect_failed_logins([_ws_failed()])
        self.assertEqual(alerts, [])

    def test_ws_failed_login_no_keyword_no_alert(self):
        entry = _ws_entry("login | login_success | user@example.com")
        alerts = _ws_det.detect_failed_logins([entry])
        self.assertEqual(alerts, [])

    # ── detect_brute_force ────────────────────────────────────────────────

    def test_ws_brute_force_below_threshold_no_alert(self):
        entries = [_ws_failed(offset_s=i * 5) for i in range(2)]
        alerts = _ws_det.detect_brute_force(entries)
        self.assertEqual(alerts, [])

    def test_ws_brute_force_at_threshold_produces_high_alert(self):
        entries = [_ws_failed(offset_s=i * 5) for i in range(3)]
        alerts = _ws_det.detect_brute_force(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "high")

    def test_ws_brute_force_triggering_entries(self):
        entries = [_ws_failed(offset_s=i * 5) for i in range(3)]
        alerts = _ws_det.detect_brute_force(entries)
        self.assertEqual(len(alerts[0].triggering_entries), 3)

    def test_ws_brute_force_non_workspace_ignored(self):
        entries = [_auth_entry("login_failure", offset_s=i * 5) for i in range(5)]
        alerts = _ws_det.detect_brute_force(entries)
        self.assertEqual(alerts, [])

    def test_ws_brute_force_safe_ip_skipped(self):
        config.SAFE_IPS = ["10.0.0.1"]
        entries = [_ws_failed(offset_s=i * 5) for i in range(5)]
        alerts = _ws_det.detect_brute_force(entries)
        self.assertEqual(alerts, [])

    # ── detect_admin_changes ──────────────────────────────────────────────

    def test_ws_admin_change_produces_high_alert(self):
        entry = _ws_entry("admin | CREATE_USER | actor@example.com")
        alerts = _ws_det.detect_admin_changes([entry])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "high")

    def test_ws_admin_change_non_workspace_ignored(self):
        entry = _auth_entry("admin | CREATE_USER")
        alerts = _ws_det.detect_admin_changes([entry])
        self.assertEqual(alerts, [])

    def test_ws_admin_change_no_prefix_no_alert(self):
        entry = _ws_entry("login | admin_something")
        alerts = _ws_det.detect_admin_changes([entry])
        self.assertEqual(alerts, [])

    # ── detect_suspicious_oauth ───────────────────────────────────────────

    def test_ws_oauth_authorize_produces_medium_alert(self):
        entry = _ws_entry("token | authorize | client_id=some-app")
        alerts = _ws_det.detect_suspicious_oauth([entry])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "medium")

    def test_ws_oauth_non_workspace_ignored(self):
        entry = _auth_entry("token | authorize | client_id=some-app")
        alerts = _ws_det.detect_suspicious_oauth([entry])
        self.assertEqual(alerts, [])

    def test_ws_oauth_no_authorize_no_alert(self):
        entry = _ws_entry("token | revoke | client_id=some-app")
        alerts = _ws_det.detect_suspicious_oauth([entry])
        self.assertEqual(alerts, [])

    def test_ws_oauth_returns_alert_objects(self):
        entry = _ws_entry("token | authorize | client_id=some-app")
        alerts = _ws_det.detect_suspicious_oauth([entry])
        self.assertIsInstance(alerts[0], Alert)


if __name__ == "__main__":
    unittest.main()
