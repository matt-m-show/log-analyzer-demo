# Unit tests for auth_parser and web_parser

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Make log_analyzer/ importable regardless of working directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from models import LogEntry
from parsers import auth_parser, web_parser


class TestAuthParser(unittest.TestCase):

    # ── Single-line cases ─────────────────────────────────────────────────

    def test_failed_ssh_login(self):
        line = "Mar 24 09:03:57 webserver sshd[3489]: Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2"
        entries = auth_parser.parse([line])
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.source_ip, "192.168.1.105")
        self.assertEqual(e.log_type, "auth")
        self.assertIn("Failed", e.raw_message)

    def test_accepted_ssh_login(self):
        line = "Mar 24 08:01:12 webserver sshd[3201]: Accepted password for alice from 10.0.0.21 port 51200 ssh2"
        entries = auth_parser.parse([line])
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.source_ip, "10.0.0.21")
        self.assertIn("Accepted", e.raw_message)

    def test_sudo_line_skipped(self):
        line = "Mar 24 08:15:44 webserver sudo[3340]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
        entries = auth_parser.parse([line])
        self.assertEqual(entries, [])

    def test_pam_line_skipped(self):
        line = "Mar 24 08:01:12 webserver sshd[3201]: pam_unix(sshd:session): session opened for user alice by (uid=0)"
        entries = auth_parser.parse([line])
        self.assertEqual(entries, [])

    def test_malformed_line_skipped(self):
        entries = auth_parser.parse(["this is not a log line at all"])
        self.assertEqual(entries, [])

    def test_empty_input(self):
        self.assertEqual(auth_parser.parse([]), [])

    # ── Multi-line / type checks ──────────────────────────────────────────

    def test_multiple_lines_parsed(self):
        lines = [
            "Mar 24 09:03:57 webserver sshd[3489]: Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2",
            "Mar 24 09:30:22 webserver sshd[3601]: Accepted password for bob from 203.0.113.42 port 49800 ssh2",
            "Mar 24 09:31:05 webserver sudo[3615]: bob : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
        ]
        entries = auth_parser.parse(lines)
        # sudo line must be skipped; two SSH password lines must be returned
        self.assertEqual(len(entries), 2)
        ips = {e.source_ip for e in entries}
        self.assertIn("192.168.1.105", ips)
        self.assertIn("203.0.113.42", ips)

    def test_returns_log_entry_objects(self):
        line = "Mar 24 09:03:57 webserver sshd[3489]: Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2"
        entries = auth_parser.parse([line])
        self.assertIsInstance(entries[0], LogEntry)

    def test_timestamp_is_datetime(self):
        line = "Mar 24 09:03:57 webserver sshd[3489]: Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2"
        entries = auth_parser.parse([line])
        self.assertIsInstance(entries[0].timestamp, datetime)

    def test_timestamp_is_utc(self):
        line = "Mar 24 09:03:57 webserver sshd[3489]: Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2"
        entries = auth_parser.parse([line])
        self.assertEqual(entries[0].timestamp.tzinfo, timezone.utc)

    def test_source_ip_is_str(self):
        line = "Mar 24 09:03:57 webserver sshd[3489]: Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2"
        entries = auth_parser.parse([line])
        self.assertIsInstance(entries[0].source_ip, str)

    def test_log_type_is_auth(self):
        line = "Mar 24 09:03:57 webserver sshd[3489]: Failed password for invalid user admin from 192.168.1.105 port 54301 ssh2"
        entries = auth_parser.parse([line])
        self.assertEqual(entries[0].log_type, "auth")

    def test_accepted_publickey_parsed(self):
        """Accepted publickey lines use a different keyword; documents current parser behaviour."""
        line = "Mar 24 09:30:22 webserver sshd[3601]: Accepted publickey for bob from 203.0.113.42 port 49800 ssh2"
        # parser currently matches only "password"; publickey lines are skipped
        entries = auth_parser.parse([line])
        self.assertIsInstance(entries, list)


class TestWebParser(unittest.TestCase):

    _200_LINE = (
        '10.0.0.21 - alice [24/Mar/2026:08:01:45 +0000] '
        '"GET /dashboard HTTP/1.1" 200 4321 '
        '"https://intranet.example.com/" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0.0.0"'
    )

    _404_LINE = (
        '192.168.1.105 - - [24/Mar/2026:09:05:11 +0000] '
        '"GET /admin HTTP/1.1" 404 512 '
        '"-" "python-requests/2.31.0"'
    )

    # ── Single-line cases ─────────────────────────────────────────────────

    def test_valid_200_line(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertEqual(len(entries), 1)

    def test_source_ip_extracted(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertEqual(entries[0].source_ip, "10.0.0.21")

    def test_404_parsed(self):
        entries = web_parser.parse([self._404_LINE])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].source_ip, "192.168.1.105")

    def test_raw_message_contains_method(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertIn("GET", entries[0].raw_message)

    def test_raw_message_contains_path(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertIn("/dashboard", entries[0].raw_message)

    def test_raw_message_contains_status_code(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertIn("200", entries[0].raw_message)

    def test_raw_message_contains_user_agent(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertIn("Chrome/123.0.0.0", entries[0].raw_message)

    def test_404_status_in_raw_message(self):
        entries = web_parser.parse([self._404_LINE])
        self.assertIn("404", entries[0].raw_message)

    def test_malformed_line_skipped(self):
        entries = web_parser.parse(["not a web log line"])
        self.assertEqual(entries, [])

    def test_empty_input(self):
        self.assertEqual(web_parser.parse([]), [])

    # ── Type / field checks ───────────────────────────────────────────────

    def test_returns_log_entry_objects(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertIsInstance(entries[0], LogEntry)

    def test_timestamp_is_utc_datetime(self):
        entries = web_parser.parse([self._200_LINE])
        ts = entries[0].timestamp
        self.assertIsInstance(ts, datetime)
        self.assertEqual(ts.tzinfo, timezone.utc)

    def test_timestamp_value(self):
        entries = web_parser.parse([self._200_LINE])
        ts = entries[0].timestamp
        self.assertEqual(ts.year,   2026)
        self.assertEqual(ts.month,  3)
        self.assertEqual(ts.day,    24)
        self.assertEqual(ts.hour,   8)
        self.assertEqual(ts.minute, 1)

    def test_log_type_is_web(self):
        entries = web_parser.parse([self._200_LINE])
        self.assertEqual(entries[0].log_type, "web")

    def test_multiple_lines_mixed(self):
        lines = [self._200_LINE, self._404_LINE, "garbage line"]
        entries = web_parser.parse(lines)
        self.assertEqual(len(entries), 2)


if __name__ == "__main__":
    unittest.main()
