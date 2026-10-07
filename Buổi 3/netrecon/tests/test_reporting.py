import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network
from pathlib import Path

from config import load_settings
from models import ScanReport, ScanResult
from modules.reporting import build_report, report_json, write_report


class ReportingTests(unittest.TestCase):
    def test_report_has_utc_scope_limits_and_results(self):
        settings = load_settings(environ={"NETRECON_ALLOWLIST": "10.0.0.0/8"})
        result = ScanResult(port=80, protocol="tcp", state="open", service="http")
        created = datetime(2026, 10, 7, 1, 2, 3, tzinfo=timezone(timedelta(hours=7)))

        report = build_report("10.0.0.4", settings, (result,), created_at=created)

        self.assertEqual(report.target, "10.0.0.4")
        self.assertEqual(report.created_at_utc, "2026-10-06T18:02:03Z")
        self.assertIn("allowlisted private", report.scope_summary.lower())
        self.assertEqual(report.rate_per_second, 2)
        self.assertEqual(report.timeout_seconds, 1.5)
        self.assertEqual(report.results, (result,))
        self.assertTrue(report.limitations)

    def test_json_is_utf8_and_omits_environment_secrets(self):
        secret = "lab-secret-should-not-appear"
        settings = load_settings(
            environ={
                "NETRECON_ALLOWLIST": "10.0.0.0/8",
                "NETRECON_BLOCKLIST": "10.99.0.0/16",
                "NETRECON_PRIVATE_TOKEN": secret,
            }
        )
        report = build_report("10.1.2.3", settings, ())
        payload = report_json(report)

        decoded = payload.decode("utf-8")
        self.assertEqual(json.loads(decoded)["target"], "10.1.2.3")
        self.assertNotIn(secret, decoded)
        self.assertNotIn("10.0.0.0/8", decoded)
        self.assertNotIn("10.99.0.0/16", decoded)
        self.assertNotIn("netrecon_allowlist", decoded.lower())

    def test_filename_is_generated_under_reports_directory(self):
        settings = load_settings(environ={"NETRECON_ALLOWLIST": "fc00::/7"})
        report = build_report("fd12::5", settings, ())
        with tempfile.TemporaryDirectory() as temp:
            reports_dir = Path(temp) / "reports"
            path = write_report(report, reports_dir)
            self.assertEqual(path.parent, reports_dir.resolve())
            self.assertTrue(path.name.endswith(".json"))
            self.assertIn("fd12--5", path.name)
            self.assertTrue(path.is_file())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["target"], "fd12::5")

    def test_report_path_cannot_be_controlled_by_input(self):
        malicious = ScanReport(
            target="..\\..\\outside",
            created_at_utc="2026-10-07T00:00:00Z",
            scope_summary="loopback only",
            rate_per_second=2,
            timeout_seconds=1.5,
            results=(),
            limitations=(),
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reports_dir = root / "reports"
            with self.assertRaises(ValueError):
                write_report(malicious, reports_dir)
            self.assertEqual(list(root.rglob("*.json")), [])


if __name__ == "__main__":
    unittest.main()
