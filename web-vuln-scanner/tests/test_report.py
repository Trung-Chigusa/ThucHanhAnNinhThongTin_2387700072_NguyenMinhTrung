import unittest
import json

from scanners.scanner_service import Finding, ScanReport, scan_target
from report.report_generator import generate_report
from scanners.target_scope import LocalTarget


class ReportGeneratorTests(unittest.TestCase):
    def test_report_has_confidence_risk_and_remediation(self):
        report = ScanReport(
            target="http://127.0.0.1:5001/",
            created_at_utc="2026-10-14T00:00:00Z",
            findings=(Finding("XSS", "q", "marker reflected", "candidate", "High", "Encode output"),),
            limitations=("Candidate finding; manual verification required.",),
        )

        result = generate_report(report)

        self.assertEqual(result["findings"][0]["confidence"], "candidate")
        self.assertEqual(result["findings"][0]["risk"], "High")
        self.assertEqual(result["findings"][0]["remediation"], "Encode output")
        self.assertNotIn("headers", result)
        self.assertNotIn("cookies", result)

    def test_report_omits_target_query_values(self):
        target = LocalTarget(
            "http://127.0.0.1:5001/search?token=private-value",
            "127.0.0.1",
            5001,
            "/search",
            "token=private-value",
        )

        result = json.dumps(generate_report(scan_target(target, checks=("sql",))))

        self.assertNotIn("private-value", result)
        self.assertNotIn("token=", result)

    def test_report_omits_sensitive_target_path_segments(self):
        target = LocalTarget(
            "http://127.0.0.1:5001/reset/private-reset-token",
            "127.0.0.1",
            5001,
            "/reset/private-reset-token",
            "",
        )

        result = json.dumps(generate_report(scan_target(target, checks=("sql",))))

        self.assertNotIn("private-reset-token", result)
        self.assertIn("http://127.0.0.1:5001/", result)


if __name__ == "__main__":
    unittest.main()
