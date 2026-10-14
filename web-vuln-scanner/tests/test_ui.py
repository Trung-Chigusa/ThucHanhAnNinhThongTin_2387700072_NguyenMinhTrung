import unittest
from unittest.mock import Mock

from scanners.scanner_service import Finding, ScanError, ScanReport
from ui.app import create_app


class UITests(unittest.TestCase):
    def report(self, finding=None):
        return ScanReport(
            "http://127.0.0.1:5001/search",
            "2026-10-14T00:00:00Z",
            (() if finding is None else (finding,)),
            ("Candidate result; manual review required.",),
        )

    def test_ui_home_loads(self):
        response = create_app().test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Web Vulnerability Scanner", response.data)

    def test_ui_rejects_public_target(self):
        scanner = Mock()
        response = create_app(scanner=scanner).test_client().post(
            "/scan", data={"target": "http://8.8.8.8/", "checks": "xss"}
        )
        self.assertEqual(response.status_code, 400)
        scanner.assert_not_called()
        self.assertIn(b"loopback", response.data.lower())

    def test_ui_displays_candidate_and_remediation_safely(self):
        finding = Finding("XSS", "<script>", "marker reflected", "candidate", "Medium", "Encode output")
        scanner = Mock(return_value=self.report(finding))
        response = create_app(scanner=scanner).test_client().post(
            "/scan", data={"target": "http://127.0.0.1:5001/search", "checks": ["xss"]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"candidate", response.data)
        self.assertIn(b"Encode output", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertNotIn(b"<script>", response.data)

    def test_ui_handles_scanner_error_without_traceback(self):
        scanner = Mock(side_effect=ScanError("safe scan error"))
        response = create_app(scanner=scanner).test_client().post(
            "/scan", data={"target": "http://127.0.0.1:5001/search", "checks": ["xss"]}
        )
        self.assertEqual(response.status_code, 502)
        self.assertIn(b"safe scan error", response.data)
        self.assertNotIn(b"Traceback", response.data)

    def test_ui_rejects_unknown_check(self):
        scanner = Mock()
        response = create_app(scanner=scanner).test_client().post(
            "/scan", data={"target": "http://127.0.0.1:5001/search", "checks": ["unknown"]}
        )
        self.assertEqual(response.status_code, 400)
        scanner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
