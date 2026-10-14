import unittest
from unittest.mock import Mock

from scanners.target_scope import LocalTarget
from scanners.csrf_detector import scan_csrf


class CSRFDetectorTests(unittest.TestCase):
    def setUp(self):
        self.target = LocalTarget("http://127.0.0.1:5001/form", "127.0.0.1", 5001, "/form", "")

    def detector(self, html):
        http = Mock()
        http.get.return_value = Mock(text=html, status_code=200)
        return scan_csrf(self.target, http=http)

    def test_csrf_flags_form_without_token(self):
        findings = self.detector('<form method="post" action="/save"><input name="name"></form>')

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "CSRF")
        self.assertEqual(findings[0].confidence, "manual-review")

    def test_csrf_accepts_case_insensitive_hidden_token(self):
        findings = self.detector(
            '<form method="post"><input TYPE="HIDDEN" name="CSRF_TOKEN" value="demo"></form>'
        )

        self.assertEqual(findings, [])

    def test_csrf_handles_empty_and_malformed_html(self):
        self.assertEqual(self.detector(""), [])
        self.assertEqual(self.detector("<form><input"), [])


if __name__ == "__main__":
    unittest.main()
