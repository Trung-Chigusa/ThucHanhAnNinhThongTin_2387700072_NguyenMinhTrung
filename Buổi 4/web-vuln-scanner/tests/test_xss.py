import html
import unittest
from unittest.mock import Mock

from scanners.target_scope import LocalTarget
from scanners.scanner_service import create_local_http_client
from scanners.xss_scanner import scan_xss


class XSSScannerTests(unittest.TestCase):
    def setUp(self):
        self.target = LocalTarget(
            "http://127.0.0.1:5001/search?keep=1", "127.0.0.1", 5001, "/search", "keep=1"
        )

    def test_xss_reports_raw_marker_reflection(self):
        http = Mock()
        http.get.side_effect = lambda url, params, **kwargs: Mock(
            text=f"<p>{params['q']}</p>", status_code=200
        )

        findings = scan_xss(self.target, http=http)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "XSS")
        self.assertEqual(findings[0].confidence, "candidate")
        http.get.assert_called_once()
        self.assertIn("keep=1", http.get.call_args.args[0])

    def test_xss_ignores_html_encoded_marker(self):
        http = Mock()
        http.get.side_effect = lambda url, params, **kwargs: Mock(
            text=html.escape(params["q"]), status_code=200
        )

        self.assertEqual(scan_xss(self.target, http=http), [])

    def test_xss_does_not_follow_redirects(self):
        http = Mock()
        http.get.return_value = Mock(text="", status_code=302)

        self.assertEqual(scan_xss(self.target, http=http), [])
        self.assertFalse(http.get.call_args.kwargs["allow_redirects"])
        self.assertEqual(http.get.call_count, 1)

    def test_xss_preserves_existing_query_parameters(self):
        http = Mock()
        http.get.return_value = Mock(text="", status_code=200)

        scan_xss(self.target, http=http)

        self.assertIn("keep=1", http.get.call_args.args[0])
        self.assertIn("q", http.get.call_args.kwargs["params"])

    def test_local_http_client_ignores_proxy_environment(self):
        client = create_local_http_client()
        try:
            self.assertFalse(client.trust_env)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
