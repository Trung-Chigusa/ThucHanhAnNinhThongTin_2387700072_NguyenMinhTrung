import json
import re
import unittest
from unittest.mock import Mock, patch

from flask import Flask

from config import load_settings
from models import ScanResult
from modules.rate_limiter import ProbeScheduler
from app import create_app, run_local


_TOKEN = re.compile(r'name="_csrf_token" value="([^"]+)"')
_REPORT = re.compile(r'href="(/report/[A-Za-z0-9_-]+)"')


class WebTests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings(environ={"NETRECON_ALLOWLIST": "127.0.0.1/32"})
        self.scheduler = ProbeScheduler(2, 1)
        self.app = create_app(self.settings, scheduler=self.scheduler)
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def csrf(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        match = _TOKEN.search(response.get_data(as_text=True))
        self.assertIsNotNone(match)
        return match.group(1)

    def post_scan(self, token, **values):
        data = {"_csrf_token": token, "target": "127.0.0.1", "ports": "80", "protocol": "tcp"}
        data.update(values)
        return self.client.post("/scan", data=data)

    def test_index_displays_scope_limits_and_csrf_token(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("127.0.0.1/32", html)
        self.assertIn("2 probes/second", html)
        self.assertIn("max 4 concurrent", html)
        self.assertRegex(html, r'name="_csrf_token" value="[A-Za-z0-9_-]+"')
        self.assertNotIn("NETRECON_ALLOWLIST", html)

    def test_valid_csrf_runs_shared_scanner(self):
        results = (ScanResult(port=80, protocol="tcp", state="closed"),)
        token = self.csrf()
        with patch("app.scan_ports", return_value=results) as scanner:
            response = self.post_scan(token, ports="80,443", protocol="both")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(scanner.call_count, 1)
        self.assertEqual(scanner.call_args.args[:2], ("127.0.0.1", (80, 443)))
        self.assertEqual(scanner.call_args.kwargs["protocols"], ("tcp", "udp"))
        self.assertIs(scanner.call_args.kwargs["scheduler"], self.scheduler)

    def test_invalid_csrf_returns_400_without_scanning(self):
        self.csrf()
        with patch("app.scan_ports") as scanner:
            response = self.post_scan("wrong-token")
        self.assertEqual(response.status_code, 400)
        scanner.assert_not_called()

    def test_scope_and_port_errors_return_400_without_scanning(self):
        token = self.csrf()
        with patch("app.scan_ports") as scanner:
            scope_response = self.post_scan(token, target="8.8.8.8")
            port_response = self.post_scan(token, ports="80,,443")
        self.assertEqual(scope_response.status_code, 400)
        self.assertEqual(port_response.status_code, 400)
        scanner.assert_not_called()

    def test_report_download_is_json(self):
        token = self.csrf()
        result = ScanResult(port=80, protocol="tcp", state="closed")
        with patch("app.scan_ports", return_value=(result,)):
            response = self.post_scan(token)
        self.assertEqual(response.status_code, 200)
        match = _REPORT.search(response.get_data(as_text=True))
        self.assertIsNotNone(match)

        download = self.client.get(match.group(1))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.mimetype, "application/json")
        self.assertEqual(json.loads(download.get_data(as_text=True))["target"], "127.0.0.1")

    def test_report_id_is_not_a_path(self):
        response = self.client.get("/report/..%2F..%2Foutside.json")
        self.assertEqual(response.status_code, 404)

    def test_report_cache_is_capped_at_twenty(self):
        token = self.csrf()
        with patch("app.scan_ports", return_value=()):
            links = []
            for _ in range(21):
                response = self.post_scan(token)
                self.assertEqual(response.status_code, 200)
                links.append(_REPORT.search(response.get_data(as_text=True)).group(1))

        self.assertEqual(self.client.get(links[0]).status_code, 404)
        self.assertEqual(self.client.get(links[-1]).status_code, 200)

    def test_run_local_uses_loopback_without_debug(self):
        with patch("app.configure_logging", return_value=Mock()), patch.object(Flask, "run") as run:
            run_local()
        run.assert_called_once_with(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    unittest.main()
