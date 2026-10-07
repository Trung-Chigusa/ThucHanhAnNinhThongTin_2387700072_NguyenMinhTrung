import contextlib
import io
import socket
import threading
import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import Mock, patch

from config import load_settings
from models import NeighborEntry, ScanResult
from modules.port_scanner import scan_ports


class CliTests(unittest.TestCase):
    def invoke(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = __import__("cli").main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_scan_requires_one_target(self):
        with patch("cli.scan_ports") as scanner, patch("cli.configure_logging", return_value=Mock()):
            code, _out, err = self.invoke(["scan"])
        self.assertNotEqual(code, 0)
        self.assertIn("--target", err)
        scanner.assert_not_called()

    def test_scan_parses_ports_and_protocol(self):
        results = (
            ScanResult(port=80, protocol="tcp", state="closed"),
            ScanResult(port=80, protocol="udp", state="open|filtered"),
        )
        with tempfile.TemporaryDirectory() as temp, patch("cli.configure_logging", return_value=Mock()), patch(
            "cli.scan_ports", return_value=results
        ) as scanner, patch("cli.REPORTS_DIR", Path(temp) / "reports"), patch(
            "cli.write_report", return_value=Path(temp) / "reports" / "report.json"
        ):
            code, out, _err = self.invoke(
                ["scan", "--target", "127.0.0.1", "--ports", "80,443", "--protocol", "both"]
            )
        self.assertEqual(code, 0)
        self.assertIn("tcp", out)
        self.assertIn("udp", out)
        args = scanner.call_args
        self.assertEqual(args.args[:2], ("127.0.0.1", (80, 443)))
        self.assertEqual(args.kwargs["protocols"], ("tcp", "udp"))

    def test_out_of_scope_target_never_calls_scanner(self):
        with patch("cli.configure_logging", return_value=Mock()), patch("cli.scan_ports") as scanner:
            code, _out, err = self.invoke(["scan", "--target", "8.8.8.8", "--ports", "80"])
        self.assertNotEqual(code, 0)
        self.assertIn("Invalid", err)
        scanner.assert_not_called()

    def test_scan_writes_local_json_report(self):
        result = ScanResult(port=80, protocol="tcp", state="closed")
        with tempfile.TemporaryDirectory() as temp, patch("cli.configure_logging", return_value=Mock()), patch(
            "cli.scan_ports", return_value=(result,)
        ), patch("cli.REPORTS_DIR", Path(temp) / "reports"):
            code, out, _err = self.invoke(["scan", "--target", "127.0.0.1", "--ports", "80"])
            files = list((Path(temp) / "reports").glob("*.json"))
        self.assertEqual(code, 0)
        self.assertEqual(len(files), 1)
        self.assertIn("reports/", out.lower())
        self.assertIn(files[0].name, out)

    def test_scan_reads_project_dotenv_file(self):
        settings = load_settings()
        with tempfile.TemporaryDirectory() as temp, patch("cli.configure_logging", return_value=Mock()), patch(
            "cli.load_settings", return_value=settings
        ) as loader, patch("cli.scan_ports", return_value=()), patch(
            "cli.BASE_DIR", Path(temp)
        ), patch("cli.REPORTS_DIR", Path(temp) / "reports"), patch(
            "cli.write_report", return_value=Path(temp) / "reports" / "report.json"
        ):
            code, _out, _err = self.invoke(["scan", "--target", "127.0.0.1", "--ports", "80"])
        self.assertEqual(code, 0)
        loader.assert_called_once_with(env_file=Path(temp) / ".env")
    def test_neighbors_uses_cache_only(self):
        entries = (NeighborEntry("127.0.0.1", ip_address("127.0.0.2"), "aa-bb-cc-dd-ee-ff", "dynamic"),)
        with patch("cli.configure_logging", return_value=Mock()), patch(
            "cli.get_neighbor_cache", return_value=entries
        ) as cache, patch("cli.scan_ports") as scanner:
            code, out, _err = self.invoke(["neighbors"])
        self.assertEqual(code, 0)
        self.assertIn("127.0.0.2", out)
        cache.assert_called_once_with()
        scanner.assert_not_called()

    def test_invalid_input_returns_nonzero(self):
        with patch("cli.configure_logging", return_value=Mock()), patch("cli.scan_ports") as scanner:
            code, _out, err = self.invoke(
                ["scan", "--target", "127.0.0.1", "--ports", "80,,443"]
            )
        self.assertNotEqual(code, 0)
        self.assertIn("Invalid", err)
        scanner.assert_not_called()

    def test_loopback_listener_is_reported_open(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(4)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = listener.getsockname()[1]

        def serve_greetings():
            for _ in range(2):
                try:
                    conn, _address = listener.accept()
                except socket.timeout:
                    break
                with conn:
                    try:
                        conn.sendall(b"loopback-test\n")
                    except OSError:
                        pass
            listener.close()

        server = threading.Thread(target=serve_greetings, daemon=True)
        server.start()
        try:
            results = scan_ports(
                "127.0.0.1", (port,), protocols=("tcp",), settings=load_settings()
            )
        finally:
            listener.close()
            server.join(timeout=5)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].state, "open")


if __name__ == "__main__":
    unittest.main()
