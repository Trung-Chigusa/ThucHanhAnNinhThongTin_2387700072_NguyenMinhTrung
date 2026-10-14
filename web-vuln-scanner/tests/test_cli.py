import io
import json
import unittest
from unittest.mock import Mock

from main import main
from scanners.scanner_service import Finding, ScanReport


class CLITests(unittest.TestCase):
    def test_cli_rejects_public_target_before_scan(self):
        scanner = Mock()
        output = io.StringIO()

        status = main(["--target", "http://8.8.8.8/"], scanner=scanner, output=output)

        self.assertNotEqual(status, 0)
        scanner.assert_not_called()
        self.assertIn("error", json.loads(output.getvalue()))

    def test_cli_outputs_json_for_local_demo(self):
        report = ScanReport(
            "http://127.0.0.1:5001/search",
            "2026-10-14T00:00:00Z",
            (Finding("XSS", "query:q", "marker reflected", "candidate", "Medium", "Encode output"),),
            ("Manual review required.",),
        )
        scanner = Mock(return_value=report)
        output = io.StringIO()

        status = main(["--demo"], scanner=scanner, output=output)

        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["findings"][0]["type"], "XSS")
        self.assertEqual(scanner.call_args.kwargs["checks"], ("xss", "sql", "csrf", "ssrf"))


if __name__ == "__main__":
    unittest.main()
