import unittest
from unittest.mock import Mock

from scanners.target_scope import LocalTarget
from scanners.ssrf_tester import scan_ssrf


class SSRFTesterTests(unittest.TestCase):
    def test_ssrf_flags_local_address_parameter(self):
        target = LocalTarget(
            "http://127.0.0.1/?url=http%3A%2F%2F169.254.169.254%2Flatest",
            "127.0.0.1",
            80,
            "/",
            "url=http%3A%2F%2F169.254.169.254%2Flatest",
        )

        findings = scan_ssrf(target)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "SSRF")
        self.assertEqual(findings[0].confidence, "heuristic")

    def test_ssrf_makes_no_request(self):
        target = LocalTarget("http://127.0.0.1/?url=http://localhost", "127.0.0.1", 80, "/", "")
        http = Mock()

        scan_ssrf(target)

        http.get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
