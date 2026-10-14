import unittest
from unittest.mock import Mock

from scanners.target_scope import LocalTarget
from scanners.sql_injection_tester import scan_sql_injection


class SQLInjectionTests(unittest.TestCase):
    def test_sql_flags_only_known_patterns(self):
        target = LocalTarget(
            "http://127.0.0.1:5001/lookup?id=1%27+OR+%271%27%3D%271&name=alice",
            "127.0.0.1",
            5001,
            "/lookup",
            "id=1%27+OR+%271%27%3D%271&name=alice",
        )

        findings = scan_sql_injection(target)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "SQLi")
        self.assertEqual(findings[0].location, "query:id")
        self.assertEqual(findings[0].confidence, "heuristic")

        safe = LocalTarget("http://127.0.0.1/?q=alice", "127.0.0.1", 80, "/", "q=alice")
        self.assertEqual(scan_sql_injection(safe), [])

    def test_sql_detector_makes_no_request(self):
        target = LocalTarget(
            "http://127.0.0.1/?id=1%27+OR+1%3D1--", "127.0.0.1", 80, "/", "id=1%27+OR+1%3D1--"
        )
        http = Mock()

        scan_sql_injection(target)

        http.get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
