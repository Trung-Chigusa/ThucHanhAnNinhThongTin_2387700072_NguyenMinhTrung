import unittest

from security_behavior_checker import SecurityBehaviorChecker


class BehaviorCheckerTests(unittest.TestCase):
    def test_flags_only_events_matching_rules(self):
        checker = SecurityBehaviorChecker()
        checker.record_event("file.read")
        checker.record_event("process.shell", {"source": "demo"})
        self.assertEqual([event["event"] for event in checker.suspicious_calls()], ["process.shell"])

    def test_clear_removes_recorded_events(self):
        checker = SecurityBehaviorChecker()
        checker.record_event("network.external_connect")
        checker.clear()
        self.assertEqual(checker.suspicious_calls(), [])


if __name__ == "__main__":
    unittest.main()
