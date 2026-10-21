import os
import unittest

from runtime_monitor import RuntimeMonitor


class RuntimeMonitorTests(unittest.TestCase):
    def test_reports_current_process_metrics(self):
        snapshot = RuntimeMonitor(os.getpid()).snapshot()
        self.assertEqual(snapshot["pid"], os.getpid())
        self.assertGreaterEqual(snapshot["rss_bytes"], 0)
        self.assertIsInstance(snapshot["open_files"], list)

    def test_rejects_invalid_pid(self):
        with self.assertRaises((ValueError, TypeError)):
            RuntimeMonitor("not-a-pid")


if __name__ == "__main__":
    unittest.main()
