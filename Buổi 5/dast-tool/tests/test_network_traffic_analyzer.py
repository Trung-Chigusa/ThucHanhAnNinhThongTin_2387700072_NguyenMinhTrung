import unittest
from unittest.mock import patch
from collections import namedtuple

from network_traffic_analyzer import NetworkTrafficAnalyzer


class NetworkAnalyzerTests(unittest.TestCase):
    @patch("network_traffic_analyzer.psutil.net_io_counters")
    def test_returns_aggregate_per_interface_counters(self, counters):
        stats = namedtuple("Counters", "bytes_sent bytes_recv packets_sent packets_recv errin errout dropin dropout")
        counters.return_value = {"loopback": stats(1, 2, 3, 4, 0, 0, 0, 0)}
        result = NetworkTrafficAnalyzer().get_network_stats()
        self.assertEqual(result["loopback"]["bytes_recv"], 2)
        self.assertNotIn("payload", result["loopback"])

    @patch("network_traffic_analyzer.psutil.net_io_counters", return_value=None)
    def test_handles_missing_counters(self, _):
        self.assertEqual(NetworkTrafficAnalyzer().get_network_stats(), {})


if __name__ == "__main__":
    unittest.main()
