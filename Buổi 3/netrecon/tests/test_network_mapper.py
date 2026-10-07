import subprocess
import unittest
from unittest.mock import Mock, patch

from modules.network_mapper import get_neighbor_cache, parse_arp_output


ARP_SAMPLE = """\
Interface: 192.168.1.25 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.10          00-11-22-33-44-55     static

Interface: 10.0.0.4 --- 0x9
  Internet Address      Physical Address      Type
  10.0.0.1              de-ad-be-ef-00-01     dynamic
"""


class NetworkMapperTests(unittest.TestCase):
    def test_parses_windows_arp_rows(self):
        entries = parse_arp_output(ARP_SAMPLE)
        self.assertEqual(len(entries), 3)
        self.assertEqual(str(entries[0].address), "192.168.1.1")
        self.assertEqual(entries[0].interface, "192.168.1.25")
        self.assertEqual(entries[0].mac_address, "aa-bb-cc-dd-ee-ff")
        self.assertEqual(entries[0].entry_type, "dynamic")
        self.assertEqual(str(entries[2].address), "10.0.0.1")
        self.assertEqual(entries[2].interface, "10.0.0.4")

    def test_ignores_headers_malformed_and_ipv6_rows(self):
        output = """\
Interface: 127.0.0.1 --- 0x1
Internet Address      Physical Address      Type
not-an-ip             aa-bb-cc-dd-ee-ff     dynamic
fe80::1               aa-bb-cc-dd-ee-ff     dynamic
192.168.0.2           malformed             dynamic
192.168.0.3           11-22-33-44-55-66     static
"""
        entries = parse_arp_output(output)
        self.assertEqual([str(entry.address) for entry in entries], ["192.168.0.3"])

    def test_never_probes_cached_addresses(self):
        with patch("socket.socket") as factory:
            entries = parse_arp_output(ARP_SAMPLE)
        self.assertEqual(len(entries), 3)
        factory.assert_not_called()

    def test_subprocess_uses_argv_no_shell_and_timeout(self):
        completed = subprocess.CompletedProcess(["arp", "-a"], 0, stdout=ARP_SAMPLE, stderr="")
        runner = Mock(return_value=completed)
        entries = get_neighbor_cache(timeout_seconds=1.7, runner=runner)

        self.assertEqual(len(entries), 3)
        runner.assert_called_once_with(
            ["arp", "-a"], capture_output=True, text=True, timeout=1.7, check=False, shell=False
        )

    def test_missing_arp_command_returns_empty(self):
        runner = Mock(side_effect=FileNotFoundError("secret command path"))
        with self.assertLogs("netrecon", level="WARNING") as captured:
            entries = get_neighbor_cache(runner=runner)
        self.assertEqual(entries, ())
        self.assertNotIn("secret command path", " ".join(captured.output))

    def test_arp_timeout_returns_empty(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired("arp", 2, output="secret"))
        with self.assertLogs("netrecon", level="WARNING") as captured:
            entries = get_neighbor_cache(runner=runner)
        self.assertEqual(entries, ())
        self.assertNotIn("secret", " ".join(captured.output))


if __name__ == "__main__":
    unittest.main()
