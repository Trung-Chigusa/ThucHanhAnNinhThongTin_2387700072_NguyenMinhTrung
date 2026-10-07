import tempfile
import unittest
from pathlib import Path
from ipaddress import ip_network

from config import ConfigurationError, load_settings


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env_file = Path(self.temp_dir.name) / ".env"
        self.env_file.write_text("", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def load(self, environ=None):
        return load_settings(env_file=self.env_file, environ=environ or {})

    def test_defaults_allow_only_both_loopbacks(self):
        settings = self.load()

        self.assertEqual(
            settings.allowlist,
            (ip_network("127.0.0.1/32"), ip_network("::1/128")),
        )
        self.assertEqual(settings.blocklist, ())
        self.assertEqual(settings.default_ports, (22, 80, 443))
        self.assertEqual(settings.rate_per_second, 2)
        self.assertEqual(settings.timeout_seconds, 1.5)
        self.assertEqual(settings.max_concurrency, 4)

    def test_process_environment_overrides_dotenv(self):
        self.env_file.write_text(
            "NETRECON_ALLOWLIST=10.10.0.0/16\n"
            "NETRECON_RATE_PER_SECOND=4\n"
            "NETRECON_TIMEOUT_SECONDS=1.0\n"
            "NETRECON_MAX_CONCURRENCY=2\n",
            encoding="utf-8",
        )

        settings = self.load(
            {
                "NETRECON_ALLOWLIST": "192.168.1.0/24",
                "NETRECON_RATE_PER_SECOND": "8",
            }
        )

        self.assertEqual(settings.allowlist, (ip_network("192.168.1.0/24"),))
        self.assertEqual(settings.rate_per_second, 8)
        self.assertEqual(settings.timeout_seconds, 1.0)
        self.assertEqual(settings.max_concurrency, 2)

    def test_explicit_empty_allowlist_fails_closed(self):
        with self.assertRaises(ConfigurationError):
            self.load({"NETRECON_ALLOWLIST": ""})

    def test_allowlist_accepts_ipv4_and_ipv6_entries(self):
        settings = self.load(
            {"NETRECON_ALLOWLIST": "10.0.0.0/8,fc00::/7"}
        )

        self.assertEqual(
            settings.allowlist,
            (ip_network("10.0.0.0/8"), ip_network("fc00::/7")),
        )

    def test_rejects_public_and_overly_broad_allowlist_networks(self):
        for value in ("8.8.8.0/24", "0.0.0.0/0", "::/0", "2001:4860::/32"):
            with self.subTest(value=value):
                with self.assertRaises(ConfigurationError):
                    self.load({"NETRECON_ALLOWLIST": value})

    def test_rate_timeout_and_concurrency_bounds(self):
        valid = (
            {"NETRECON_RATE_PER_SECOND": "1", "NETRECON_TIMEOUT_SECONDS": "0.2", "NETRECON_MAX_CONCURRENCY": "1"},
            {"NETRECON_RATE_PER_SECOND": "10", "NETRECON_TIMEOUT_SECONDS": "3", "NETRECON_MAX_CONCURRENCY": "4"},
        )
        for environ in valid:
            with self.subTest(environ=environ):
                self.load(environ)

        invalid = (
            {"NETRECON_RATE_PER_SECOND": "0"},
            {"NETRECON_RATE_PER_SECOND": "11"},
            {"NETRECON_TIMEOUT_SECONDS": "0.19"},
            {"NETRECON_TIMEOUT_SECONDS": "3.01"},
            {"NETRECON_MAX_CONCURRENCY": "0"},
            {"NETRECON_MAX_CONCURRENCY": "5"},
        )
        for environ in invalid:
            with self.subTest(environ=environ):
                with self.assertRaises(ConfigurationError):
                    self.load(environ)


if __name__ == "__main__":
    unittest.main()
