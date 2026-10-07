import socket
import unittest
from unittest.mock import patch

from config import load_settings
from modules.scope import ScopeError, validate_target


class ScopeTests(unittest.TestCase):
    def settings(self, allowlist="10.0.0.0/8,fc00::/7", blocklist=""):
        return load_settings(
            environ={
                "NETRECON_ALLOWLIST": allowlist,
                "NETRECON_BLOCKLIST": blocklist,
            }
        )

    def test_accepts_loopback_and_allowlisted_private_hosts(self):
        settings = self.settings("127.0.0.1/32,::1/128,10.0.0.0/8,fc00::/7")

        self.assertEqual(str(validate_target("127.0.0.1", settings)), "127.0.0.1")
        self.assertEqual(str(validate_target("::1", settings)), "::1")
        self.assertEqual(str(validate_target("10.23.4.5", settings)), "10.23.4.5")
        self.assertEqual(str(validate_target("fd12::5", settings)), "fd12::5")

    def test_rejects_public_reserved_hostname_url_and_cidr_inputs(self):
        settings = self.settings()
        invalid = (
            "8.8.8.8",
            "169.254.1.3",
            "224.0.0.1",
            "0.0.0.0",
            "localhost",
            "http://10.1.2.3",
            "10.1.0.0/24",
            "::1%lo",
        )

        for target in invalid:
            with self.subTest(target=target):
                with self.assertRaises(ScopeError):
                    validate_target(target, settings)

    def test_rejects_non_allowlisted_private_host_and_family_mismatch(self):
        settings = self.settings("10.0.0.0/8")

        for target in ("192.168.1.5", "fd00::5"):
            with self.subTest(target=target):
                with self.assertRaises(ScopeError):
                    validate_target(target, settings)

    def test_blocklist_overrides_allowlist(self):
        settings = self.settings("10.0.0.0/8", "10.0.0.5/32")

        with self.assertRaises(ScopeError):
            validate_target("10.0.0.5", settings)
        self.assertEqual(str(validate_target("10.0.0.6", settings)), "10.0.0.6")

    def test_scope_validation_does_not_open_socket(self):
        settings = self.settings()

        with patch.object(socket, "socket") as socket_factory:
            with self.assertRaises(ScopeError):
                validate_target("8.8.8.8", settings)

        socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
