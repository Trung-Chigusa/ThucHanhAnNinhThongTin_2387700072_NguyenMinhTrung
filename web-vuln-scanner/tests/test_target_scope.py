import socket
import unittest

from scanners.target_scope import TargetError, validate_local_target


def resolver_for(*addresses):
    def resolve(host, port, type=socket.SOCK_STREAM):
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET,
             type,
             0,
             "",
             (address, port, 0, 0) if ":" in address else (address, port))
            for address in addresses
        ]

    return resolve


class TargetScopeTests(unittest.TestCase):
    def test_accepts_loopback_ipv4_and_localhost(self):
        target = validate_local_target("http://127.0.0.1:5001/search?q=x")
        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 5001)
        self.assertEqual(target.path, "/search")
        self.assertEqual(target.query, "q=x")

        local = validate_local_target(
            "http://localhost:5001/search?q=x", resolver=resolver_for("127.0.0.1")
        )
        self.assertEqual(local.canonical_url, "http://127.0.0.1:5001/search?q=x")

    def test_rejects_public_ipv4_and_ipv6(self):
        for url in ("http://8.8.8.8/", "http://[2001:4860:4860::8888]/"):
            with self.subTest(url=url), self.assertRaises(TargetError):
                validate_local_target(url)

    def test_rejects_hostname_with_any_non_loopback_answer(self):
        with self.assertRaises(TargetError):
            validate_local_target(
                "http://localhost/", resolver=resolver_for("127.0.0.1", "93.184.216.34")
            )

    def test_pins_localhost_to_resolved_loopback_address(self):
        target = validate_local_target(
            "http://localhost:5000/", resolver=resolver_for("127.0.0.1", "::1")
        )
        self.assertEqual(target.canonical_url, "http://127.0.0.1:5000/")

    def test_rejects_invalid_scheme_and_url(self):
        for url in ("ftp://127.0.0.1/file", "http:///missing-host", "http://127.0.0.1:bad/"):
            with self.subTest(url=url), self.assertRaises(TargetError):
                validate_local_target(url)

    def test_rejects_credentials_and_fragments(self):
        for url in ("http://user:pass@127.0.0.1/", "http://127.0.0.1/#fragment"):
            with self.subTest(url=url), self.assertRaises(TargetError):
                validate_local_target(url)

    def test_resolution_failure_fails_closed(self):
        def fail_resolution(host, port, type=socket.SOCK_STREAM):
            raise socket.gaierror("not found")

        with self.assertRaises(TargetError):
            validate_local_target("http://localhost/", resolver=fail_resolution)


if __name__ == "__main__":
    unittest.main()
