import socket
import threading
import unittest
from concurrent.futures import Future
from ipaddress import ip_address
from unittest.mock import patch

from config import load_settings
from modules.banner_grabber import grab_banner
from modules.port_scanner import ScanError, scan_ports
from modules.rate_limiter import ProbeScheduler


class FakeSocket:
    def __init__(self, *, connect_action=None, recv_action=b"", recvfrom_action=b"reply"):
        self.connect_action = connect_action
        self.recv_action = recv_action
        self.recvfrom_action = recvfrom_action
        self.timeouts = []
        self.sent = []
        self.recv_sizes = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        if isinstance(self.connect_action, BaseException):
            raise self.connect_action

    def sendto(self, payload, address):
        self.sent.append(payload)
        return len(payload)

    def recv(self, size):
        self.recv_sizes.append(size)
        if isinstance(self.recv_action, BaseException):
            raise self.recv_action
        return self.recv_action[:size]

    def recvfrom(self, size):
        if isinstance(self.recvfrom_action, BaseException):
            raise self.recvfrom_action
        return self.recvfrom_action[:size], ("127.0.0.1", 9999)

    def close(self):
        self.closed = True


class ScannerTests(unittest.TestCase):
    def settings(self, **values):
        return load_settings(environ=values)

    def scheduler(self, settings):
        return ProbeScheduler(settings.rate_per_second, settings.max_concurrency)

    def test_tcp_connect_states(self):
        settings = self.settings(NETRECON_MAX_CONCURRENCY="1")
        actions = [None, None, ConnectionRefusedError(), socket.timeout()]
        sockets = []

        def make_socket(*_args):
            fake = FakeSocket(connect_action=actions[len(sockets)])
            sockets.append(fake)
            return fake

        with patch("modules.port_scanner.socket.socket", side_effect=make_socket):
            results = scan_ports("127.0.0.1", (80, 81, 82), protocols=("tcp",), settings=settings)

        self.assertEqual([result.state for result in results], ["open", "closed", "filtered"])
        self.assertTrue(all(fake.closed for fake in sockets))

    def test_udp_refusal_and_silence_states(self):
        settings = self.settings(NETRECON_MAX_CONCURRENCY="1")
        sockets = []

        def make_socket(*_args):
            action = ConnectionRefusedError() if not sockets else socket.timeout()
            fake = FakeSocket(recvfrom_action=action)
            sockets.append(fake)
            return fake

        with patch("modules.port_scanner.socket.socket", side_effect=make_socket):
            results = scan_ports("127.0.0.1", (53, 54), protocols=("udp",), settings=settings)

        self.assertEqual([result.state for result in results], ["closed", "open|filtered"])
        self.assertEqual([fake.sent for fake in sockets], [[b""], [b""]])

    def test_rejected_scope_creates_no_socket(self):
        settings = self.settings()
        with patch("modules.port_scanner.socket.socket") as factory:
            with self.assertRaises(ValueError):
                scan_ports("8.8.8.8", (80,), protocols=("tcp",), settings=settings)
        factory.assert_not_called()

    def test_each_probe_uses_configured_timeout(self):
        settings = self.settings(NETRECON_TIMEOUT_SECONDS="0.7", NETRECON_MAX_CONCURRENCY="1")
        sockets = []

        def make_socket(*_args):
            fake = FakeSocket()
            sockets.append(fake)
            return fake

        with patch("modules.port_scanner.socket.socket", side_effect=make_socket):
            scan_ports("127.0.0.1", (80,), protocols=("tcp",), settings=settings)

        self.assertGreaterEqual(len(sockets), 2)
        self.assertTrue(all(fake.timeouts == [0.7] for fake in sockets))

    def test_banner_read_sends_nothing_and_caps_bytes(self):
        settings = self.settings()
        scheduler = self.scheduler(settings)
        fake = FakeSocket(recv_action=b"A" * 700)
        with patch("modules.banner_grabber.socket.socket", return_value=fake):
            banner = grab_banner(ip_address("127.0.0.1"), 80, scheduler=scheduler, timeout_seconds=1.0)

        self.assertEqual(banner, "A" * 512)
        self.assertEqual(fake.recv_sizes, [512])
        self.assertEqual(fake.sent, [])

    def test_control_characters_are_removed(self):
        settings = self.settings()
        fake = FakeSocket(recv_action=b"Hello\x00\x01World\r\n")
        with patch("modules.banner_grabber.socket.socket", return_value=fake):
            banner = grab_banner(ip_address("127.0.0.1"), 80, scheduler=self.scheduler(settings), timeout_seconds=1.0)
        self.assertEqual(banner, "HelloWorld")

    def test_results_are_sorted(self):
        settings = self.settings(NETRECON_MAX_CONCURRENCY="1")

        def make_socket(_family, kind):
            if kind == socket.SOCK_STREAM:
                return FakeSocket(connect_action=ConnectionRefusedError())
            return FakeSocket(recvfrom_action=socket.timeout())

        with patch("modules.port_scanner.socket.socket", side_effect=make_socket):
            results = scan_ports(
                "127.0.0.1", (81, 80), protocols=("udp", "tcp"), settings=settings
            )

        self.assertEqual(
            [(result.protocol, result.port) for result in results],
            [("tcp", 80), ("tcp", 81), ("udp", 80), ("udp", 81)],
        )

    def test_rejects_more_than_128_ports(self):
        settings = self.settings()
        with patch("modules.port_scanner.socket.socket") as factory:
            with self.assertRaises(ValueError):
                scan_ports("127.0.0.1", tuple(range(1, 130)), protocols=("tcp",), settings=settings)
        factory.assert_not_called()

    def test_unexpected_socket_error_stops_scan_without_exposing_details(self):
        settings = self.settings(NETRECON_MAX_CONCURRENCY="1")
        with patch("modules.port_scanner.socket.socket", side_effect=OSError("sensitive socket detail")) as factory:
            with self.assertRaises(ScanError) as caught:
                scan_ports("127.0.0.1", (80,), protocols=("tcp",), settings=settings)
        self.assertNotIn("sensitive socket detail", str(caught.exception))
        factory.assert_called_once()

    def test_keyboard_interrupt_cancels_pending_probes(self):
        settings = self.settings(NETRECON_MAX_CONCURRENCY="1")
        futures = []

        class FakeExecutor:
            def __init__(self, max_workers):
                self.max_workers = max_workers
                self.shutdown_args = None

            def submit(self, function, *args):
                future = Future()
                future.cancel = lambda: setattr(future, "was_cancelled", True) or True
                future.was_cancelled = False
                futures.append(future)
                return future

            def shutdown(self, **kwargs):
                self.shutdown_args = kwargs

        with patch("modules.port_scanner.ThreadPoolExecutor", FakeExecutor), patch(
            "modules.port_scanner.as_completed", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(ScanError):
                scan_ports("127.0.0.1", (80, 81, 82), protocols=("tcp",), settings=settings)

        self.assertEqual(len(futures), 3)
        self.assertTrue(all(future.was_cancelled for future in futures))


if __name__ == "__main__":
    unittest.main()
