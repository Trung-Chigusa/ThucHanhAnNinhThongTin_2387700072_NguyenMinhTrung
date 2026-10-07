from __future__ import annotations

import queue
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography import x509

from client import create_client_tls_context, run_client
from helpers import TestPeer, create_test_credentials
from securechat.crypto import decrypt_message, derive_pairwise_key, encrypt_message, verify_key_announcement
from server import SecureChatServer


class SecureChatClientIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_directory = tempfile.TemporaryDirectory(prefix="securechat-client-")
        cls.credentials = create_test_credentials(Path(cls.temp_directory.name))

    @classmethod
    def tearDownClass(cls):
        cls.temp_directory.cleanup()

    def setUp(self):
        credentials = self.credentials
        self.server = SecureChatServer(
            str(credentials.server_certificate),
            str(credentials.server_key),
            str(credentials.ca_certificate),
            host="127.0.0.1",
            port=0,
        )
        self.port = self.server.start()
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        self.server.stop()
        self.server_thread.join(timeout=2)
        self.assertFalse(self.server_thread.is_alive())

    def test_client_validates_tls_and_exchanges_end_to_end_messages(self):
        alice_cert, alice_key = self.credentials.clients["alice"]
        context = create_client_tls_context(
            str(self.credentials.ca_certificate), str(alice_cert), str(alice_key)
        )
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

        bob_cert, bob_key = self.credentials.clients["bob"]
        bob = TestPeer.connect(
            username="bob",
            host="127.0.0.1",
            port=self.port,
            room="general",
            ca_file=self.credentials.ca_certificate,
            certificate_file=bob_cert,
            key_file=bob_key,
        )
        inputs: queue.Queue[str] = queue.Queue()
        outputs: list[str] = []
        client_errors: list[BaseException] = []

        def input_fn(_prompt: str = "") -> str:
            return inputs.get(timeout=6)

        def run_alice() -> None:
            try:
                run_client(
                    "127.0.0.1",
                    self.port,
                    "general",
                    str(alice_cert),
                    str(alice_key),
                    str(self.credentials.ca_certificate),
                    input_fn=input_fn,
                    output_fn=outputs.append,
                )
            except BaseException as exc:
                client_errors.append(exc)

        alice_thread = threading.Thread(target=run_alice, daemon=True)
        alice_thread.start()
        try:
            alice_identity = verify_key_announcement(
                bob.receive_type("peer_joined")["peer"],
                x509.load_pem_x509_certificate(self.credentials.ca_certificate.read_bytes()),
                "general",
            )
            self.assertEqual(alice_identity.username, "alice")
            deadline = time.monotonic() + 2
            while "Peers in this room: bob" not in outputs and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn("Peers in this room: bob", outputs)
            pairwise_key = derive_pairwise_key(
                bob.private_key,
                alice_identity.public_key,
                "general",
                "bob",
                "alice",
                bob.public_key,
            )
            incoming_text = "hello from Bob"
            bob.send(
                {
                    "type": "chat",
                    "sender": "bob",
                    "room": "general",
                    "recipient": "alice",
                    "envelope": encrypt_message(
                        pairwise_key,
                        incoming_text,
                        room="general",
                        sender="bob",
                        recipient="alice",
                    ),
                }
            )
            deadline = time.monotonic() + 3
            while incoming_text not in "\n".join(outputs) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn(incoming_text, "\n".join(outputs))

            outgoing_text = "hello from Alice"
            inputs.put(f"@bob {outgoing_text}")
            delivered = bob.receive_type("chat")
            self.assertEqual(
                decrypt_message(
                    pairwise_key,
                    delivered["envelope"],
                    room="general",
                    sender="alice",
                    recipient="bob",
                ),
                outgoing_text,
            )
            inputs.put("exit")
            alice_thread.join(timeout=3)
            self.assertFalse(alice_thread.is_alive())
            self.assertEqual(client_errors, [])
        finally:
            bob.close()
            inputs.put("exit")
            alice_thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
