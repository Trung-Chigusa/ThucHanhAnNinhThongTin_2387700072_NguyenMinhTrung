from __future__ import annotations

import base64
import json
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from helpers import TestPeer, connect_without_trusted_certificate, create_test_credentials
from securechat.crypto import (
    CryptoError,
    create_key_announcement,
    decrypt_message,
    derive_pairwise_key,
    encrypt_message,
)
from server import SecureChatServer


class FailingSocket:
    def sendall(self, _data):
        raise OSError("simulated client disconnect during welcome")

    def shutdown(self, _how):
        pass

    def close(self):
        pass


class SecureChatServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_directory = tempfile.TemporaryDirectory(prefix="securechat-integration-")
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
        self.peers: list[TestPeer] = []

    def tearDown(self):
        for peer in self.peers:
            peer.close()
        self.server.stop()
        self.server_thread.join(timeout=2)
        self.assertFalse(self.server_thread.is_alive())

    def connect_peer(self, username: str, room: str) -> TestPeer:
        certificate, key = self.credentials.clients[username]
        try:
            peer = TestPeer.connect(
                username=username,
                host="127.0.0.1",
                port=self.port,
                room=room,
                ca_file=self.credentials.ca_certificate,
                certificate_file=certificate,
                key_file=key,
            )
        except OSError as exc:
            self.fail(f"trusted client {username} failed to connect: {exc}")
        self.peers.append(peer)
        return peer

    def test_trusted_clients_join_and_ciphertext_reaches_only_named_peer(self):
        alice = self.connect_peer("alice", "general")
        bob = self.connect_peer("bob", "general")
        carol = self.connect_peer("carol", "general")

        alice_key = derive_pairwise_key(
            alice.private_key,
            bob.public_key,
            "general",
            "alice",
            "bob",
            alice.public_key,
        )
        plaintext = "this plaintext stays on the clients"
        envelope = encrypt_message(
            alice_key,
            plaintext,
            room="general",
            sender="alice",
            recipient="bob",
        )
        alice.send(
            {
                "type": "chat",
                "sender": "alice",
                "room": "general",
                "recipient": "bob",
                "envelope": envelope,
            }
        )

        delivered = bob.receive_type("chat")
        self.assertEqual(delivered["sender"], "alice")
        self.assertEqual(delivered["recipient"], "bob")
        self.assertEqual(delivered["room"], "general")
        self.assertEqual(
            decrypt_message(
                alice_key,
                delivered["envelope"],
                room="general",
                sender="alice",
                recipient="bob",
            ),
            plaintext,
        )
        self.assertNotIn(plaintext, json.dumps(delivered))

        carol_key = derive_pairwise_key(
            carol.private_key,
            alice.public_key,
            "general",
            "carol",
            "alice",
            carol.public_key,
        )
        with self.assertRaises(CryptoError):
            decrypt_message(
                carol_key,
                delivered["envelope"],
                room="general",
                sender="alice",
                recipient="bob",
            )
        with self.assertRaises(TimeoutError):
            carol.receive_type("chat", timeout=0.2)

    def test_server_rejects_cross_room_recipient(self):
        alice = self.connect_peer("alice", "general")
        bob = self.connect_peer("bob", "private")
        envelope = encrypt_message(
            bytes(32), "room check", room="general", sender="alice", recipient="bob"
        )

        alice.send(
            {
                "type": "chat",
                "sender": "alice",
                "room": "general",
                "recipient": "bob",
                "envelope": envelope,
            }
        )

        error = alice.receive_type("error")
        self.assertEqual(error.get("code"), "recipient_unavailable")
        with self.assertRaises(TimeoutError):
            bob.receive_type("chat", timeout=0.2)

    def test_missing_client_certificate_is_rejected(self):
        connect_without_trusted_certificate(
            host="127.0.0.1",
            port=self.port,
            ca_file=self.credentials.ca_certificate,
            client=None,
        )

    def test_untrusted_client_certificate_is_rejected(self):
        connect_without_trusted_certificate(
            host="127.0.0.1",
            port=self.port,
            ca_file=self.credentials.ca_certificate,
            client=self.credentials.untrusted_client,
        )

    def test_duplicate_active_certificate_identity_is_rejected(self):
        alice = self.connect_peer("alice", "general")
        certificate, key = self.credentials.clients["alice"]
        with self.assertRaises((OSError, TimeoutError, EOFError)):
            TestPeer.connect(
                username="alice",
                host="127.0.0.1",
                port=self.port,
                room="general",
                ca_file=self.credentials.ca_certificate,
                certificate_file=certificate,
                key_file=key,
            )

    def test_disconnect_removes_identity_and_notifies_remaining_room_members(self):
        alice = self.connect_peer("alice", "general")
        bob = self.connect_peer("bob", "general")
        bob.close()

        left = alice.receive_type("peer_left")
        self.assertEqual(left.get("username"), "bob")

        bob_cert, bob_key = self.credentials.clients["bob"]
        reconnected = TestPeer.connect(
            username="bob",
            host="127.0.0.1",
            port=self.port,
            room="general",
            ca_file=self.credentials.ca_certificate,
            certificate_file=bob_cert,
            key_file=bob_key,
        )
        self.peers.append(reconnected)
        self.assertEqual(reconnected.welcome["username"], "bob")

    def test_welcome_is_the_first_frame_during_concurrent_joins(self):
        welcome_blocked = threading.Event()
        release_welcome = threading.Event()
        send_types: list[str] = []
        send_types_lock = threading.Lock()
        original_send = self.server._connections.send

        def controlled_send(session, payload):
            if session.username == "alice" and payload.get("type") == "welcome":
                welcome_blocked.set()
                if not release_welcome.wait(timeout=3):
                    raise TimeoutError("test did not release Alice's welcome")
            if session.username == "alice":
                with send_types_lock:
                    send_types.append(str(payload.get("type")))
            original_send(session, payload)

        self.server._connections.send = controlled_send
        alice_results: list[TestPeer] = []
        alice_errors: list[BaseException] = []

        def connect_alice():
            try:
                certificate, key = self.credentials.clients["alice"]
                alice_results.append(
                    TestPeer.connect(
                        username="alice",
                        host="127.0.0.1",
                        port=self.port,
                        room="general",
                        ca_file=self.credentials.ca_certificate,
                        certificate_file=certificate,
                        key_file=key,
                    )
                )
            except BaseException as exc:
                alice_errors.append(exc)

        alice_thread = threading.Thread(target=connect_alice)
        alice_thread.start()
        self.assertTrue(welcome_blocked.wait(timeout=3))
        try:
            bob = self.connect_peer("bob", "general")
        finally:
            release_welcome.set()
        alice_thread.join(timeout=3)

        self.assertFalse(alice_thread.is_alive())
        self.assertEqual(alice_errors, [])
        self.assertEqual(len(alice_results), 1)
        alice = alice_results[0]
        self.peers.append(alice)
        self.assertEqual(alice.welcome.get("type"), "welcome")
        self.assertTrue(send_types)
        self.assertEqual(send_types[0], "welcome")
        self.assertEqual(alice.receive_type("peer_joined").get("peer", {}).get("username"), "bob")
        self.assertEqual(bob.receive_type("peer_joined").get("peer", {}).get("username"), "alice")

    def test_failed_active_send_and_delayed_cleanup_preserve_reconnected_session(self):
        alice = self.connect_peer("alice", "general")
        old_bob = self.connect_peer("bob", "general")
        old_session = self.server._connections.get("bob")
        self.assertIsNotNone(old_session)

        delayed_cleanup_seen = threading.Event()
        cleanup_calls = 0
        original_disconnect = self.server._disconnect

        def tracked_disconnect(session):
            nonlocal cleanup_calls
            if session is old_session:
                cleanup_calls += 1
                if cleanup_calls >= 2:
                    delayed_cleanup_seen.set()
            original_disconnect(session)

        self.server._disconnect = tracked_disconnect
        old_session.socket = FailingSocket()
        self.server._safe_send(old_session, {"type": "test_failure"})
        self.assertIsNone(self.server._connections.get("bob"))
        self.assertNotIn("bob", self.server._rooms.members("general"))
        left = alice.receive_type("peer_left")
        self.assertEqual(left.get("public_key"), base64.b64encode(old_session.public_key).decode("ascii"))

        bob_certificate, bob_key = self.credentials.clients["bob"]
        new_bob = TestPeer.connect(
            username="bob",
            host="127.0.0.1",
            port=self.port,
            room="general",
            ca_file=self.credentials.ca_certificate,
            certificate_file=bob_certificate,
            key_file=bob_key,
        )
        self.peers.append(new_bob)
        new_session = self.server._connections.get("bob")
        self.assertIsNotNone(new_session)
        old_bob.close()
        self.assertTrue(delayed_cleanup_seen.wait(timeout=3))
        self.assertIs(self.server._connections.get("bob"), new_session)

    def test_failed_welcome_send_removes_new_client_from_all_server_state(self):
        certificate_file, key_file = self.credentials.clients["alice"]
        certificate = x509.load_pem_x509_certificate(certificate_file.read_bytes())
        signing_key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        ephemeral_key = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        announcement = create_key_announcement(
            "alice",
            "general",
            signing_key,
            certificate.public_bytes(serialization.Encoding.DER),
            ephemeral_public,
        )

        with self.assertRaises(OSError):
            self.server._register_client(
                FailingSocket(),
                certificate.public_bytes(serialization.Encoding.DER),
                announcement,
            )

        self.assertIsNone(self.server._connections.get("alice"))
        self.assertEqual(self.server._rooms.members("general"), [])
        self.assertNotIn("alice", self.server._announcements)


if __name__ == "__main__":
    unittest.main()
