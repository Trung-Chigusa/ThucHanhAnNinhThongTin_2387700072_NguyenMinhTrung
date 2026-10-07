import base64
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from securechat.crypto import (
    CryptoError,
    create_key_announcement,
    decrypt_message,
    derive_pairwise_key,
    encrypt_message,
    verify_key_announcement,
)


def raw_public_key(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def make_ca_and_client(*, common_name="alice", client_auth=True, expired=False):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    end_date = now - timedelta(days=1) if expired else now + timedelta(days=7)
    client_builder = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(end_date)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH if client_auth else ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
    )
    client_cert = client_builder.sign(ca_key, hashes.SHA256())
    return ca_key, ca_cert, client_key, client_cert


class CryptoTests(unittest.TestCase):
    def test_pairwise_key_agreement_matches_for_both_peers(self):
        alice_private = x25519.X25519PrivateKey.generate()
        bob_private = x25519.X25519PrivateKey.generate()
        alice_public = raw_public_key(alice_private.public_key())
        bob_public = raw_public_key(bob_private.public_key())

        alice_key = derive_pairwise_key(
            alice_private, bob_public, "general", "alice", "bob", alice_public
        )
        bob_key = derive_pairwise_key(
            bob_private, alice_public, "general", "bob", "alice", bob_public
        )

        self.assertEqual(alice_key, bob_key)
        self.assertEqual(len(alice_key), 32)

    def test_aes_gcm_round_trip_binds_room_sender_and_recipient(self):
        key = bytes(range(32))
        envelope = encrypt_message(key, "xin chào", room="general", sender="alice", recipient="bob")

        self.assertEqual(
            decrypt_message(key, envelope, room="general", sender="alice", recipient="bob"),
            "xin chào",
        )
        with self.assertRaises(CryptoError):
            decrypt_message(key, envelope, room="other", sender="alice", recipient="bob")
        with self.assertRaises(CryptoError):
            decrypt_message(key, envelope, room="general", sender="alice", recipient="carol")

    def test_aes_gcm_rejects_tampered_ciphertext_and_wrong_key(self):
        key = bytes(range(32))
        envelope = encrypt_message(key, "secret", room="general", sender="alice", recipient="bob")
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
        ciphertext[-1] ^= 1
        tampered = {**envelope, "ciphertext": base64.b64encode(ciphertext).decode("ascii")}

        with self.assertRaises(CryptoError):
            decrypt_message(key, tampered, room="general", sender="alice", recipient="bob")
        with self.assertRaises(CryptoError):
            decrypt_message(bytes(reversed(key)), envelope, room="general", sender="alice", recipient="bob")

    def test_signed_announcement_is_verified_against_ca_and_room(self):
        _, ca_cert, client_key, client_cert = make_ca_and_client()
        ephemeral = x25519.X25519PrivateKey.generate()
        announcement = create_key_announcement(
            "alice",
            "general",
            client_key,
            client_cert.public_bytes(serialization.Encoding.DER),
            raw_public_key(ephemeral.public_key()),
        )

        peer = verify_key_announcement(announcement, ca_cert, "general")
        self.assertEqual(peer.username, "alice")
        self.assertEqual(peer.room, "general")
        self.assertEqual(peer.public_key, raw_public_key(ephemeral.public_key()))
        with self.assertRaises(CryptoError):
            verify_key_announcement(announcement, ca_cert, "private")

    def test_announcement_rejects_wrong_ca_modified_key_and_identity_mismatch(self):
        _, ca_cert, client_key, client_cert = make_ca_and_client()
        _, other_ca_cert, _, _ = make_ca_and_client(common_name="other")
        ephemeral = x25519.X25519PrivateKey.generate()
        announcement = create_key_announcement(
            "alice",
            "general",
            client_key,
            client_cert.public_bytes(serialization.Encoding.DER),
            raw_public_key(ephemeral.public_key()),
        )

        with self.assertRaises(CryptoError):
            verify_key_announcement(announcement, other_ca_cert, "general")
        altered_key = {**announcement, "public_key": base64.b64encode(b"not-the-signed-key").decode("ascii")}
        with self.assertRaises(CryptoError):
            verify_key_announcement(altered_key, ca_cert, "general")
        altered_identity = {**announcement, "username": "bob"}
        with self.assertRaises(CryptoError):
            verify_key_announcement(altered_identity, ca_cert, "general")

    def test_announcement_rejects_expired_certificate_and_wrong_eku(self):
        for kwargs in ({"expired": True}, {"client_auth": False}):
            with self.subTest(kwargs=kwargs):
                _, ca_cert, client_key, client_cert = make_ca_and_client(**kwargs)
                ephemeral = x25519.X25519PrivateKey.generate()
                announcement = create_key_announcement(
                    "alice",
                    "general",
                    client_key,
                    client_cert.public_bytes(serialization.Encoding.DER),
                    raw_public_key(ephemeral.public_key()),
                )
                with self.assertRaises(CryptoError):
                    verify_key_announcement(announcement, ca_cert, "general")


if __name__ == "__main__":
    unittest.main()
