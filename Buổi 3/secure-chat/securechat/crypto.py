"""Client-side key agreement, certificate-bound identities, and E2E messages."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
_ANNOUNCEMENT_VERSION = 1
_ENVELOPE_VERSION = "1"
_NONCE_BYTES = 12


class CryptoError(ValueError):
    """Raised for invalid identities, certificates, keys, or encrypted data."""


@dataclass(frozen=True)
class PeerIdentity:
    username: str
    room: str
    public_key: bytes
    certificate_der: bytes


def _validate_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise CryptoError(f"invalid {label}")


def _announcement_body(username: str, room: str, public_key: bytes) -> bytes:
    payload = {
        "version": _ANNOUNCEMENT_VERSION,
        "username": username,
        "room": room,
        "public_key": base64.b64encode(public_key).decode("ascii"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _certificate_common_name(certificate: x509.Certificate) -> str:
    values = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(values) != 1:
        raise CryptoError("client certificate must contain exactly one common name")
    return values[0].value


def _validate_client_certificate(certificate: x509.Certificate, ca_certificate: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)
    if certificate.issuer != ca_certificate.subject:
        raise CryptoError("peer certificate was not issued by the trusted CA")
    if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
        raise CryptoError("peer certificate is outside its validity period")
    try:
        constraints = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        usage = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound as exc:
        raise CryptoError("peer certificate is missing required extensions") from exc
    if constraints.ca:
        raise CryptoError("a CA certificate cannot be used as a client certificate")
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usage:
        raise CryptoError("peer certificate is not valid for client authentication")

    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, rsa.RSAPublicKey):
        raise CryptoError("the lab CA must use an RSA key")
    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except InvalidSignature as exc:
        raise CryptoError("peer certificate signature is invalid") from exc


def create_key_announcement(
    username: str,
    room: str,
    private_key: rsa.RSAPrivateKey,
    certificate_der: bytes,
    ephemeral_public_key: bytes,
) -> dict[str, object]:
    """Create a signed announcement binding an identity to an ephemeral key."""
    _validate_identifier(username, "username")
    _validate_identifier(room, "room")
    if len(ephemeral_public_key) != 32:
        raise CryptoError("X25519 public keys must contain 32 bytes")
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise CryptoError("client certificate is not valid DER") from exc
    certificate_key = certificate.public_key()
    if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(certificate_key, rsa.RSAPublicKey):
        raise CryptoError("client certificates and signing keys must use RSA")
    if private_key.public_key().public_numbers() != certificate_key.public_numbers():
        raise CryptoError("client signing key does not match its certificate")
    if _certificate_common_name(certificate) != username:
        raise CryptoError("username does not match the client certificate")

    signature = private_key.sign(
        _announcement_body(username, room, ephemeral_public_key),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "type": "key_announcement",
        "version": _ANNOUNCEMENT_VERSION,
        "username": username,
        "room": room,
        "certificate": base64.b64encode(certificate_der).decode("ascii"),
        "public_key": base64.b64encode(ephemeral_public_key).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_key_announcement(
    announcement: dict[str, object],
    ca_certificate: x509.Certificate,
    expected_room: str,
) -> PeerIdentity:
    """Validate a peer certificate and its signed room-scoped X25519 key."""
    if not isinstance(announcement, dict) or announcement.get("type") != "key_announcement":
        raise CryptoError("invalid key announcement")
    if announcement.get("version") != _ANNOUNCEMENT_VERSION:
        raise CryptoError("unsupported key announcement version")
    username = announcement.get("username")
    room = announcement.get("room")
    _validate_identifier(username, "username")
    _validate_identifier(room, "room")
    _validate_identifier(expected_room, "room")
    if room != expected_room:
        raise CryptoError("key announcement is for a different room")

    try:
        certificate_der = base64.b64decode(announcement["certificate"], validate=True)
        public_key = base64.b64decode(announcement["public_key"], validate=True)
        signature = base64.b64decode(announcement["signature"], validate=True)
        certificate = x509.load_der_x509_certificate(certificate_der)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise CryptoError("key announcement contains invalid certificate or key data") from exc
    if len(public_key) != 32:
        raise CryptoError("X25519 public keys must contain 32 bytes")
    try:
        x25519.X25519PublicKey.from_public_bytes(public_key)
    except ValueError as exc:
        raise CryptoError("invalid X25519 public key") from exc

    _validate_client_certificate(certificate, ca_certificate)
    if _certificate_common_name(certificate) != username:
        raise CryptoError("announced username does not match the certificate")
    certificate_key = certificate.public_key()
    if not isinstance(certificate_key, rsa.RSAPublicKey):
        raise CryptoError("client certificates must use RSA signing keys")
    try:
        certificate_key.verify(
            signature,
            _announcement_body(username, room, public_key),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise CryptoError("key announcement signature is invalid") from exc
    return PeerIdentity(username, room, public_key, certificate_der)


def derive_pairwise_key(
    private_key: x25519.X25519PrivateKey,
    peer_public_key: bytes,
    room: str,
    local_username: str,
    peer_username: str,
    local_public_key: bytes,
) -> bytes:
    """Derive a room and identity-bound pairwise AES key from X25519."""
    _validate_identifier(room, "room")
    _validate_identifier(local_username, "username")
    _validate_identifier(peer_username, "username")
    if local_username == peer_username:
        raise CryptoError("pairwise keys require two distinct identities")
    if len(peer_public_key) != 32 or len(local_public_key) != 32:
        raise CryptoError("X25519 public keys must contain 32 bytes")
    expected_local = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if not secrets.compare_digest(local_public_key, expected_local):
        raise CryptoError("local public key does not match its private key")
    try:
        peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = private_key.exchange(peer_key)
    except ValueError as exc:
        raise CryptoError("invalid X25519 peer key") from exc

    identities_and_keys = sorted(
        ((local_username, local_public_key), (peer_username, peer_public_key)),
        key=lambda item: item[0],
    )
    context = {
        "protocol": "securechat-pairwise-v1",
        "room": room,
        "participants": [
            {"username": username, "public_key": base64.b64encode(key).decode("ascii")}
            for username, key in identities_and_keys
        ],
    }
    info = json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")
    salt = hashlib.sha256(("securechat-v1:" + room).encode("utf-8")).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared_secret)


def _associated_data(*, room: str, sender: str, recipient: str) -> bytes:
    _validate_identifier(room, "room")
    _validate_identifier(sender, "username")
    _validate_identifier(recipient, "username")
    return json.dumps(
        {"version": _ENVELOPE_VERSION, "room": room, "sender": sender, "recipient": recipient},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encrypt_message(
    key: bytes,
    plaintext: str,
    *,
    room: str,
    sender: str,
    recipient: str,
) -> dict[str, str]:
    if len(key) != 32:
        raise CryptoError("AES-256-GCM keys must contain 32 bytes")
    if not isinstance(plaintext, str):
        raise CryptoError("message plaintext must be text")
    nonce = secrets.token_bytes(_NONCE_BYTES)
    try:
        ciphertext = AESGCM(key).encrypt(
            nonce,
            plaintext.encode("utf-8"),
            _associated_data(room=room, sender=sender, recipient=recipient),
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise CryptoError("message could not be encrypted") from exc
    return {
        "version": _ENVELOPE_VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_message(
    key: bytes,
    envelope: dict[str, str],
    *,
    room: str,
    sender: str,
    recipient: str,
) -> str:
    if len(key) != 32:
        raise CryptoError("AES-256-GCM keys must contain 32 bytes")
    if not isinstance(envelope, dict) or envelope.get("version") != _ENVELOPE_VERSION:
        raise CryptoError("unsupported message envelope")
    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(nonce) != _NONCE_BYTES:
            raise CryptoError("invalid AES-GCM nonce")
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            _associated_data(room=room, sender=sender, recipient=recipient),
        )
        return plaintext.decode("utf-8")
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidTag, UnicodeDecodeError) as exc:
        raise CryptoError("message authentication failed") from exc
