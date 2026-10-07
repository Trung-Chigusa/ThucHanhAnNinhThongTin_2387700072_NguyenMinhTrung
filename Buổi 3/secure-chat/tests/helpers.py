"""Certificate and client helpers for local TLS integration tests."""

from __future__ import annotations

import json
import queue
import socket
import ssl
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from securechat.crypto import create_key_announcement
from securechat.protocol import FrameDecoder, encode_frame


@dataclass
class TestCredentials:
    directory: Path
    ca_certificate: Path
    server_certificate: Path
    server_key: Path
    clients: dict[str, tuple[Path, Path]] = field(default_factory=dict)
    untrusted_client: tuple[Path, Path] | None = None


def _write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _issue_certificate(
    *,
    ca_key: rsa.RSAPrivateKey,
    ca_name: x509.Name,
    common_name: str,
    server: bool = False,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
    return private_key, builder.sign(ca_key, hashes.SHA256())


def _make_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Name, x509.Certificate]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_name, ca_certificate


def create_test_credentials(directory: Path) -> TestCredentials:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca_name, ca_cert = _make_ca("SecureChat Integration CA")
    ca_path = directory / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    server_key, server_cert = _issue_certificate(
        ca_key=ca_key, ca_name=ca_name, common_name="localhost", server=True
    )
    server_key_path = directory / "server.key"
    server_cert_path = directory / "server.pem"
    _write_private_key(server_key_path, server_key)
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    credentials = TestCredentials(directory, ca_path, server_cert_path, server_key_path)
    for username in ("alice", "bob", "carol"):
        key, cert = _issue_certificate(ca_key=ca_key, ca_name=ca_name, common_name=username)
        key_path = directory / f"{username}.key"
        cert_path = directory / f"{username}.pem"
        _write_private_key(key_path, key)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        credentials.clients[username] = (cert_path, key_path)

    other_ca_key, other_ca_name, _ = _make_ca("Untrusted Integration CA")
    outsider_key, outsider_cert = _issue_certificate(
        ca_key=other_ca_key, ca_name=other_ca_name, common_name="outsider"
    )
    outsider_key_path = directory / "outsider.key"
    outsider_cert_path = directory / "outsider.pem"
    _write_private_key(outsider_key_path, outsider_key)
    outsider_cert_path.write_bytes(outsider_cert.public_bytes(serialization.Encoding.PEM))
    credentials.untrusted_client = (outsider_cert_path, outsider_key_path)
    return credentials


@dataclass
class TestPeer:
    username: str
    room: str
    connection: ssl.SSLSocket
    private_key: x25519.X25519PrivateKey
    public_key: bytes
    welcome: dict[str, object] = field(default_factory=dict)
    _decoder: FrameDecoder = field(default_factory=FrameDecoder)
    _messages: queue.Queue[dict[str, object]] = field(default_factory=queue.Queue)

    @classmethod
    def connect(
        cls,
        *,
        username: str,
        host: str,
        port: int,
        room: str,
        ca_file: Path,
        certificate_file: Path,
        key_file: Path,
    ) -> "TestPeer":
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.load_cert_chain(str(certificate_file), str(key_file))
        raw_connection = socket.create_connection((host, port), timeout=3)
        connection = context.wrap_socket(raw_connection, server_hostname=host)

        certificate = x509.load_pem_x509_certificate(certificate_file.read_bytes())
        private_key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        ephemeral_key = x25519.X25519PrivateKey.generate()
        public_key = ephemeral_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        announcement = create_key_announcement(
            username,
            room,
            private_key,
            certificate.public_bytes(serialization.Encoding.DER),
            public_key,
        )
        connection.sendall(encode_frame(announcement))
        peer = cls(username, room, connection, ephemeral_key, public_key)
        try:
            welcome = peer.receive_type("welcome")
            assert welcome["username"] == username
            peer.welcome = welcome
        except BaseException:
            peer.close()
            raise
        return peer

    def send(self, message: dict[str, object]) -> None:
        self.connection.sendall(encode_frame(message))

    def receive(self, timeout: float = 2.0) -> dict[str, object]:
        try:
            return self._messages.get_nowait()
        except queue.Empty:
            pass
        self.connection.settimeout(timeout)
        while True:
            chunk = self.connection.recv(4096)
            if not chunk:
                raise EOFError("server closed the TLS connection")
            frames = self._decoder.feed(chunk)
            for frame in frames[1:]:
                self._messages.put(frame)
            if frames:
                return frames[0]

    def receive_type(self, message_type: str, timeout: float = 2.0) -> dict[str, object]:
        import time

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no {message_type} frame received")
            message = self.receive(timeout=remaining)
            if message.get("type") == message_type:
                return message

    def close(self) -> None:
        try:
            self.connection.close()
        except OSError:
            pass


def connect_without_trusted_certificate(
    *,
    host: str,
    port: int,
    ca_file: Path,
    client: tuple[Path, Path] | None,
) -> None:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if client is not None:
        context.load_cert_chain(str(client[0]), str(client[1]))
    raw_connection = socket.create_connection((host, port), timeout=3)
    connection: ssl.SSLSocket | None = None
    try:
        try:
            connection = context.wrap_socket(raw_connection, server_hostname=host)
        except TimeoutError as exc:
            raise AssertionError("TLS handshake stalled instead of rejecting the client") from exc
        except (OSError, ssl.SSLError):
            return
        connection.settimeout(1.5)
        try:
            connection.sendall(encode_frame({"type": "not-an-announcement"}))
            received = connection.recv(4096)
        except TimeoutError as exc:
            raise AssertionError("TLS handshake stalled instead of rejecting the client") from exc
        except (OSError, ssl.SSLError):
            return
        if received:
            message = json.loads(received.split(b"\n", 1)[0].decode("utf-8"))
            if message.get("type") == "welcome":
                raise AssertionError("server accepted a client without a trusted certificate")
    finally:
        if connection is not None:
            connection.close()
        else:
            raw_connection.close()
