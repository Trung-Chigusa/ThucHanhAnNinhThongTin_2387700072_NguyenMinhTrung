"""Terminal client for the local SecureChat lab."""

from __future__ import annotations

import argparse
import socket
import ssl
import threading
from collections import deque
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.x509.oid import NameOID

from securechat.crypto import (
    CryptoError,
    PeerIdentity,
    create_key_announcement,
    decrypt_message,
    derive_pairwise_key,
    encrypt_message,
    verify_key_announcement,
)
from securechat.protocol import FrameDecoder, ProtocolError, encode_frame


def create_client_tls_context(ca_file: str, certfile: str, keyfile: str) -> ssl.SSLContext:
    """Create a TLS client context that verifies both chain and server name."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile, keyfile)
    return context


def _certificate_username(certificate: x509.Certificate) -> str:
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise CryptoError("client certificate must contain exactly one common name")
    return common_names[0].value


class SecureChatClient:
    """One terminal user's authenticated TLS and end-to-end chat session."""

    def __init__(
        self,
        host: str,
        port: int,
        room: str,
        certfile: str,
        keyfile: str,
        ca_file: str,
        *,
        output_fn: Callable[[str], object] = print,
    ) -> None:
        self.host = host
        self.port = port
        self.room = room
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_file = ca_file
        self.output_fn = output_fn

        certificate = x509.load_pem_x509_certificate(Path(certfile).read_bytes())
        self.username = _certificate_username(certificate)
        self.certificate_der = certificate.public_bytes(serialization.Encoding.DER)
        private_key = serialization.load_pem_private_key(Path(keyfile).read_bytes(), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoError("client certificate signing keys must use RSA")
        self.signing_key = private_key
        self.ca_certificate = x509.load_pem_x509_certificate(Path(ca_file).read_bytes())
        self.ephemeral_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.ephemeral_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        self._connection: ssl.SSLSocket | None = None
        self._decoder = FrameDecoder()
        self._pending: deque[dict[str, object]] = deque()
        self._peers: dict[str, PeerIdentity] = {}
        self._peers_lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._stopped = threading.Event()
        self._reader_thread: threading.Thread | None = None

    def connect(self) -> None:
        context = create_client_tls_context(self.ca_file, self.certfile, self.keyfile)
        raw_connection = socket.create_connection((self.host, self.port), timeout=5.0)
        try:
            self._connection = context.wrap_socket(raw_connection, server_hostname=self.host)
        except BaseException:
            raw_connection.close()
            raise
        self._connection.settimeout(None)
        announcement = create_key_announcement(
            self.username,
            self.room,
            self.signing_key,
            self.certificate_der,
            self.public_key,
        )
        self._send(announcement)
        welcome = self._receive_one(timeout=5.0)
        if (
            welcome.get("type") != "welcome"
            or welcome.get("username") != self.username
            or welcome.get("room") != self.room
            or not isinstance(welcome.get("peers"), list)
        ):
            raise ConnectionError("server did not accept this client identity and room")
        for announcement in welcome["peers"]:
            self._add_peer(announcement)
        self.output_fn(f"Connected as {self.username} in room {self.room}.")
        self.output_fn("Send a message with @username message; enter /help for commands.")

    def start_reader(self) -> None:
        if self._connection is None:
            raise RuntimeError("connect() must be called before start_reader()")
        if self._reader_thread is not None:
            raise RuntimeError("reader is already running")
        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            daemon=True,
            name=f"securechat-reader-{self.username}",
        )
        self._reader_thread.start()

    def send_text(self, recipient: str, plaintext: str) -> None:
        with self._peers_lock:
            peer = self._peers.get(recipient)
        if peer is None:
            self.output_fn(f"{recipient} is not connected to room {self.room}.")
            return
        try:
            key = derive_pairwise_key(
                self.ephemeral_key,
                peer.public_key,
                self.room,
                self.username,
                recipient,
                self.public_key,
            )
            envelope = encrypt_message(
                key,
                plaintext,
                room=self.room,
                sender=self.username,
                recipient=recipient,
            )
            self._send(
                {
                    "type": "chat",
                    "sender": self.username,
                    "room": self.room,
                    "recipient": recipient,
                    "envelope": envelope,
                }
            )
        except (CryptoError, ProtocolError, OSError, ssl.SSLError):
            self.output_fn("Message could not be sent. Check the connection and message size.")
            return
        self.output_fn(f"Encrypted message sent to {recipient}.")

    def close(self) -> None:
        connection = self._connection
        if connection is None:
            self._stopped.set()
            return
        if not self._stopped.is_set():
            try:
                self._send({"type": "leave"})
            except (OSError, ProtocolError, ssl.SSLError):
                pass
        self._stopped.set()
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            connection.close()
        except OSError:
            pass
        reader = self._reader_thread
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=1.0)
        self._connection = None

    def _send(self, message: dict[str, object]) -> None:
        connection = self._connection
        if connection is None:
            raise ConnectionError("client is not connected")
        frame = encode_frame(message)
        with self._send_lock:
            connection.sendall(frame)

    def _receive_one(self, *, timeout: float | None = None) -> dict[str, object]:
        connection = self._connection
        if connection is None:
            raise ConnectionError("client is not connected")
        if self._pending:
            return self._pending.popleft()
        connection.settimeout(timeout)
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                raise ConnectionError("server closed the TLS connection")
            frames = self._decoder.feed(chunk)
            if frames:
                self._pending.extend(frames[1:])
                return frames[0]

    def _reader_loop(self) -> None:
        try:
            while not self._stopped.is_set():
                if self._pending:
                    message = self._pending.popleft()
                else:
                    message = self._receive_one()
                self._handle_server_message(message)
        except (OSError, ssl.SSLError, ProtocolError, ConnectionError, CryptoError):
            if not self._stopped.is_set():
                self.output_fn("Disconnected from the SecureChat relay.")
        finally:
            self._stopped.set()

    def _handle_server_message(self, message: dict[str, object]) -> None:
        message_type = message.get("type")
        if message_type == "peer_joined":
            peer = self._add_peer(message.get("peer"))
            self.output_fn(f"{peer.username} joined room {self.room}.")
            return
        if message_type == "peer_left":
            username = message.get("username")
            if isinstance(username, str):
                with self._peers_lock:
                    self._peers.pop(username, None)
                self.output_fn(f"{username} left room {self.room}.")
            return
        if message_type == "chat":
            self._receive_chat(message)
            return
        if message_type == "error":
            code = message.get("code")
            if isinstance(code, str):
                self.output_fn(f"Server rejected the message ({code}).")
            return

    def _add_peer(self, announcement: object) -> PeerIdentity:
        if not isinstance(announcement, dict):
            raise CryptoError("peer announcement is not an object")
        peer = verify_key_announcement(announcement, self.ca_certificate, self.room)
        if peer.username == self.username:
            raise CryptoError("server announced the local identity as another peer")
        with self._peers_lock:
            existing = self._peers.get(peer.username)
            if existing is not None and existing.certificate_der != peer.certificate_der:
                raise CryptoError("peer identity changed during the session")
            self._peers[peer.username] = peer
        return peer

    def _receive_chat(self, message: dict[str, object]) -> None:
        sender = message.get("sender")
        recipient = message.get("recipient")
        room = message.get("room")
        envelope = message.get("envelope")
        if recipient != self.username or room != self.room or not isinstance(sender, str):
            return
        if not isinstance(envelope, dict):
            return
        with self._peers_lock:
            peer = self._peers.get(sender)
        if peer is None:
            self.output_fn("Ignored a message from an unknown peer.")
            return
        try:
            key = derive_pairwise_key(
                self.ephemeral_key,
                peer.public_key,
                self.room,
                self.username,
                sender,
                self.public_key,
            )
            plaintext = decrypt_message(
                key,
                envelope,
                room=self.room,
                sender=sender,
                recipient=self.username,
            )
        except CryptoError:
            self.output_fn(f"Ignored an unauthenticated message from {sender}.")
            return
        self.output_fn(f"[{sender}] {plaintext}")


def run_client(
    host: str,
    port: int,
    room: str,
    certfile: str,
    keyfile: str,
    ca_file: str,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], object] = print,
) -> None:
    """Run an interactive client; the certificate common name is its username."""
    client = SecureChatClient(
        host,
        port,
        room,
        certfile,
        keyfile,
        ca_file,
        output_fn=output_fn,
    )
    try:
        client.connect()
        client.start_reader()
        while True:
            try:
                line = input_fn("securechat> ")
            except (EOFError, KeyboardInterrupt):
                break
            command = line.strip()
            if not command:
                continue
            if command.lower() == "exit":
                break
            if command == "/help":
                output_fn("Commands: @username message, /help, exit")
                continue
            if command.startswith("@"):
                target_and_message = command[1:].split(maxsplit=1)
                if len(target_and_message) != 2 or not target_and_message[1].strip():
                    output_fn("Use @username message")
                    continue
                recipient, plaintext = target_and_message
                client.send_text(recipient, plaintext)
                continue
            output_fn("Use @username message, /help, or exit.")
    finally:
        client.close()


def _default_cert_path(filename: str) -> str:
    return str(Path(__file__).resolve().parent / "certs" / filename)


def main() -> None:
    parser = argparse.ArgumentParser(description="Join a local SecureChat room")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--room", required=True)
    parser.add_argument("--cert", required=True, help="client certificate PEM")
    parser.add_argument("--key", required=True, help="client private key PEM")
    parser.add_argument("--ca", default=_default_cert_path("ca.pem"))
    args = parser.parse_args()
    run_client(args.host, args.port, args.room, args.cert, args.key, args.ca)


if __name__ == "__main__":
    main()
