"""Mutual-TLS SecureChat relay. Message bodies remain encrypted on clients."""

from __future__ import annotations

import argparse
import base64
import binascii
import socket
import ssl
import threading
from pathlib import Path

from cryptography import x509

from securechat.connection_manager import ClientSession, ConnectionManager
from securechat.crypto import CryptoError, verify_key_announcement
from securechat.protocol import FrameDecoder, ProtocolError
from securechat.room_manager import RoomManager


class SecureChatServer:
    """A threaded, certificate-authenticated ciphertext relay."""

    def __init__(
        self,
        certfile: str,
        keyfile: str,
        ca_file: str,
        host: str = "127.0.0.1",
        port: int = 8443,
    ) -> None:
        self.certfile = str(certfile)
        self.keyfile = str(keyfile)
        self.ca_file = str(ca_file)
        self.host = host
        self.port = port
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._tls_context.verify_mode = ssl.CERT_REQUIRED
        self._tls_context.load_cert_chain(self.certfile, self.keyfile)
        self._tls_context.load_verify_locations(cafile=self.ca_file)
        self._ca_certificate = x509.load_pem_x509_certificate(Path(self.ca_file).read_bytes())

        self._connections = ConnectionManager()
        self._rooms = RoomManager()
        self._announcements: dict[str, dict[str, object]] = {}
        self._state_lock = threading.RLock()
        self._sockets_lock = threading.Lock()
        self._client_sockets: set[socket.socket] = set()
        self._listener: socket.socket | None = None
        self._stopped = threading.Event()

    def start(self) -> int:
        """Bind and listen, returning the actual port (useful with port 0)."""
        if self._listener is not None:
            raise RuntimeError("server has already been started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, self.port))
            listener.listen()
        except OSError:
            listener.close()
            raise
        listener.settimeout(0.25)
        self._listener = listener
        self.port = listener.getsockname()[1]
        self._stopped.clear()
        return self.port

    def serve_forever(self) -> None:
        """Accept connections until :meth:`stop` closes the listener."""
        listener = self._listener
        if listener is None:
            raise RuntimeError("call start() before serve_forever()")
        while not self._stopped.is_set():
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stopped.is_set():
                    return
                raise
            connection.settimeout(5.0)
            self._track_socket(connection)
            worker = threading.Thread(
                target=self._handle_connection,
                args=(connection,),
                daemon=True,
                name="securechat-client",
            )
            worker.start()

    def stop(self) -> None:
        """Stop accepting clients and close active TLS connections."""
        self._stopped.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._sockets_lock:
            active_sockets = list(self._client_sockets)
        for connection in active_sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def _track_socket(self, connection: socket.socket) -> None:
        with self._sockets_lock:
            self._client_sockets.add(connection)

    def _replace_tracked_socket(self, old: socket.socket, new: socket.socket) -> None:
        with self._sockets_lock:
            self._client_sockets.discard(old)
            self._client_sockets.add(new)

    def _untrack_socket(self, connection: socket.socket) -> None:
        with self._sockets_lock:
            self._client_sockets.discard(connection)

    def _handle_connection(self, raw_connection: socket.socket) -> None:
        connection: ssl.SSLSocket | None = None
        username: str | None = None
        try:
            connection = self._tls_context.wrap_socket(raw_connection, server_side=True)
            self._replace_tracked_socket(raw_connection, connection)
            connection.settimeout(None)
            certificate_der = connection.getpeercert(binary_form=True)
            if not certificate_der:
                return

            decoder = FrameDecoder()
            registered = False
            while not self._stopped.is_set():
                chunk = connection.recv(4096)
                if not chunk:
                    return
                for message in decoder.feed(chunk):
                    if not registered:
                        username = self._register_client(connection, certificate_der, message)
                        registered = True
                    elif not self._handle_message(username, message):
                        return
        except (OSError, ssl.SSLError, ProtocolError, CryptoError, ValueError, TypeError, KeyError, binascii.Error):
            return
        finally:
            if username is not None:
                self._disconnect(username)
            target = connection if connection is not None else raw_connection
            self._untrack_socket(target)
            self._untrack_socket(raw_connection)
            try:
                target.close()
            except OSError:
                pass

    def _register_client(
        self,
        connection: ssl.SSLSocket,
        certificate_der: bytes,
        announcement: dict[str, object],
    ) -> str:
        identity = verify_key_announcement(announcement, self._ca_certificate, str(announcement.get("room", "")))
        try:
            announced_certificate = base64.b64decode(announcement["certificate"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise CryptoError("invalid certificate in key announcement") from exc
        if announced_certificate != certificate_der:
            raise CryptoError("key announcement certificate does not match the TLS identity")

        session = ClientSession(
            username=identity.username,
            room=identity.room,
            socket=connection,
            certificate_der=certificate_der,
            public_key=identity.public_key,
        )
        with self._state_lock:
            existing_peers = [
                self._announcements[name]
                for name in self._rooms.members(identity.room)
                if name in self._announcements
            ]
            self._connections.register(session)
            self._rooms.join(identity.room, identity.username)
            self._announcements[identity.username] = announcement

        try:
            self._connections.send(
                session,
                {
                    "type": "welcome",
                    "username": identity.username,
                    "room": identity.room,
                    "peers": existing_peers,
                },
            )
        except (OSError, KeyError, ProtocolError, ValueError):
            self._disconnect(identity.username)
            raise
        self._broadcast(
            identity.room,
            {"type": "peer_joined", "peer": announcement},
            exclude=identity.username,
        )
        return identity.username

    def _handle_message(self, username: str, message: dict[str, object]) -> bool:
        session = self._connections.get(username)
        if session is None:
            return False
        message_type = message.get("type")
        if message_type == "leave" and set(message) == {"type"}:
            self._disconnect(username)
            return False
        if message_type != "chat":
            self._send_error(session, "unsupported_message")
            return True
        if set(message) != {"type", "sender", "room", "recipient", "envelope"}:
            self._send_error(session, "invalid_message")
            return True
        sender = message.get("sender")
        room = message.get("room")
        recipient = message.get("recipient")
        envelope = message.get("envelope")
        if sender != session.username or room != session.room:
            self._send_error(session, "identity_mismatch")
            return True
        if (
            not isinstance(recipient, str)
            or not isinstance(envelope, dict)
            or set(envelope) != {"version", "nonce", "ciphertext"}
            or envelope.get("version") != "1"
            or not all(isinstance(envelope.get(field), str) for field in ("nonce", "ciphertext"))
        ):
            self._send_error(session, "invalid_envelope")
            return True
        try:
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        except (ValueError, binascii.Error):
            self._send_error(session, "invalid_envelope")
            return True
        if len(nonce) != 12 or len(ciphertext) < 16:
            self._send_error(session, "invalid_envelope")
            return True

        recipient_session = self._connections.get(recipient)
        if recipient_session is None or recipient_session.room != session.room:
            self._send_error(session, "recipient_unavailable")
            return True
        delivered = {
            "type": "chat",
            "sender": session.username,
            "recipient": recipient,
            "room": session.room,
            "envelope": {"version": "1", "nonce": envelope["nonce"], "ciphertext": envelope["ciphertext"]},
        }
        self._safe_send(recipient_session, delivered)
        return True

    def _send_error(self, session: ClientSession, code: str) -> None:
        self._safe_send(session, {"type": "error", "code": code})

    def _safe_send(self, session: ClientSession, payload: dict[str, object]) -> None:
        try:
            self._connections.send(session, payload)
        except (OSError, KeyError, ProtocolError, ValueError):
            self._disconnect(session.username)

    def _broadcast(self, room: str, payload: dict[str, object], *, exclude: str | None = None) -> None:
        with self._state_lock:
            recipients = [
                self._connections.get(username)
                for username in self._rooms.members(room)
                if username != exclude
            ]
        for session in recipients:
            if session is not None:
                self._safe_send(session, payload)

    def _disconnect(self, username: str) -> None:
        with self._state_lock:
            session = self._connections.remove(username)
            if session is None:
                return
            rooms = self._rooms.remove_client(username)
            self._announcements.pop(username, None)
        try:
            session.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            session.socket.close()
        except OSError:
            pass
        for room in rooms:
            self._broadcast(room, {"type": "peer_left", "username": username})


def _default_cert_path(filename: str) -> str:
    return str(Path(__file__).resolve().parent / "certs" / filename)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local SecureChat TLS relay")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default=_default_cert_path("server.pem"))
    parser.add_argument("--key", default=_default_cert_path("server.key"))
    parser.add_argument("--ca", default=_default_cert_path("ca.pem"))
    args = parser.parse_args()
    server = SecureChatServer(args.cert, args.key, args.ca, args.host, args.port)
    try:
        bound_port = server.start()
        print(f"SecureChat relay listening on {args.host}:{bound_port}")
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping SecureChat relay")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
