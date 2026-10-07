"""Thread-safe registry for authenticated client connections."""

import re
from dataclasses import dataclass, field
from threading import Lock, RLock

from .protocol import encode_frame

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")


@dataclass
class ClientSession:
    username: str
    room: str
    socket: object
    certificate_der: bytes
    public_key: bytes
    ready: bool = False
    send_lock: Lock = field(default_factory=Lock)


class ConnectionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, ClientSession] = {}
        self._lock = RLock()

    def register(self, session: ClientSession) -> None:
        if not _IDENTIFIER.fullmatch(session.username):
            raise ValueError("invalid username")
        if not _IDENTIFIER.fullmatch(session.room):
            raise ValueError("invalid room")
        with self._lock:
            if session.username in self._sessions:
                raise ValueError("username is already connected")
            self._sessions[session.username] = session

    def get(self, username: str) -> ClientSession | None:
        with self._lock:
            return self._sessions.get(username)

    def snapshot(self) -> list[ClientSession]:
        with self._lock:
            return list(self._sessions.values())

    def send(self, session: ClientSession, payload: dict[str, object]) -> None:
        with self._lock:
            if self._sessions.get(session.username) is not session:
                raise KeyError("client session is no longer active")
        frame = encode_frame(payload)
        with session.send_lock:
            session.socket.sendall(frame)

    def remove(self, username: str) -> ClientSession | None:
        with self._lock:
            return self._sessions.pop(username, None)

    def remove_if_current(self, session: ClientSession) -> ClientSession | None:
        """Remove a session only when it still owns its username."""
        with self._lock:
            if self._sessions.get(session.username) is not session:
                return None
            return self._sessions.pop(session.username)
