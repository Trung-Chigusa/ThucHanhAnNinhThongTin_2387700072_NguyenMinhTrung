"""Thread-safe room membership registry."""

import re
from threading import RLock

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")


def _validate_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid {label}")

class RoomManager:
    def __init__(self) -> None:
        self._rooms: dict[str, set[str]] = {}
        self._memberships: dict[str, set[str]] = {}
        self._lock = RLock()

    def join(self, room: str, username: str) -> None:
        _validate_identifier(room, "room")
        _validate_identifier(username, "username")
        with self._lock:
            self._rooms.setdefault(room, set()).add(username)
            self._memberships.setdefault(username, set()).add(room)

    def leave(self, room: str, username: str) -> None:
        _validate_identifier(room, "room")
        _validate_identifier(username, "username")
        with self._lock:
            members = self._rooms.get(room)
            if not members or username not in members:
                return
            members.remove(username)
            if not members:
                self._rooms.pop(room, None)
            memberships = self._memberships.get(username)
            if memberships is not None:
                memberships.discard(room)
                if not memberships:
                    self._memberships.pop(username, None)

    def members(self, room: str) -> list[str]:
        _validate_identifier(room, "room")
        with self._lock:
            return sorted(self._rooms.get(room, set()))

    def remove_client(self, username: str) -> list[str]:
        _validate_identifier(username, "username")
        with self._lock:
            memberships = sorted(self._memberships.pop(username, set()))
            for room in memberships:
                members = self._rooms.get(room)
                if members is None:
                    continue
                members.discard(username)
                if not members:
                    self._rooms.pop(room, None)
            return memberships
