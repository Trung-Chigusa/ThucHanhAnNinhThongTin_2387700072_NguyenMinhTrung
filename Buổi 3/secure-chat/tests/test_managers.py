import threading
import time
import unittest

from securechat.connection_manager import ClientSession, ConnectionManager
from securechat.room_manager import RoomManager


class RecordingSocket:
    def __init__(self):
        self.frames = []

    def sendall(self, data):
        self.frames.append(data)


class BlockingSocket:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.overlapped = threading.Event()
        self._lock = threading.Lock()
        self._active = 0

    def sendall(self, data):
        with self._lock:
            self._active += 1
            if self._active > 1:
                self.overlapped.set()
        self.entered.set()
        self.release.wait(timeout=2)
        with self._lock:
            self._active -= 1


def make_session(username="alice", socket=None, room="general"):
    return ClientSession(
        username=username,
        room=room,
        socket=socket or RecordingSocket(),
        certificate_der=b"certificate",
        public_key=b"public-key",
    )


class ConnectionManagerTests(unittest.TestCase):
    def test_register_rejects_duplicate_username(self):
        manager = ConnectionManager()
        manager.register(make_session("alice"))

        with self.assertRaises(ValueError):
            manager.register(make_session("alice"))

    def test_register_rejects_invalid_username(self):
        with self.assertRaises(ValueError):
            ConnectionManager().register(make_session("alice\nadmin"))

    def test_snapshot_is_a_copy_of_active_sessions(self):
        manager = ConnectionManager()
        session = make_session()
        manager.register(session)

        snapshot = manager.snapshot()
        snapshot.clear()

        self.assertIs(manager.get("alice"), session)

    def test_send_encodes_a_frame(self):
        manager = ConnectionManager()
        session = make_session()
        manager.register(session)

        manager.send(session, {"type": "notice", "text": "joined"})

        self.assertEqual(session.socket.frames, [b'{"type":"notice","text":"joined"}\n'])

    def test_concurrent_sends_to_one_session_are_serialized(self):
        socket = BlockingSocket()
        manager = ConnectionManager()
        session = make_session(socket=socket)
        manager.register(session)
        first = threading.Thread(target=manager.send, args=(session, {"number": 1}))
        second_started = threading.Event()

        def second_send():
            second_started.set()
            manager.send(session, {"number": 2})

        first.start()
        self.assertTrue(socket.entered.wait(timeout=1))
        second = threading.Thread(target=second_send)
        second.start()
        self.assertTrue(second_started.wait(timeout=1))
        time.sleep(0.03)
        was_overlapped = socket.overlapped.is_set()
        socket.release.set()
        first.join(timeout=1)
        second.join(timeout=1)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertFalse(was_overlapped)

    def test_slow_send_does_not_hold_registry_lock(self):
        socket = BlockingSocket()
        manager = ConnectionManager()
        session = make_session(socket=socket)
        manager.register(session)
        sender = threading.Thread(target=manager.send, args=(session, {"number": 1}))
        sender.start()
        self.assertTrue(socket.entered.wait(timeout=1))

        start = time.perf_counter()
        self.assertIs(manager.get("alice"), session)
        lookup_duration = time.perf_counter() - start
        socket.release.set()
        sender.join(timeout=1)

        self.assertFalse(sender.is_alive())
        self.assertLess(lookup_duration, 0.1)

    def test_remove_returns_and_forgets_session(self):
        manager = ConnectionManager()
        session = make_session()
        manager.register(session)

        self.assertIs(manager.remove("alice"), session)
        self.assertIsNone(manager.get("alice"))
        self.assertIsNone(manager.remove("alice"))

    def test_remove_if_current_does_not_remove_a_replacement_session(self):
        manager = ConnectionManager()
        old_session = make_session()
        manager.register(old_session)
        self.assertIs(manager.remove_if_current(old_session), old_session)

        new_session = make_session()
        manager.register(new_session)

        self.assertIsNone(manager.remove_if_current(old_session))
        self.assertIs(manager.get("alice"), new_session)


class RoomManagerTests(unittest.TestCase):
    def test_join_rejects_invalid_room_and_username(self):
        rooms = RoomManager()

        with self.assertRaises(ValueError):
            rooms.join("../private", "alice")
        with self.assertRaises(ValueError):
            rooms.join("general", "alice\nadmin")

    def test_join_leave_and_members_are_isolated_by_room(self):
        rooms = RoomManager()
        rooms.join("general", "alice")
        rooms.join("general", "bob")
        rooms.join("private", "carol")

        self.assertEqual(rooms.members("general"), ["alice", "bob"])
        self.assertEqual(rooms.members("private"), ["carol"])
        self.assertEqual(rooms.members("missing"), [])

        rooms.leave("general", "alice")
        self.assertEqual(rooms.members("general"), ["bob"])
        self.assertEqual(rooms.members("private"), ["carol"])

    def test_remove_client_leaves_all_rooms_and_returns_room_names(self):
        rooms = RoomManager()
        rooms.join("general", "alice")
        rooms.join("private", "alice")
        rooms.join("private", "bob")

        self.assertEqual(rooms.remove_client("alice"), ["general", "private"])
        self.assertEqual(rooms.members("general"), [])
        self.assertEqual(rooms.members("private"), ["bob"])


if __name__ == "__main__":
    unittest.main()
