"""Bounded newline-delimited JSON framing for SecureChat."""

from __future__ import annotations

import json

MAX_FRAME_BYTES = 64 * 1024


class ProtocolError(ValueError):
    """Raised when a wire frame is malformed or exceeds the protocol limit."""


def encode_frame(payload: dict[str, object]) -> bytes:
    """Encode one JSON object, including its newline, within the frame limit."""
    if not isinstance(payload, dict):
        raise ProtocolError("protocol frames must be JSON objects")
    try:
        wire = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("frame is not valid UTF-8 JSON") from exc
    if len(wire) > MAX_FRAME_BYTES:
        raise ProtocolError("frame exceeds the 64 KiB limit")
    return wire


class FrameDecoder:
    """Incrementally decode newline-delimited JSON objects from TCP bytes."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[dict[str, object]]:
        if not isinstance(data, bytes):
            raise TypeError("frame data must be bytes")
        self._buffer.extend(data)
        decoded: list[dict[str, object]] = []

        while True:
            try:
                newline = self._buffer.index(b"\n")
            except ValueError:
                if len(self._buffer) >= MAX_FRAME_BYTES:
                    raise ProtocolError("unterminated frame exceeds the 64 KiB limit")
                break

            if newline + 1 > MAX_FRAME_BYTES:
                raise ProtocolError("frame exceeds the 64 KiB limit")
            raw = bytes(self._buffer[:newline])
            del self._buffer[: newline + 1]
            if not raw:
                raise ProtocolError("empty frames are not allowed")
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProtocolError("frame is not valid UTF-8 JSON") from exc
            if not isinstance(value, dict):
                raise ProtocolError("protocol frames must decode to JSON objects")
            decoded.append(value)

        return decoded
