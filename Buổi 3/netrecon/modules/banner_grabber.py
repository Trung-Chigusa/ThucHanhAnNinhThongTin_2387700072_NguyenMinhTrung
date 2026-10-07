"""Read a small, unsolicited TCP greeting without sending application data."""

import socket
import unicodedata
from ipaddress import IPv4Address, IPv6Address

from modules.rate_limiter import ProbeScheduler


def _socket_address(target: IPv4Address | IPv6Address, port: int):
    if target.version == 6:
        return (str(target), port, 0, 0)
    return (str(target), port)


def _sanitize(data: bytes) -> str | None:
    decoded = data.decode("utf-8", errors="replace")
    cleaned = "".join(char for char in decoded if unicodedata.category(char) != "Cc").strip()
    return cleaned or None


def grab_banner(
    target: IPv4Address | IPv6Address,
    port: int,
    *,
    scheduler: ProbeScheduler,
    timeout_seconds: float,
    max_bytes: int = 512,
) -> str | None:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not 0 < timeout_seconds <= 3:
        raise ValueError("timeout_seconds must be between 0 and 3")
    if not 1 <= max_bytes <= 512:
        raise ValueError("max_bytes must be between 1 and 512")

    def read_greeting() -> str | None:
        sock = socket.socket(socket.AF_INET6 if target.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout_seconds)
            sock.connect(_socket_address(target, port))
            return _sanitize(sock.recv(max_bytes)[:max_bytes])
        except (ConnectionRefusedError, socket.timeout, TimeoutError, BrokenPipeError):
            return None
        finally:
            sock.close()

    return scheduler.run_probe(read_greeting)
