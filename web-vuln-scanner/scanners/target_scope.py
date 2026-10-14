"""Fail-closed validation and pinning for loopback HTTP targets."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class TargetError(ValueError):
    """Raised when a scan target is not an explicitly local HTTP URL."""


@dataclass(frozen=True)
class LocalTarget:
    canonical_url: str
    host: str
    port: int
    path: str
    query: str


def _ip_from_answer(answer: tuple) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(answer[4][0].split("%", 1)[0])


def validate_local_target(
    raw_url: str,
    resolver=socket.getaddrinfo,
) -> LocalTarget:
    """Parse a URL and pin it to a numeric loopback address before HTTP use."""
    if not isinstance(raw_url, str) or not raw_url or raw_url != raw_url.strip():
        raise TargetError("Enter a valid local HTTP or HTTPS URL.")
    try:
        parsed = urlsplit(raw_url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise TargetError("Only HTTP or HTTPS targets are supported.")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise TargetError("Credentials and URL fragments are not allowed.")
        port = parsed.port or (443 if scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise TargetError("Target port must be between 1 and 65535.")
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, TargetError):
            raise
        raise TargetError("Enter a valid local HTTP or HTTPS URL.") from None

    hostname = parsed.hostname
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = [literal]
    except ValueError:
        try:
            answers = resolver(hostname, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(_ip_from_answer(answer) for answer in answers))
        except (OSError, ValueError, IndexError, TypeError):
            raise TargetError("Target hostname could not be safely resolved.") from None
        if not addresses:
            raise TargetError("Target hostname has no address records.")

    if any(not address.is_loopback for address in addresses):
        raise TargetError("Every target address must be a loopback address.")

    chosen = addresses[0]
    host = str(chosen)
    if isinstance(chosen, ipaddress.IPv6Address):
        netloc_host = f"[{host}]"
    else:
        netloc_host = host
    default_port = 443 if scheme == "https" else 80
    netloc = netloc_host if port == default_port and parsed.port is None else f"{netloc_host}:{port}"
    canonical = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    return LocalTarget(
        canonical_url=canonical,
        host=host,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
    )
