"""Conservative local service-name hints; no network activity."""

from models import Protocol


_SERVICES: dict[tuple[Protocol, int], str] = {
    ("tcp", 20): "ftp-data",
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
    ("tcp", 25): "smtp",
    ("tcp", 53): "domain",
    ("udp", 53): "domain",
    ("tcp", 80): "http",
    ("tcp", 110): "pop3",
    ("tcp", 143): "imap",
    ("tcp", 443): "https",
    ("udp", 123): "ntp",
    ("udp", 161): "snmp",
}


def detect_service(port: int, protocol: Protocol, banner: str | None) -> str | None:
    service = _SERVICES.get((protocol, port))
    if service:
        return service
    if not banner:
        return None
    greeting = banner.casefold()
    if greeting.startswith("ssh-"):
        return "ssh"
    if greeting.startswith("http/") or "\nhttp/" in greeting:
        return "http"
    if greeting.startswith("220 ") and "ftp" in greeting:
        return "ftp"
    return None
