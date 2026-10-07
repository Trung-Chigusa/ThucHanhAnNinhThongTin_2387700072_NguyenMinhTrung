"""Informational exposure notes, not vulnerability or CVE assessments."""


_PLAINTEXT_SERVICES = {
    "ftp": "FTP may carry credentials and data without transport encryption; review whether a protected protocol is appropriate.",
    "telnet": "Telnet may carry credentials and session data without transport encryption; review whether a protected protocol is appropriate.",
    "http": "HTTP traffic may be unencrypted; review whether transport encryption is appropriate.",
    "pop3": "POP3 may carry credentials and mail without transport encryption; review whether a protected protocol is appropriate.",
    "imap": "IMAP may carry credentials and mail without transport encryption; review whether a protected protocol is appropriate.",
}


def review_exposure(port: int, service: str | None) -> tuple[str, ...]:
    del port  # The service hint controls this local, informational review only.
    if service is None:
        return ()
    note = _PLAINTEXT_SERVICES.get(service.casefold())
    return (f"Informational: {note}",) if note else ()
