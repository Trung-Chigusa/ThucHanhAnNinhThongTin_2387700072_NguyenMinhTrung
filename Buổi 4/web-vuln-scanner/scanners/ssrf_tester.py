"""Static hints for URL parameters that refer to local/private addresses."""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, urlsplit

from scanners.scanner_service import Finding


def _private_destination(value: str) -> str | None:
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    hostname = parsed.hostname or candidate.split("/", 1)[0]
    hostname = hostname.strip("[]").lower().rstrip(".")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return "localhost"
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return None
    if address.is_loopback:
        return "loopback address"
    if address.is_link_local:
        return "link-local address"
    if address.is_private:
        return "private address"
    return None


def scan_ssrf(target) -> list[Finding]:
    findings = []
    for name, value in parse_qsl(urlsplit(target.canonical_url).query, keep_blank_values=True):
        destination = _private_destination(value)
        if destination:
            findings.append(
                Finding(
                    type="SSRF",
                    location=f"query:{name}",
                    evidence=f"Parameter value contains a {destination} indicator; no request was made.",
                    confidence="heuristic",
                    risk="High",
                    remediation="Resolve and validate destinations against an explicit server-side allowlist before fetching.",
                )
            )
    return findings
