"""Harmless, scriptless reflection check for the loopback demo target."""

from __future__ import annotations

import secrets

from scanners.scanner_service import Finding, ScanError, create_local_http_client


def scan_xss(target, http=None) -> list[Finding]:
    if http is None:
        http = create_local_http_client()
    marker = f"<lab04-marker-{secrets.token_hex(8)}>"
    try:
        response = http.get(
            target.canonical_url,
            params={"q": marker},
            timeout=3,
            allow_redirects=False,
        )
    except Exception:
        raise ScanError("The local target did not return a usable response.") from None
    if not 200 <= response.status_code < 300 or marker not in response.text:
        return []
    return [
        Finding(
            type="XSS",
            location="query:q",
            evidence="A harmless custom-element marker was reflected without HTML encoding.",
            confidence="candidate",
            risk="Medium",
            remediation="Encode untrusted output for its HTML context and use safe template rendering.",
        )
    ]
