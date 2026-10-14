"""Static SQLi pattern hints; this module never makes requests or SQL calls."""

from urllib.parse import parse_qsl, urlsplit
import re

from scanners.scanner_service import Finding


_PATTERNS = (
    re.compile(r"\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.IGNORECASE),
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"\bSLEEP\s*\(", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
)


def scan_sql_injection(target) -> list[Finding]:
    findings = []
    for name, value in parse_qsl(urlsplit(target.canonical_url).query, keep_blank_values=True):
        if any(pattern.search(value) for pattern in _PATTERNS):
            findings.append(
                Finding(
                    type="SQLi",
                    location=f"query:{name}",
                    evidence="A query value matches a common SQL injection pattern; no SQL was executed.",
                    confidence="heuristic",
                    risk="High",
                    remediation="Use parameterized queries and validate values at the application boundary.",
                )
            )
    return findings
