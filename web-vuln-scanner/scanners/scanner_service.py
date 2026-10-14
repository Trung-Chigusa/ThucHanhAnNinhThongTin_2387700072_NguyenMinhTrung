"""Shared scan models and orchestration for the local lab detectors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Sequence
from urllib.parse import urlsplit, urlunsplit

from scanners.target_scope import LocalTarget


@dataclass(frozen=True)
class Finding:
    type: str
    location: str
    evidence: str
    confidence: str
    risk: str
    remediation: str


@dataclass(frozen=True)
class ScanReport:
    target: str
    created_at_utc: str
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]


class ScanError(RuntimeError):
    """A sanitized error while querying the explicitly local demo target."""


def create_local_http_client():
    """Create a requests session that cannot route loopback calls through env proxies."""
    import requests

    client = requests.Session()
    client.trust_env = False
    return client


LIMITATIONS = (
    "Findings are heuristic candidates for manual verification, not proof of exploitability.",
    "The scanner targets loopback only and does not execute payloads or make SSRF requests.",
)


def _safe_target_url(raw_url: str) -> str:
    """Keep host/path context while dropping credentials, query values, and fragments."""
    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname
        if not hostname:
            return parsed.path or "local target"
        host = f"[{hostname}]" if ":" in hostname else hostname
        port = parsed.port
        netloc = host if port is None else f"{host}:{port}"
        # Path segments can contain reset links, identifiers, or other secrets.
        # Keep only the validated host so reports never persist path data.
        return urlunsplit((parsed.scheme, netloc, "/", "", ""))
    except ValueError:
        return "local target"


def scan_target(
    target: LocalTarget,
    *,
    checks: Sequence[str] = ("xss", "sql", "csrf", "ssrf"),
    http=None,
) -> ScanReport:
    """Run selected checks against a target that has already passed scope validation."""
    from scanners import csrf_detector, ssrf_tester, sql_injection_tester, xss_scanner
    client = http if http is not None else create_local_http_client()
    selected = tuple(checks)
    supported = {"xss", "sql", "csrf", "ssrf"}
    if not selected or any(check not in supported for check in selected):
        raise ValueError("Select one or more supported checks.")

    findings: list[Finding] = []
    try:
        for check in selected:
            if check == "xss":
                findings.extend(xss_scanner.scan_xss(target, http=client))
            elif check == "sql":
                findings.extend(sql_injection_tester.scan_sql_injection(target))
            elif check == "csrf":
                findings.extend(csrf_detector.scan_csrf(target, http=client))
            elif check == "ssrf":
                findings.extend(ssrf_tester.scan_ssrf(target))
    except ScanError:
        raise
    except Exception:
        raise ScanError("The local scan could not complete. Check the demo target and retry.") from None

    return ScanReport(
        target=_safe_target_url(target.canonical_url),
        created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        findings=tuple(findings),
        limitations=LIMITATIONS,
    )


def report_dict(report: ScanReport) -> dict[str, object]:
    return {
        "target": _safe_target_url(report.target),
        "created_at_utc": report.created_at_utc,
        "findings": [asdict(finding) for finding in report.findings],
        "limitations": list(report.limitations),
    }
