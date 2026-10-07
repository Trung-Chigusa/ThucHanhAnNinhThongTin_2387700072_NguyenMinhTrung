"""Stable, local-only JSON report creation and persistence."""

from dataclasses import asdict
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from typing import Sequence
from uuid import uuid4

from config import Settings
from models import ScanReport, ScanResult
from modules.scope import validate_target


_SCOPE_SUMMARY = "Loopback and explicitly allowlisted private IPv4/IPv6 lab hosts only."
_LIMITATIONS = (
    "TCP connect and minimal UDP checks only; UDP silence is reported as open|filtered.",
    "Service names and exposure notes are local informational hints, not vulnerability assessments.",
    "Banner collection is passive, sends no application payload, and is limited to 512 bytes.",
)


def build_report(
    target: str,
    settings: Settings,
    results: Sequence[ScanResult],
    *,
    created_at: datetime | None = None,
) -> ScanReport:
    address = validate_target(target, settings)
    moment = created_at if created_at is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)
    timestamp = moment.isoformat(timespec="seconds").replace("+00:00", "Z")
    return ScanReport(
        target=str(address),
        created_at_utc=timestamp,
        scope_summary=_SCOPE_SUMMARY,
        rate_per_second=settings.rate_per_second,
        timeout_seconds=settings.timeout_seconds,
        results=tuple(results),
        limitations=_LIMITATIONS,
    )


def report_json(report: ScanReport) -> bytes:
    payload = json.dumps(asdict(report), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (payload + "\n").encode("utf-8")


def write_report(report: ScanReport, reports_dir: Path) -> Path:
    try:
        address = ipaddress.ip_address(report.target)
    except (TypeError, ValueError) as exc:
        raise ValueError("Report target must be a literal IP address") from exc
    if getattr(address, "scope_id", None) is not None:
        raise ValueError("Scoped IPv6 report targets are not supported")
    target_component = str(address).replace(":", "-")
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    filename = f"netrecon-{target_component}-{timestamp}-{uuid4().hex[:8]}.json"
    destination = directory / filename
    destination.write_bytes(report_json(report))
    return destination
