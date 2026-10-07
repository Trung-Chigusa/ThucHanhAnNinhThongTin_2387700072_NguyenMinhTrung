"""Typed, immutable records shared by scanner and reporting code."""

from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Literal

Protocol = Literal["tcp", "udp"]
PortState = Literal["open", "closed", "filtered", "open|filtered"]


@dataclass(frozen=True)
class ScanResult:
    port: int
    protocol: Protocol
    state: PortState
    banner: str | None = None
    service: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class NeighborEntry:
    interface: str | None
    address: IPv4Address
    mac_address: str
    entry_type: str | None


@dataclass(frozen=True)
class ScanReport:
    target: str
    created_at_utc: str
    scope_summary: str
    rate_per_second: int
    timeout_seconds: float
    results: tuple[ScanResult, ...]
    limitations: tuple[str, ...]
