"""Configuration for the private-lab NetRecon tool."""

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
import os
from pathlib import Path
from typing import Mapping

try:
    from dotenv import dotenv_values
except ImportError:  # Keep scope validation usable before optional runtime setup.
    dotenv_values = None


DEFAULT_ALLOWLIST = (ip_network("127.0.0.1/32"), ip_network("::1/128"))
APPROVED_NETWORKS = (
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
)


class ConfigurationError(ValueError):
    """Raised when configuration is malformed or exceeds lab limits."""


@dataclass(frozen=True)
class Settings:
    allowlist: tuple[IPv4Network | IPv6Network, ...]
    blocklist: tuple[IPv4Network | IPv6Network, ...]
    default_ports: tuple[int, ...]
    rate_per_second: int
    timeout_seconds: float
    max_concurrency: int


def _dotenv_values(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    if not path.is_file():
        raise ConfigurationError("Environment file must be a file")
    if dotenv_values is None:
        raise ConfigurationError("python-dotenv is required to read an environment file")
    try:
        return {key: value for key, value in dotenv_values(path).items() if value is not None}
    except (OSError, UnicodeError, ValueError) as exc:
        raise ConfigurationError("Could not read environment file") from exc


def _networks(raw: str, name: str) -> tuple[IPv4Network | IPv6Network, ...]:
    if raw == "":
        if name == "allowlist":
            raise ConfigurationError("Allowlist cannot be empty")
        return ()
    result = []
    for item in raw.split(","):
        value = item.strip()
        if not value:
            raise ConfigurationError(f"{name} contains an empty entry")
        try:
            network = ip_network(value, strict=True)
        except ValueError as exc:
            raise ConfigurationError(f"{name} contains an invalid network") from exc
        if name == "allowlist" and not any(
            network.version == approved.version and network.subnet_of(approved)
            for approved in APPROVED_NETWORKS
        ):
            raise ConfigurationError("Allowlist networks must stay inside approved lab ranges")
        result.append(network)
    return tuple(result)


def _bounded_number(values: Mapping[str, str], key: str, default: str, low: float, high: float, cast):
    try:
        value = cast(values.get(key, default))
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{key} must be a number") from exc
    if not low <= value <= high:
        raise ConfigurationError(f"{key} is outside its permitted range")
    return value


def load_settings(
    env_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Load .env values and apply process environment overrides."""
    values = _dotenv_values(env_file)
    values.update(os.environ if environ is None else environ)

    allowlist = (
        _networks(values["NETRECON_ALLOWLIST"], "allowlist")
        if "NETRECON_ALLOWLIST" in values
        else DEFAULT_ALLOWLIST
    )
    blocklist = _networks(values.get("NETRECON_BLOCKLIST", ""), "blocklist")
    rate = _bounded_number(values, "NETRECON_RATE_PER_SECOND", "2", 1, 10, int)
    timeout = _bounded_number(values, "NETRECON_TIMEOUT_SECONDS", "1.5", 0.2, 3, float)
    concurrency = _bounded_number(values, "NETRECON_MAX_CONCURRENCY", "4", 1, 4, int)

    return Settings(
        allowlist=allowlist,
        blocklist=blocklist,
        default_ports=(22, 80, 443),
        rate_per_second=rate,
        timeout_seconds=timeout,
        max_concurrency=concurrency,
    )
