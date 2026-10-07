"""Scope validation that is deliberately independent of network access."""

from ipaddress import IPv4Address, IPv6Address, ip_address

from config import APPROVED_NETWORKS, Settings


class ScopeError(ValueError):
    """Raised when a target is not an approved literal lab address."""


def validate_target(raw: str, settings: Settings) -> IPv4Address | IPv6Address:
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        raise ScopeError("Target must be a literal IP address")
    try:
        address = ip_address(raw)
    except ValueError as exc:
        raise ScopeError("Target must be a literal IP address") from exc

    if not any(
        address.version == network.version and address in network
        for network in APPROVED_NETWORKS
    ):
        raise ScopeError("Target is outside approved private lab ranges")
    if not any(
        address.version == network.version and address in network
        for network in settings.allowlist
    ):
        raise ScopeError("Target is not in the configured allowlist")
    if any(
        address.version == network.version and address in network
        for network in settings.blocklist
    ):
        raise ScopeError("Target is blocked by configuration")
    return address
