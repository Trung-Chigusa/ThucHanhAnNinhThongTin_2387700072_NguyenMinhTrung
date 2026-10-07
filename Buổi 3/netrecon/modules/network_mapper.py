"""Read the existing Windows IPv4 neighbor cache without probing hosts."""

import ipaddress
import logging
import re
import subprocess
from typing import Callable

from models import NeighborEntry


_INTERFACE = re.compile(r"^\s*Interface:\s*(\S+)(?:\s+---\s+0x[0-9a-f]+)?\s*$", re.IGNORECASE)
_MAC = re.compile(r"(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\Z", re.IGNORECASE)
_TYPES = {"dynamic", "static", "permanent"}
_LOGGER = logging.getLogger("netrecon")


def parse_arp_output(output: str) -> tuple[NeighborEntry, ...]:
    if not isinstance(output, str):
        return ()
    current_interface: str | None = None
    entries: list[NeighborEntry] = []
    for line in output.splitlines():
        interface_match = _INTERFACE.fullmatch(line)
        if interface_match:
            try:
                interface_address = ipaddress.ip_address(interface_match.group(1))
                current_interface = str(interface_address) if interface_address.version == 4 else None
            except ValueError:
                current_interface = None
            continue
        fields = line.split()
        if len(fields) != 3 or not _MAC.fullmatch(fields[1]) or fields[2].casefold() not in _TYPES:
            continue
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        if address.version != 4:
            continue
        entries.append(
            NeighborEntry(
                interface=current_interface,
                address=address,
                mac_address=fields[1].lower(),
                entry_type=fields[2].casefold(),
            )
        )
    return tuple(entries)


def get_neighbor_cache(
    *,
    timeout_seconds: float = 2.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[NeighborEntry, ...]:
    try:
        completed = runner(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        _LOGGER.warning("event=neighbor_cache count=0 status=404")
        return ()
    except subprocess.TimeoutExpired:
        _LOGGER.warning("event=neighbor_cache count=0 status=408")
        return ()
    except OSError:
        _LOGGER.warning("event=neighbor_cache count=0 status=500")
        return ()
    if completed.returncode != 0:
        _LOGGER.warning("event=neighbor_cache count=0 status=500")
        return ()
    return parse_arp_output(completed.stdout)
