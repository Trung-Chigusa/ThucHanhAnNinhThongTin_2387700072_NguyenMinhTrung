"""Strict parser for comma-separated ports and inclusive port ranges."""

import re


_SINGLE = re.compile(r"[0-9]+\Z")
_RANGE = re.compile(r"([0-9]+)-([0-9]+)\Z")


def parse_ports(raw: str, *, max_ports: int = 128) -> tuple[int, ...]:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("At least one port is required")
    if not isinstance(max_ports, int) or isinstance(max_ports, bool) or max_ports < 1:
        raise ValueError("max_ports must be a positive integer")

    ports: list[int] = []
    seen: set[int] = set()
    for segment in raw.split(","):
        item = segment.strip()
        if not item:
            raise ValueError("Port list contains an empty segment")
        if _SINGLE.fullmatch(item):
            start = end = int(item)
        else:
            match = _RANGE.fullmatch(item)
            if not match:
                raise ValueError("Port list contains a malformed segment")
            start, end = map(int, match.groups())
            if end < start:
                raise ValueError("Port ranges must be ascending")
        if start < 1 or end > 65535:
            raise ValueError("Ports must be between 1 and 65535")
        for port in range(start, end + 1):
            if port not in seen:
                seen.add(port)
                ports.append(port)
                if len(ports) > max_ports:
                    raise ValueError(f"At most {max_ports} unique ports are allowed")
    return tuple(ports)
