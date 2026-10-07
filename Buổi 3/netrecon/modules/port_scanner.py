"""Bounded TCP connect and minimal UDP reachability checks for one host."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
import socket
from typing import Sequence

from config import Settings
from models import Protocol, ScanResult
from modules.banner_grabber import grab_banner
from modules.rate_limiter import ProbeScheduler
from modules.scope import validate_target
from modules.service_detector import detect_service
from modules.vuln_checker import review_exposure


class ScanError(RuntimeError):
    """Raised when a scan cannot finish safely; details are kept private."""


def _socket_address(target, port: int):
    if target.version == 6:
        return (str(target), port, 0, 0)
    return (str(target), port)


def _make_socket(target, protocol: Protocol):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    family = socket.AF_INET6 if target.version == 6 else socket.AF_INET
    return socket.socket(family, kind)


def _connection_refused(exc: OSError) -> bool:
    return isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED or getattr(exc, "winerror", None) == 10061


def _network_unreachable(exc: OSError) -> bool:
    windows_error = getattr(exc, "winerror", None)
    return isinstance(exc, ConnectionRefusedError) or exc.errno in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH} or windows_error in {10051, 10061, 10065}


def _tcp_state(target, port: int, timeout_seconds: float, scheduler: ProbeScheduler) -> str:
    def connect():
        sock = _make_socket(target, "tcp")
        try:
            sock.settimeout(timeout_seconds)
            sock.connect(_socket_address(target, port))
            return "open"
        except (socket.timeout, TimeoutError):
            return "filtered"
        except OSError as exc:
            if _connection_refused(exc):
                return "closed"
            raise
        finally:
            sock.close()

    return scheduler.run_probe(connect)


def _udp_state(target, port: int, timeout_seconds: float, scheduler: ProbeScheduler) -> str:
    def probe():
        sock = _make_socket(target, "udp")
        try:
            sock.settimeout(timeout_seconds)
            sock.sendto(b"", _socket_address(target, port))
            sock.recvfrom(1)
            return "open"
        except (socket.timeout, TimeoutError):
            return "open|filtered"
        except OSError as exc:
            if _network_unreachable(exc):
                return "closed"
            raise
        finally:
            sock.close()

    return scheduler.run_probe(probe)


def _probe(target, port: int, protocol: Protocol, settings: Settings, scheduler: ProbeScheduler) -> ScanResult:
    if protocol == "tcp":
        state = _tcp_state(target, port, settings.timeout_seconds, scheduler)
    else:
        state = _udp_state(target, port, settings.timeout_seconds, scheduler)

    banner = None
    if protocol == "tcp" and state == "open":
        banner = grab_banner(
            target,
            port,
            scheduler=scheduler,
            timeout_seconds=settings.timeout_seconds,
            max_bytes=512,
        )
    service = detect_service(port, protocol, banner) if state == "open" else None
    notes = review_exposure(port, service) if protocol == "tcp" and state == "open" else ()
    return ScanResult(port=port, protocol=protocol, state=state, banner=banner, service=service, notes=notes)


def scan_ports(
    target: str,
    ports: Sequence[int],
    *,
    protocols: Sequence[Protocol],
    settings: Settings,
    scheduler: ProbeScheduler | None = None,
) -> tuple[ScanResult, ...]:
    address = validate_target(target, settings)
    if not ports:
        raise ValueError("At least one port is required")
    unique_ports: list[int] = []
    seen_ports: set[int] = set()
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Ports must be between 1 and 65535")
        if port not in seen_ports:
            seen_ports.add(port)
            unique_ports.append(port)
            if len(unique_ports) > 128:
                raise ValueError("At most 128 unique ports are allowed")
    if not protocols:
        raise ValueError("At least one protocol is required")
    unique_protocols: list[Protocol] = []
    for protocol in protocols:
        if protocol not in ("tcp", "udp"):
            raise ValueError("Protocol must be tcp or udp")
        if protocol not in unique_protocols:
            unique_protocols.append(protocol)
    active_scheduler = scheduler or ProbeScheduler(settings.rate_per_second, settings.max_concurrency)

    executor = ThreadPoolExecutor(max_workers=settings.max_concurrency)
    futures = [
        executor.submit(_probe, address, port, protocol, settings, active_scheduler)
        for protocol in unique_protocols
        for port in unique_ports
    ]
    results: list[ScanResult] = []
    try:
        for future in as_completed(futures):
            results.append(future.result())
    except KeyboardInterrupt:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise ScanError("Scan cancelled before completion") from None
    except Exception as exc:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        if isinstance(exc, ScanError):
            raise ScanError("Scan could not be completed") from None
        raise ScanError("Scan could not be completed") from None
    else:
        executor.shutdown(wait=True)

    return tuple(sorted(results, key=lambda result: (result.protocol, result.port)))
