"""Command-line entry points for the bounded private-lab scanner."""

import argparse
from pathlib import Path
import sys
from typing import Sequence

from config import ConfigurationError, load_settings
from modules.filter_utils import parse_ports
from modules.logging_setup import configure_logging
from modules.network_mapper import get_neighbor_cache
from modules.port_scanner import ScanError, scan_ports
from modules.reporting import build_report, write_report
from modules.scope import ScopeError, validate_target


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netrecon", description="Private-lab host checks")
    commands = parser.add_subparsers(dest="command")

    scan = commands.add_parser("scan", help="check one allowlisted private host")
    scan.add_argument("--target", required=True, help="one literal allowlisted IPv4 or IPv6 address")
    scan.add_argument("--ports", default="22,80,443", help="comma-separated ports and ranges (max 128)")
    scan.add_argument("--protocol", choices=("tcp", "udp", "both"), default="tcp")

    commands.add_parser("neighbors", help="show the local Windows neighbor cache")
    commands.add_parser("serve", help="start the localhost-only web interface")
    return parser


def _protocols(value: str) -> tuple[str, ...]:
    return ("tcp", "udp") if value == "both" else (value,)


def _print_scan_summary(target: str, results, report_path: Path) -> None:
    print(f"Target: {target}")
    for result in results:
        service = f" service={result.service}" if result.service else ""
        print(f"{result.protocol}/{result.port} {result.state}{service}")
        for note in result.notes:
            print(f"  {note}")
    print(f"Report saved: {report_path}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    if args.command == "serve":
        try:
            from app import run_local

            run_local()
            return 0
        except Exception:
            print("Unable to start the local web interface.", file=sys.stderr)
            return 1

    try:
        logger = configure_logging(LOG_DIR)
    except OSError:
        print("Unable to initialize local logging.", file=sys.stderr)
        return 1

    if args.command == "neighbors":
        entries = get_neighbor_cache()
        for entry in entries:
            interface = entry.interface or "-"
            entry_type = entry.entry_type or "-"
            print(f"{interface} {entry.address} {entry.mac_address} {entry_type}")
        logger.info("event=neighbors_complete count=%d status=200", len(entries))
        return 0

    try:
        settings = load_settings()
        ports = parse_ports(args.ports)
        target = validate_target(args.target, settings)
        protocols = _protocols(args.protocol)
        results = scan_ports(
            str(target),
            ports,
            protocols=protocols,
            settings=settings,
        )
        report = build_report(str(target), settings, results)
        report_path = write_report(report, REPORTS_DIR)
    except (ConfigurationError, ScopeError, ValueError):
        logger.info("event=scan_rejected count=0 status=400")
        print("Invalid target, configuration, or scan options.", file=sys.stderr)
        return 2
    except ScanError:
        logger.info("event=scan_failed count=0 status=500")
        print("Scan could not be completed.", file=sys.stderr)
        return 1
    except OSError:
        logger.info("event=report_failed count=0 status=500")
        print("Unable to save the local report.", file=sys.stderr)
        return 1

    _print_scan_summary(str(target), results, report_path)
    logger.info("event=scan_complete count=%d status=200", len(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
