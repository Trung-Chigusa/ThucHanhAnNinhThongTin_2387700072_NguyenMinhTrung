"""Command-line entry point for local-only WebVulnScanner demonstrations."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence, TextIO

from report.report_generator import generate_report
from scanners.scanner_service import ScanError, scan_target
from scanners.target_scope import TargetError, validate_local_target


DEMO_TARGET = (
    "http://127.0.0.1:5001/search?"
    "id=1%27+OR+1%3D1&url=http%3A%2F%2F169.254.169.254%2Flatest"
)
ALL_CHECKS = ("xss", "sql", "csrf", "ssrf")


def main(
    argv: Sequence[str] | None = None,
    *,
    scanner=scan_target,
    output: TextIO | None = None,
) -> int:
    stream = output or sys.stdout
    parser = argparse.ArgumentParser(description="Scan an explicitly local lab target.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="HTTP(S) URL on loopback only")
    group.add_argument("--demo", action="store_true", help="use the local demo target on port 5001")
    parser.add_argument("--check", choices=ALL_CHECKS, action="append", help="check to run; repeatable")
    args = parser.parse_args(argv)
    raw_target = DEMO_TARGET if args.demo else args.target
    try:
        target = validate_local_target(raw_target)
    except TargetError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=stream)
        return 2
    try:
        report = scanner(target, checks=tuple(args.check or ALL_CHECKS))
    except (ScanError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=stream)
        return 2
    print(json.dumps(generate_report(report), ensure_ascii=False, indent=2), file=stream)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
