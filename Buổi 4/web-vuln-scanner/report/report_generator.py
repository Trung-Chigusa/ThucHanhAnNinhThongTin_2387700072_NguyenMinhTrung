"""Convert scan results to stable JSON-compatible report data."""

from scanners.scanner_service import ScanReport, report_dict


def generate_report(report: ScanReport) -> dict[str, object]:
    return report_dict(report)
