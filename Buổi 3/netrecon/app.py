"""Local-only Flask interface for the private-lab scanner."""

from collections import OrderedDict
from pathlib import Path
import secrets
from typing import Sequence

from flask import Flask, abort, make_response, render_template, request, session

from config import ConfigurationError, Settings, load_settings
from models import ScanResult
from modules.filter_utils import parse_ports
from modules.logging_setup import configure_logging
from modules.port_scanner import ScanError, scan_ports
from modules.rate_limiter import ProbeScheduler
from modules.reporting import build_report, report_json
from modules.scope import ScopeError, validate_target


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
_REPORT_CACHE_LIMIT = 20


def _protocols(value: str) -> tuple[str, ...]:
    if value == "tcp":
        return ("tcp",)
    if value == "udp":
        return ("udp",)
    if value == "both":
        return ("tcp", "udp")
    raise ValueError("Invalid protocol")


def create_app(
    settings: Settings | None = None,
    *,
    scheduler: ProbeScheduler | None = None,
) -> Flask:
    active_settings = settings or load_settings(env_file=BASE_DIR / ".env")
    active_scheduler = scheduler or ProbeScheduler(
        active_settings.rate_per_second, active_settings.max_concurrency
    )
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    app.extensions["netrecon.scheduler"] = active_scheduler
    reports: OrderedDict[str, bytes] = OrderedDict()
    app.extensions["netrecon.reports"] = reports

    scope_summary = ", ".join(str(network) for network in active_settings.allowlist)

    def csrf_token() -> str:
        token = session.get("csrf_token")
        if not isinstance(token, str) or not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def render_index(*, error: str | None = None, results: Sequence[ScanResult] = (), report_id: str | None = None, status: int = 200):
        response = make_response(
            render_template(
                "index.html",
                csrf_token=csrf_token(),
                scope_summary=scope_summary,
                rate_per_second=active_settings.rate_per_second,
                max_concurrency=active_settings.max_concurrency,
                timeout_seconds=active_settings.timeout_seconds,
                default_ports=",".join(str(port) for port in active_settings.default_ports),
                error=error,
                results=results,
                report_id=report_id,
            ),
            status,
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.after_request
    def set_no_store(response):
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/")
    def index():
        return render_index()

    @app.post("/scan")
    def scan():
        expected = session.get("csrf_token")
        submitted = request.form.get("_csrf_token", "")
        try:
            csrf_valid = isinstance(expected, str) and bool(expected) and secrets.compare_digest(expected, submitted)
        except TypeError:
            csrf_valid = False
        if not csrf_valid:
            return render_index(error="Invalid or expired form token.", status=400)

        try:
            target = validate_target(request.form.get("target", ""), active_settings)
            ports = parse_ports(request.form.get("ports", ""))
            protocols = _protocols(request.form.get("protocol", ""))
        except (ScopeError, ValueError, ConfigurationError):
            return render_index(error="Invalid target or scan options.", status=400)

        try:
            results = scan_ports(
                str(target),
                ports,
                protocols=protocols,
                settings=active_settings,
                scheduler=active_scheduler,
            )
            report = build_report(str(target), active_settings, results)
            payload = report_json(report)
        except ScanError:
            return render_index(error="Scan could not be completed.", status=500)
        except (ScopeError, ValueError):
            return render_index(error="Invalid target or scan options.", status=400)

        report_id = secrets.token_urlsafe(18)
        while report_id in reports:
            report_id = secrets.token_urlsafe(18)
        reports[report_id] = payload
        reports.move_to_end(report_id)
        while len(reports) > _REPORT_CACHE_LIMIT:
            reports.popitem(last=False)
        return render_index(results=results, report_id=report_id)

    @app.get("/report/<string:report_id>")
    def download_report(report_id: str):
        payload = reports.get(report_id)
        if payload is None:
            abort(404)
        response = make_response(payload)
        response.mimetype = "application/json"
        response.headers["Content-Disposition"] = f'attachment; filename="netrecon-{report_id}.json"'
        response.headers["Cache-Control"] = "no-store"
        return response

    return app


def run_local() -> None:
    configure_logging(LOG_DIR)
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_local()
