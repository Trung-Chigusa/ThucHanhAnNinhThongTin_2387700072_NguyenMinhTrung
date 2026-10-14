"""Loopback-only browser UI for the local WebVulnScanner lab."""

from flask import Flask, render_template, request

from scanners.scanner_service import ScanError, scan_target
from scanners.target_scope import TargetError, validate_local_target


_CHECKS = {"xss", "sql", "csrf", "ssrf"}


def create_app(scanner=scan_target) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/scan")
    def scan():
        target_text = request.form.get("target", "")
        checks = request.form.getlist("checks")
        if not checks or any(check not in _CHECKS for check in checks):
            return render_template(
                "index.html", target=target_text, error="Select one or more valid checks."
            ), 400
        try:
            target = validate_local_target(target_text)
        except TargetError as exc:
            return render_template("index.html", target=target_text, error=str(exc)), 400
        try:
            report = scanner(target, checks=tuple(checks))
        except ScanError as exc:
            return render_template("index.html", target=target_text, error=str(exc)), 502
        except Exception:
            return render_template(
                "index.html",
                target=target_text,
                error="The local scan could not complete. Check the demo target and retry.",
            ), 502
        return render_template("result.html", report=report)

    return app


def run(host: str = "127.0.0.1", port: int = 5000) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("The scanner UI can bind only to loopback.")
    create_app().run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run()
