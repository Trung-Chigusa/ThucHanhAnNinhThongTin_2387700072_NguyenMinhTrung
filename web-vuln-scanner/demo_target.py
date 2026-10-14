"""Intentionally vulnerable but harmless local fixture for Lab 04."""

from flask import Flask, Response, request


def create_demo_app() -> Flask:
    app = Flask(__name__)

    @app.get("/search")
    def search():
        query = request.args.get("q", "")
        # Deliberately raw reflection for a local output-encoding demonstration.
        return Response(
            "<!doctype html><html><body>"
            f"<h1>Local search</h1><section>{query}</section>"
            '<form method="post" action="/save"><input name="name"></form>'
            "</body></html>",
            mimetype="text/html",
        )

    @app.get("/lookup")
    def lookup():
        return f"Local demo received: {request.args.get('id', '')}", 200

    @app.get("/form")
    def form():
        return (
            '<!doctype html><form method="post" action="/save">'
            '<input name="name"></form>',
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/inspect")
    def inspect():
        # Intentionally records no destination and never makes a server-side request.
        return f"Local demo received: {request.args.get('url', '')}", 200

    @app.post("/save")
    def save():
        return "Local training fixture; no state was changed.", 200

    return app


def run(host: str = "127.0.0.1", port: int = 5001) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("The training fixture can bind only to loopback.")
    create_demo_app().run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run()
