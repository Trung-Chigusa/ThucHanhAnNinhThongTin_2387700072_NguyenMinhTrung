from flask import Flask, jsonify, request
from jwt_validator import JWTValidator

class APIGateway:
    def __init__(self, validator: JWTValidator):
        self._validator = validator

    def create_app(self) -> Flask:
        app = Flask(__name__)
        app.config["DEBUG"] = False

        @app.get("/protected")
        def protected():
            header = request.headers.get("Authorization", "")
            parts = header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({"error": "unauthorized"}), 401
            result = self._validator.validate(parts[1])
            if not result.valid or result.payload is None:
                return jsonify({"error": "unauthorized"}), 401
            return jsonify({"message": "authenticated", "subject": result.payload.get("sub")}), 200

        return app

def run(app: Flask | None = None, *, host: str = "127.0.0.1", port: int = 5000) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("gateway may bind only to loopback")
    (app or Flask(__name__)).run(host=host, port=port, debug=False, use_reloader=False)
