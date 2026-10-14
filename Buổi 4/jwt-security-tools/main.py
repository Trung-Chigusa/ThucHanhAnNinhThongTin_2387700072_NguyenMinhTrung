import argparse
import secrets
from api_gateway import APIGateway, run
from token_manager import TokenManager


def run_demo(port: int) -> None:
    secret = secrets.token_bytes(48)
    manager = TokenManager(secret, access_ttl_seconds=300)
    pair = manager.issue_tokens("lab-demo")
    app = APIGateway(manager.validator).create_app()
    @app.get("/")
    def home():
        from flask import Response
        return Response("""<!doctype html><meta charset='utf-8'><title>JWT Lab Demo</title>
<h1>JWT Security Tools — Local Demo</h1>
<p>Gateway is running on loopback. Access tokens and secrets are not shown.</p>
<p>Protected route: <code>GET /protected</code> (Bearer token required).</p>
<p>For the local demo, copy the short-lived access token printed in the server terminal and send it as a Bearer token.</p>
<p>Use the local lifecycle test command to verify issuance, refresh rotation, replay revocation, and gateway decisions.</p>""", mimetype="text/html")
    print(f"Local demo access token (expires in 300 seconds): {pair.access_token}")
    print(f"Local JWT gateway: http://127.0.0.1:{port}/")
    run(app, host="127.0.0.1", port=port)


def run_demo_check() -> int:
    manager = TokenManager(secrets.token_bytes(48), access_ttl_seconds=300)
    first = manager.issue_tokens("lab-demo")
    app = APIGateway(manager.validator).create_app()
    client = app.test_client()
    accepted = client.get("/protected", headers={"Authorization": f"Bearer {first.access_token}"}).status_code == 200
    second = manager.refresh(first.refresh_token)
    try:
        manager.refresh(first.refresh_token)
    except ValueError:
        replay_rejected = True
    else:
        replay_rejected = False
    descendant_rejected = False
    try:
        manager.refresh(second.refresh_token)
    except ValueError:
        descendant_rejected = True
    missing_rejected = client.get("/protected").status_code == 401
    print("JWT local lifecycle demo: " + ("PASS" if all((accepted, replay_rejected, descendant_rejected, missing_rejected)) else "FAIL"))
    print(f"protected_access={'accepted' if accepted else 'rejected'}; missing_bearer={'rejected' if missing_rejected else 'accepted'}")
    print(f"refresh_rotation={'issued' if second.refresh_token != first.refresh_token else 'failed'}; replay={'revoked' if replay_rejected and descendant_rejected else 'failed'}")
    return 0 if all((accepted, replay_rejected, descendant_rejected, missing_rejected)) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Local JWT security tools demo")
    parser.add_argument("--demo", action="store_true", help="start the loopback-only gateway")
    parser.add_argument("--demo-check", action="store_true", help="run a local token lifecycle and gateway demonstration")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    if args.demo_check:
        raise SystemExit(run_demo_check())
    if args.demo:
        run_demo(args.port)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()


