# JWTSecure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the JWT security toolkit portion of Lab 04 as a tested local application demonstrating validation, bounded local secret checking, safe OAuth request construction, token lifecycle, and a JWT-protected API gateway.

**Architecture:** The validator is the shared trust boundary for token manager and gateway. The cracker handles only caller-supplied local data, OAuth uses injected transports and PKCE/state, and the demo gateway binds to loopback with an ephemeral secret.

**Tech Stack:** Python 3.10+, PyJWT, requests, Flask, pytest.

**Spec:** [2026-10-14-lab-04-security-tools-design.md](../specs/2026-10-14-lab-04-security-tools-design.md)

## Global Constraints

- JWT validation pins `HS256`, requires expiration, and checks configured issuer/audience when present.
- Cracking is local-only, sequential, uses a supplied wordlist, and is capped at a configurable small candidate count.
- OAuth constructs Authorization Code + state + PKCE S256 requests and uses an injected transport; no live provider integration.
- Refresh tokens rotate; reuse revokes the token family; state is in-memory.
- The gateway binds only to `127.0.0.1`; Flask debug and reloader stay disabled.
- No actual secret, bearer token, refresh token, or authorization header is written to source, logs, reports, or screenshots.
- Keep changes within `jwt-security-tools/` in an isolated worktree; do not commit or push before the student reviews the result.

## Review Focus

- `alg=none`, unsupported algorithms, malformed tokens, invalid signatures, and expired tokens fail closed; pin in Task 1 tests.
- Missing, unreadable, or oversized wordlists fail safely without an uncapped run; pin in Task 2 tests.
- OAuth state mismatch, missing verifier, and PKCE challenge calculation errors prevent token exchange; pin in Task 2 tests.
- Refresh replay revokes the family, including previously rotated descendants; pin in Task 3 tests.
- Missing, malformed, wrong-scheme, or expired gateway bearer tokens never reveal exception text or token contents; pin in Task 3 tests.

---

### Task 1: Project setup and JWT validator

**Files:**
- Create `jwt-security-tools/{__init__.py,requirements.txt,pytest.ini}`
- Create `jwt-security-tools/jwt_validator/{__init__.py,validator.py}`
- Create `jwt-security-tools/tests/{__init__.py,test_validator.py}`

**Interfaces:**
- `JWTValidator(secret: str | bytes, *, issuer: str | None = None, audience: str | None = None)` accepts only non-empty local secrets.
- `validate(token: str) -> ValidationResult` returns `{valid: bool, payload: dict | None, reason: str | None}`; it decodes only with `algorithms=["HS256"]`, requires `exp`, and applies configured issuer/audience.
- `ValidationResult` is a frozen record; errors do not include token or secret values.

- [ ] Write tests `test_accepts_valid_hs256_with_expiration`, `test_rejects_expired_token`, `test_rejects_wrong_signature`, `test_rejects_malformed_token`, `test_rejects_alg_none`, `test_rejects_unsupported_algorithm`, `test_requires_expiration`, and `test_checks_issuer_and_audience_when_configured`.
- [ ] Run `py -3 -m pytest tests/test_validator.py -q`; confirm expected failures before implementation.
- [ ] Implement the validator with strict fixed algorithm and claim options; do not perform an unverified decode as a trust decision.
- [ ] Rerun validator tests and confirm every invalid token returns a safe failure result.
- [ ] Add `.gitignore` entries for `.venv/`, `__pycache__/`, `*.pyc`, `.env`, local logs, and generated evidence scratch files; do not ignore required committed screenshots.

### Task 2: Bounded local cracker and OAuth client

**Files:**
- Create `jwt-security-tools/jwt_cracker/{__init__.py,cracker.py}`
- Create `jwt-security-tools/oauth_client/{__init__.py,client.py}`
- Create `jwt-security-tools/tests/{test_cracker.py,test_oauth_client.py}`

**Interfaces:**
- `JWTCracker(token: str, *, max_candidates: int = 1000, max_wordlist_bytes: int = 1_048_576)` exposes `crack(wordlist_path: Path) -> CrackResult`; it rejects files over 1 MiB, reads at most `max_candidates`, tests HS256 locally in order, and has no thread pool/network method.
- `CrackResult` records `matched: bool`, `candidate_index: int | None`, and `candidate: str | None`; caller controls whether the weak candidate is printed.
- `OAuthClient(client_id: str, authorization_url: str, redirect_uri: str)` exposes `create_authorization_request(scopes: Sequence[str]) -> AuthorizationRequest` and `validate_callback(query: Mapping[str, str], expected_state: str) -> str`; the request includes random `state`, `code_challenge`, and `code_challenge_method="S256"`.
- `exchange_code(code: str, request: AuthorizationRequest, *, token_endpoint: str, transport: HTTPTransport) -> Mapping[str, object]` posts the authorization code, redirect URI, client ID, and PKCE verifier through the injected transport. No default network transport is provided; tests use a fake transport.

- [ ] Write tests `test_cracker_finds_secret_in_supplied_wordlist`, `test_cracker_returns_no_match`, `test_cracker_stops_at_candidate_limit`, `test_cracker_rejects_missing_wordlist`, `test_cracker_rejects_oversized_wordlist`, `test_oauth_request_uses_state_and_s256_pkce`, `test_oauth_state_is_unpredictable`, `test_callback_rejects_state_mismatch`, `test_callback_rejects_missing_code`, and `test_code_exchange_sends_pkce_verifier_through_fake_transport`.
- [ ] Run cracker and OAuth tests to confirm expected missing-module failures.
- [ ] Implement local-only wordlist checking and Authorization Code request/callback validation with cryptographic state and verifier generation.
- [ ] Rerun Task 2 tests; assert no real HTTP client call occurs without an injected transport.

### Task 3: Token manager and API gateway

**Files:**
- Create `jwt-security-tools/token_manager/{__init__.py,manager.py}`
- Create `jwt-security-tools/api_gateway/{__init__.py,gateway.py}`
- Create `jwt-security-tools/tests/{test_token_manager.py,test_api_gateway.py}`

**Interfaces:**
- `TokenPair` is a frozen record with `access_token: str`, `refresh_token: str`, and `expires_at: int`.
- `TokenManager(secret: str | bytes, *, access_ttl_seconds: int = 600, clock=time.time)` issues HS256 access tokens and random opaque refresh tokens.
- `issue_tokens(subject: str) -> TokenPair`, `refresh(refresh_token: str) -> TokenPair`, and `revoke(refresh_token: str) -> bool` implement rotation, replay-family revocation, and explicit revocation.
- `APIGateway(validator: JWTValidator).create_app() -> Flask` exposes `GET /protected` and returns a non-sensitive `401` for all invalid bearer input.
- `run(host="127.0.0.1", port=5000)` refuses a non-loopback host.

- [ ] Write tests `test_issue_returns_access_and_refresh_tokens`, `test_refresh_rotates_token`, `test_reuse_revokes_family_and_descendants`, `test_revoke_invalidates_refresh_token`, `test_expired_access_token_rejected`, `test_gateway_accepts_valid_bearer`, `test_gateway_rejects_missing_and_malformed_bearer`, and `test_gateway_binds_loopback_by_default`.
- [ ] Run lifecycle/gateway tests to confirm expected missing-module failures.
- [ ] Implement opaque refresh-token storage with family identifiers and revocation state; keep all state in memory.
- [ ] Implement gateway route and loopback-only run entry; do not log bearer values.
- [ ] Rerun Tasks 1–3 tests and confirm gateway requests use Flask's local test client only.

### Task 4: CLI, README, and real PoC evidence

**Files:**
- Create `jwt-security-tools/main.py`, `jwt-security-tools/README.md`
- Create `jwt-security-tools/minh-chung/01-tests.png`, `02-gateway-demo.png`, `03-token-lifecycle.png`, and `test-output.txt`

- [ ] Implement `main.py --demo` to generate an ephemeral secret, issue a short-lived local token, and start the gateway on `127.0.0.1:5000`; never persist tokens or secrets.
- [ ] Write README install/test/demo/curl instructions matching the PDF and explain local-only limits, fixed algorithm, and in-memory refresh state.
- [ ] Run pytest and capture exact text output; then capture screenshots of passing tests and actual local gateway/token lifecycle behavior with all token values hidden at capture time.
- [ ] Verify screenshots correspond to the final run, contain no credentials or bearer values, and are saved under `minh-chung/`.
- [ ] Run `py -3 -m pytest -q`, `git diff --check`, and the loopback-only gateway check; report results without committing or pushing.
