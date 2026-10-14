# Lab 04 Security Tools - Design Specification

## Goal

Complete both practical projects in `lab-04.pdf` as runnable, testable Python coursework: a local Web Vulnerability Scanner and a local JWT security toolkit. Provide real run evidence, including screenshots of passing tests and both local demos, for the student to review before any Git commit or push.

## Context and placement

- The assignment source is the root-level `lab-04.pdf`.
- `web-vuln-scanner/` and `jwt-security-tools/` are separate projects at the repository root, matching the PDF.
- Existing Buổi 1 and Buổi 3 files and the current uncommitted work are out of scope and must remain untouched.
- The current checkout is on `main`, has unrelated working-tree changes, and is six commits behind `origin/main`. Implementation must use an isolated worktree based on the current remote default branch; the supplied PDF may be read from the original checkout.
- The PDF includes public scan examples and simplified code with unsafe patterns. This coursework will preserve the requested learning outcomes while keeping network activity loopback-only and using safe, local examples.

## Web Vulnerability Scanner

### Components and behavior

- `scanners/xss_scanner.py` sends a harmless unique marker through query parameters to an explicitly local target. It reports unescaped marker reflection as a potential XSS finding; it does not execute JavaScript or claim exploitability from reflection alone.
- `scanners/sql_injection_tester.py` checks URL query values for a small set of recognizable SQLi patterns and reports heuristic candidates. It does not issue destructive SQL, connect to a database, or claim database compromise.
- `scanners/csrf_detector.py` parses supplied/local HTML forms and looks for hidden anti-CSRF tokens. It reports forms without a recognized token as candidates for manual review, not proof of exploitable CSRF.
- `scanners/ssrf_tester.py` inspects URL parameters for localhost, loopback, private, and link-local address indicators. It makes no request to parameter-supplied destinations.
- A shared target validator accepts only HTTP(S) URLs whose host resolves to loopback. Hostnames are resolved once and every resolved address must be loopback; redirects are disabled so a local endpoint cannot redirect the scanner elsewhere. Invalid and non-loopback targets fail before requests are sent.
- `report/report_generator.py` creates a stable JSON report with scan time, local target, finding type, location, evidence, confidence, risk, and remediation. Candidate findings retain their heuristic/manual-review wording.
- `main.py` runs the same checks from the command line. `ui/app.py` serves the browser interface on `127.0.0.1` only, with debug/reloader disabled and request validation shared with the CLI.
- A deliberately vulnerable fixture under the project provides repeatable local demonstrations of reflected HTML, a form without a CSRF token, and query strings that trigger static SQLi/SSRF heuristics. It binds only to loopback and is clearly marked for training.

### Files

- `web-vuln-scanner/{__init__.py,main.py,requirements.txt}`
- `web-vuln-scanner/scanners/{__init__.py,xss_scanner.py,sql_injection_tester.py,csrf_detector.py,ssrf_tester.py,target_scope.py}`
- `web-vuln-scanner/report/{__init__.py,report_generator.py}`
- `web-vuln-scanner/ui/{__init__.py,app.py,templates/index.html,templates/result.html}`
- `web-vuln-scanner/demo_target.py` for the intentionally vulnerable loopback fixture
- `web-vuln-scanner/tests/` for scanner, scope, report, CLI, and UI tests
- `web-vuln-scanner/minh-chung/` for genuine test and local UI/demo screenshots plus raw test output
- `web-vuln-scanner/README.md` for setup, safe demo commands, evidence, and limitations

## JWT Security Toolkit

### Components and behavior

- `jwt_validator/validator.py` verifies tokens with a fixed, explicit algorithm allowlist (HS256 for this local lab), a configured local secret, required expiration, and applicable issuer/audience checks. It rejects `none`, algorithm confusion, malformed tokens, invalid signatures, and expired tokens. Decoding without signature verification is informational only and is never treated as validation.
- `jwt_cracker/cracker.py` checks only an explicitly supplied local token against a caller-supplied wordlist, sequentially with a configurable small candidate limit. It has no network feature, does not download wordlists, and displays that a match is a weak local demo secret.
- `oauth_client/client.py` builds authorization-code requests with cryptographically random state and PKCE S256, validates the returned state, and accepts an injected local/test transport. No real provider credentials or outbound OAuth flow are included in the demo.
- `token_manager/manager.py` issues short-lived access tokens and opaque refresh tokens, rotates refresh tokens on use, and revokes a token family after refresh-token reuse. State is in-memory for the lab and resets at process restart.
- `api_gateway/gateway.py` exposes a protected Flask route that verifies bearer tokens using the validator and binds to `127.0.0.1` with debug/reloader disabled.
- `main.py` runs a local demonstration with an ephemeral secret and prints sample tokens only to the terminal. No actual secrets or tokens are written to source, screenshots, reports, or tracked files.
- `pytest.ini`, requirements, and tests match the requested layout while keeping all token and HTTP tests local.

### Files

- `jwt-security-tools/{main.py,pytest.ini,requirements.txt,README.md}`
- `jwt-security-tools/jwt_validator/{__init__.py,validator.py}`
- `jwt-security-tools/jwt_cracker/{__init__.py,cracker.py}`
- `jwt-security-tools/oauth_client/{__init__.py,client.py}`
- `jwt-security-tools/token_manager/{__init__.py,manager.py}`
- `jwt-security-tools/api_gateway/{__init__.py,gateway.py}`
- `jwt-security-tools/tests/` for validator, cracker, OAuth, token lifecycle, and gateway behavior
- `jwt-security-tools/minh-chung/` for genuine test output and local gateway/token screenshots with all bearer values redacted

## Error handling and local data

- Both web applications bind only to loopback, disable Flask debug/reload, and validate inputs at their public entry points.
- Tests use local fixtures or mocked transports. The scanner rejects non-loopback destinations before network activity; the SSRF check itself never fetches user-supplied URLs.
- Invalid tokens and invalid scan targets fail closed with simple, non-sensitive errors. Logs and reports omit authorization headers, cookies, secrets, and complete bearer tokens.
- `.gitignore` entries keep virtual environments, generated reports, local secrets, logs, caches, and temporary token data out of Git. Required screenshots contain no credentials or live tokens.

## Verification and acceptance

1. Each project installs from its own `requirements.txt` and its documented commands run from that project directory.
2. Scanner unit tests cover all four detectors, report structure, malformed input, loopback acceptance, and rejection of public hosts, hostnames resolving outside loopback, redirects, and unsupported schemes before a request is made.
3. Scanner integration tests use only a loopback fixture and demonstrate the expected candidate findings without executing a payload.
4. JWT tests cover valid, expired, malformed, wrong-signature, `none`, and unsupported-algorithm tokens; cracker limits; OAuth state/PKCE; refresh rotation/reuse/revocation; and authorized/unauthorized gateway requests.
5. All test output is captured from actual runs. Screenshots show passing test summaries and actual local UI/API demo results; they are not reconstructed terminal text.
6. Both README files explain the commands, expected local evidence, candidate-versus-confirmed finding limits, and that neither project is a production scanner or identity provider.
7. Review confirms no source, logs, screenshots, or reports contain real credentials, secrets, or unredacted access/refresh tokens.
8. The student reviews the isolated worktree diff and evidence before authorizing any commit or push. No GitHub changes occur during implementation.

## Out of scope

- Scanning public websites or non-loopback targets; exploiting vulnerabilities; sending active XSS scripts; making SQL queries; contacting internal/cloud metadata endpoints; following redirects; or running SSRF requests.
- Brute forcing remote tokens, fetching wordlists, or testing tokens against a remote API.
- Integrating a live OAuth provider, storing production users/sessions, or deploying either Flask application.
- Modifying existing coursework or pushing any code before the student's review and explicit follow-up request.
