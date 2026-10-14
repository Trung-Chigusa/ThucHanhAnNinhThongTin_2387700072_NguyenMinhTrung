# WebVulnScanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the Web Vulnerability Scanner portion of Lab 04 as a tested, loopback-only CLI and browser demo with genuine PoC screenshots.

**Architecture:** Four small detector modules share one strict local-target validator and one finding/report shape. The CLI and Flask UI call the same scanner service; an intentionally vulnerable fixture listens on loopback for repeatable evidence.

**Tech Stack:** Python 3.10+, Flask, requests, Python standard library, unittest.

**Spec:** [2026-10-14-lab-04-security-tools-design.md](../specs/2026-10-14-lab-04-security-tools-design.md)

## Global Constraints

- Only HTTP(S) loopback targets are accepted; all resolved addresses must be loopback, and redirects are disabled.
- XSS uses a harmless marker and reports unescaped reflection as a candidate; no executable payload is sent.
- SQLi checks are heuristic; they do not issue SQL or claim database compromise.
- CSRF checks inspect forms and report candidate findings for manual review.
- SSRF checks inspect parameter values and make no request to those values.
- UI and fixture bind to `127.0.0.1`; Flask debug and reloader stay disabled.
- Reports, logs, evidence, and tests contain no credentials or external-target data.
- Keep all changes within `web-vuln-scanner/` in an isolated worktree; do not commit or push before the student reviews the result.

## Review Focus

- Public hosts, mixed public/loopback DNS, malformed URLs, and non-HTTP schemes are rejected before a network request; pin in Task 1 tests.
- Redirect responses never trigger a second request to their Location value; pin in Task 2 tests.
- An existing query string is preserved and encoded payload values are parsed consistently; pin in Task 2 detector tests.
- Empty or malformed HTML and forms with token names in different casing do not crash or create false protected results; pin in Task 2 CSRF tests.
- A response that reflects only an encoded marker is not reported as unescaped XSS; pin in Task 2 XSS tests.
- Invalid UI method, missing target, and unexpected scanner errors return a safe user-visible result without traceback or secret leakage; pin in Task 3 web tests.

---

### Task 1: Project skeleton and local target scope

**Files:**
- Create `web-vuln-scanner/{__init__.py,requirements.txt}`
- Create `web-vuln-scanner/scanners/{__init__.py,target_scope.py}`
- Create `web-vuln-scanner/tests/test_target_scope.py`

**Interfaces:**
- `validate_local_target(raw_url: str, resolver=socket.getaddrinfo) -> LocalTarget` returns a frozen target record with canonical URL, host, port, path, and query; raises `TargetError` before any HTTP call.
- `LocalTarget` carries the validated components and the chosen loopback address. For a hostname such as `localhost`, construct the request URL with that numeric loopback address so the HTTP client cannot resolve the name again after validation.

- [ ] Write tests `test_accepts_loopback_ipv4_and_localhost`, `test_rejects_public_ipv4_and_ipv6`, `test_rejects_hostname_with_any_non_loopback_answer`, `test_pins_localhost_to_resolved_loopback_address`, `test_rejects_invalid_scheme_and_url`, `test_rejects_credentials_and_fragments`, and `test_resolution_failure_fails_closed`.
- [ ] Run `py -3 -m unittest discover -s tests -p test_target_scope.py -v`; confirm the expected missing-module failures.
- [ ] Implement `LocalTarget`, `TargetError`, and `validate_local_target`; perform no network request during validation except DNS resolution of a hostname and reject if any answer is non-loopback.
- [ ] Rerun the target-scope tests and confirm all pass.
- [ ] Add project-local ignore rules for `.venv/`, `__pycache__/`, `*.pyc`, `report/*.json`, and `minh-chung/*.log`; confirm no global ignore or existing file was modified.

### Task 2: Four detectors and report generation

**Files:**
- Create `web-vuln-scanner/scanners/{xss_scanner.py,sql_injection_tester.py,csrf_detector.py,ssrf_tester.py,scanner_service.py}`
- Create `web-vuln-scanner/report/{__init__.py,report_generator.py}`
- Create `web-vuln-scanner/tests/{test_xss.py,test_sql_injection.py,test_csrf.py,test_ssrf.py,test_report.py}`

**Interfaces:**
- `Finding` is a frozen record containing `type`, `location`, `evidence`, `confidence`, `risk`, and `remediation`.
- `scan_xss(target: LocalTarget, http=requests) -> list[Finding]` sends one random, scriptless marker in query parameter `q`; only raw unescaped marker reflection yields a candidate.
- `scan_sql_injection(target: LocalTarget) -> list[Finding]` scans decoded query values against the fixed harmless pattern set and never performs HTTP or SQL.
- `scan_csrf(target: LocalTarget, http=requests) -> list[Finding]` fetches the validated local page once and parses HTML forms with `HTMLParser`.
- `scan_ssrf(target: LocalTarget) -> list[Finding]` flags query values containing loopback, private, link-local, or localhost indicators; it never fetches those values.
- `scan_target(target: LocalTarget, *, checks: Sequence[str], http=requests) -> ScanReport` calls only selected checks and returns findings plus limitations.
- `generate_report(report: ScanReport) -> dict[str, object]` returns stable JSON-compatible data without headers, cookies, or credentials.

- [ ] Write detector/report tests first: `test_xss_reports_raw_marker_reflection`, `test_xss_ignores_html_encoded_marker`, `test_xss_does_not_follow_redirects`, `test_sql_flags_only_known_patterns`, `test_sql_detector_makes_no_request`, `test_csrf_flags_form_without_token`, `test_csrf_accepts_case_insensitive_hidden_token`, `test_csrf_handles_empty_and_malformed_html`, `test_ssrf_flags_local_address_parameter`, `test_ssrf_makes_no_request`, and `test_report_has_confidence_risk_and_remediation`.
- [ ] Run those test files and confirm failure because the detector/report modules are absent.
- [ ] Implement the `Finding` and `ScanReport` records and the XSS, SQLi, CSRF, and SSRF functions with the interfaces above.
- [ ] Rerun detector/report tests; confirm static detectors produce no network calls and only XSS/CSRF use the validated target.
- [ ] Add tests for preserving existing query parameters and no finding for escaped reflections; rerun the complete Task 2 test set.

### Task 3: CLI, local fixture, and browser UI

**Files:**
- Create `web-vuln-scanner/{main.py,demo_target.py}`
- Create `web-vuln-scanner/ui/{__init__.py,app.py,templates/index.html,templates/result.html}`
- Create `web-vuln-scanner/tests/{test_cli.py,test_ui.py,test_demo_target.py}`

**Interfaces:**
- `main.py` supports `--target`, repeated `--check`, and `--demo`; output is formatted JSON and exit status is nonzero for invalid target input.
- `create_app(scanner=scan_target) -> Flask` provides `GET /` and `POST /scan`; POST validates the target and selected checks through Task 1/2 interfaces and renders escaped report fields.
- `demo_target.py` exposes `create_demo_app()` with loopback-only run defaults and harmless routes `/search?q=`, `/lookup?id=`, `/form`, and `/inspect?url=`.

- [ ] Write tests `test_cli_rejects_public_target_before_scan`, `test_cli_outputs_json_for_local_demo`, `test_ui_home_loads`, `test_ui_rejects_public_target`, `test_ui_displays_candidate_and_remediation_safely`, `test_ui_handles_scanner_error_without_traceback`, and fixture route tests for reflection/form/query behavior.
- [ ] Run tests to verify expected failures before implementing entry points.
- [ ] Implement the fixture and CLI; keep the fixture bind default at `127.0.0.1:5001` and UI bind default at `127.0.0.1:5000`, with Flask debug/reloader disabled.
- [ ] Implement the UI using the same `create_app` service path; rely on template escaping and show the candidate/manual-review wording.
- [ ] Run all scanner tests, including loopback integration, and confirm non-loopback inputs never reach the injected HTTP client.

### Task 4: README and real PoC evidence

**Files:**
- Create `web-vuln-scanner/README.md`
- Create `web-vuln-scanner/minh-chung/01-tests.png`, `02-local-scan.png`, `03-web-ui.png`, and `test-output.txt`

- [ ] Write README setup and run instructions for `py -3 -m venv .venv`, install requirements, unit tests, fixture, CLI, and UI.
- [ ] Start the fixture and UI on loopback and run the documented scan through the browser.
- [ ] Capture actual screenshots of passing tests, local CLI report, and browser result page; save them in `minh-chung/`, redact no values by editing after capture, and include no tokens or credentials.
- [ ] Save the exact test output as `test-output.txt`; verify its summary matches the screenshot and final test run.
- [ ] Re-run `py -3 -m unittest discover -s tests -v`, `git diff --check`, and the non-loopback rejection checks; report results without committing or pushing.
