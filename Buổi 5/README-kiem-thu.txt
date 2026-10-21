Lab 05 verification record
Date: 2026-10-21

SAST
Command: python -m unittest discover -s tests -v
Result: PASS — 12 tests
CLI PoC: python -m sast_tool examples\vulnerable_01.py --output minh-chung\sast-vulnerable-01.sarif
Result: 4 findings; SARIF 2.1.0; screenshot: minh-chung\sast-report.png

DAST
Command: python -m unittest discover -s tests -v
Result: PASS — 15 tests
PoC: GET /demo submits a bounded echo request to POST /api/sandbox.
Result: HTTP 200; stdout is "Hello from Lab 05"; screenshot: minh-chung\dast-sandbox.png

Notes: Python 3.13.10; project dependencies installed in ignored project-local .venv directories.
