"""Inspect local HTML forms for a recognizable hidden CSRF token."""

from html.parser import HTMLParser

from scanners.scanner_service import Finding, ScanError, create_local_http_client


_TOKEN_NAMES = {
    "csrf_token",
    "csrfmiddlewaretoken",
    "_csrf",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf-token",
}


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag, attrs):
        attrs_map = dict(attrs)
        if tag == "form":
            if self._current is not None:
                self.forms.append(self._current)
            self._current = {
                "method": (attrs_map.get("method") or "get").lower(),
                "has_token": False,
            }
        elif tag == "input" and self._current is not None:
            name = (attrs_map.get("name") or "").lower()
            input_type = (attrs_map.get("type") or "text").lower()
            value = attrs_map.get("value") or ""
            if input_type == "hidden" and name in _TOKEN_NAMES and value.strip():
                self._current["has_token"] = True

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def finish(self):
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None


def scan_csrf(target, http=None) -> list[Finding]:
    if http is None:
        http = create_local_http_client()
    try:
        response = http.get(target.canonical_url, timeout=3, allow_redirects=False)
    except Exception:
        raise ScanError("The local target did not return a usable response.") from None
    if not 200 <= response.status_code < 300:
        return []
    parser = _FormParser()
    try:
        parser.feed(response.text)
        parser.close()
        parser.finish()
    except Exception:
        return []
    findings = []
    for index, form in enumerate(parser.forms, start=1):
        if form["method"] in {"post", "put", "patch", "delete"} and not form["has_token"]:
            findings.append(
                Finding(
                    type="CSRF",
                    location=f"form:{index}",
                    evidence="A state-changing form has no recognized non-empty hidden CSRF token.",
                    confidence="manual-review",
                    risk="Medium",
                    remediation="Use a per-session CSRF token and validate it on state-changing requests.",
                )
            )
    return findings
