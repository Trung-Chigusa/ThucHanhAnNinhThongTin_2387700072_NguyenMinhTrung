from dataclasses import dataclass
import base64
import hashlib
import secrets
from collections.abc import Mapping, Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    state: str
    code_verifier: str
    redirect_uri: str
    client_id: str

class OAuthClient:
    def __init__(self, client_id: str, authorization_url: str, redirect_uri: str):
        if not client_id:
            raise ValueError("client_id is required")
        for label, value in (("authorization_url", authorization_url), ("redirect_uri", redirect_uri)):
            parsed = urlsplit(value)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError(f"{label} must be an HTTPS URL")
        self.client_id = client_id
        self.authorization_url = authorization_url
        self.redirect_uri = redirect_uri

    def create_authorization_request(self, scopes: Sequence[str]) -> AuthorizationRequest:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        parsed = urlsplit(self.authorization_url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params.update({"response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
                       "scope": " ".join(scopes), "state": state, "code_challenge": challenge,
                       "code_challenge_method": "S256"})
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), parsed.fragment))
        return AuthorizationRequest(url, state, verifier, self.redirect_uri, self.client_id)

    def validate_callback(self, query: Mapping[str, str], expected_state: str) -> str:
        if not expected_state or not secrets.compare_digest(str(query.get("state", "")), expected_state):
            raise ValueError("OAuth state mismatch")
        code = query.get("code")
        if not code:
            raise ValueError("OAuth authorization code is missing")
        return code

def exchange_code(code: str, request: AuthorizationRequest, *, token_endpoint: str, transport) -> Mapping[str, object]:
    if not code:
        raise ValueError("authorization code is required")
    parsed = urlsplit(token_endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("token endpoint must be an HTTPS URL")
    response = transport.post(token_endpoint, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": request.redirect_uri,
        "client_id": request.client_id, "code_verifier": request.code_verifier,
    }, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, Mapping):
        raise ValueError("token response must be an object")
    return payload
