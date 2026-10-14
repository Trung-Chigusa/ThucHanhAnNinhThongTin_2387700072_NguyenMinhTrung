import time
import jwt
import pytest
from jwt_cracker import JWTCracker
from oauth_client import OAuthClient, exchange_code

SECRET = "supplied-local-wordlist-secret-with-strong-demo-key"

def token(key=SECRET):
    return jwt.encode({"sub": "local", "exp": int(time.time()) - 10}, key, algorithm="HS256")

def test_cracker_finds_secret_in_supplied_wordlist(tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("guess-candidate-with-sufficient-length\n" + SECRET + "\n", encoding="utf-8")
    result = JWTCracker(token()).crack(words)
    assert result.matched and result.candidate_index == 2 and result.candidate == SECRET

def test_cracker_returns_no_match(tmp_path):
    words = tmp_path / "words.txt"; words.write_text("first-no-match-candidate-over-thirty-two-bytes\nsecond-no-match-candidate-over-thirty-two-bytes\n", encoding="utf-8")
    result = JWTCracker(token()).crack(words)
    assert not result.matched and result.candidate is None

def test_cracker_stops_at_candidate_limit(tmp_path):
    words = tmp_path / "words.txt"; words.write_text("first-no-match-candidate-over-thirty-two-bytes\nsecond-no-match-candidate-over-thirty-two-bytes\n" + SECRET + "\n", encoding="utf-8")
    result = JWTCracker(token(), max_candidates=2).crack(words)
    assert not result.matched

def test_cracker_rejects_missing_wordlist(tmp_path):
    with pytest.raises(ValueError): JWTCracker(token()).crack(tmp_path / "missing")

def test_cracker_rejects_oversized_wordlist(tmp_path):
    words = tmp_path / "large"; words.write_bytes(b"x" * 30)
    with pytest.raises(ValueError): JWTCracker(token(), max_wordlist_bytes=20).crack(words)

def test_cracker_rejects_non_utf8_wordlist(tmp_path):
    words = tmp_path / "invalid-utf8"
    words.write_bytes(b"candidate\xff")
    with pytest.raises(ValueError, match="UTF-8"):
        JWTCracker(token()).crack(words)

def client(): return OAuthClient("lab-client", "https://issuer.example/authorize", "https://app.example/callback")

def test_oauth_request_uses_state_and_s256_pkce():
    request = client().create_authorization_request(["openid", "profile"])
    assert "code_challenge_method=S256" in request.url and "code_challenge=" in request.url and request.state

def test_oauth_state_is_unpredictable():
    assert client().create_authorization_request([]).state != client().create_authorization_request([]).state

def test_callback_rejects_state_mismatch():
    with pytest.raises(ValueError): client().validate_callback({"state": "bad", "code": "c"}, "expected")

def test_callback_rejects_missing_code():
    request = client().create_authorization_request([])
    with pytest.raises(ValueError): client().validate_callback({"state": request.state}, request.state)

def test_code_exchange_sends_pkce_verifier_through_fake_transport():
    request = client().create_authorization_request([])
    class Response:
        def raise_for_status(self): pass
        def json(self): return {"access_token": "fake"}
    class Fake:
        def post(self, url, **kwargs):
            assert url == "https://issuer.example/token"
            assert kwargs["data"]["code_verifier"] == request.code_verifier
            assert kwargs["data"]["code"] == "auth-code"
            return Response()
    assert exchange_code("auth-code", request, token_endpoint="https://issuer.example/token", transport=Fake())["access_token"] == "fake"
