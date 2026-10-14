import time

import jwt

from jwt_validator import JWTValidator


SECRET = "local-test-secret-with-sufficient-entropy-and-length-48"


def token(claims=None, key=SECRET, algorithm="HS256"):
    return jwt.encode(claims or {"sub": "student", "exp": int(time.time()) + 60}, key, algorithm=algorithm)


def test_accepts_valid_hs256_with_expiration():
    result = JWTValidator(SECRET).validate(token())
    assert result.valid and result.payload["sub"] == "student"


def test_rejects_expired_token():
    result = JWTValidator(SECRET).validate(token({"sub": "student", "exp": int(time.time()) - 1}))
    assert not result.valid and result.payload is None


def test_rejects_wrong_signature():
    result = JWTValidator("d" * 48).validate(token())
    assert not result.valid and result.reason == "invalid token"


def test_rejects_malformed_token():
    result = JWTValidator(SECRET).validate("not.a.jwt")
    assert not result.valid and result.payload is None


def test_rejects_alg_none():
    forged = jwt.encode({"sub": "student", "exp": int(time.time()) + 60}, key=None, algorithm="none")
    result = JWTValidator(SECRET).validate(forged)
    assert not result.valid


def test_rejects_unsupported_algorithm():
    forged = jwt.encode({"sub": "student", "exp": int(time.time()) + 60}, SECRET, algorithm="HS384")
    result = JWTValidator(SECRET).validate(forged)
    assert not result.valid


def test_requires_expiration():
    result = JWTValidator(SECRET).validate(token({"sub": "student"}))
    assert not result.valid and result.payload is None


def test_checks_issuer_and_audience_when_configured():
    signed = token({"sub": "student", "exp": int(time.time()) + 60, "iss": "lab", "aud": "api"})
    assert JWTValidator(SECRET, issuer="lab", audience="api").validate(signed).valid
    assert not JWTValidator(SECRET, issuer="other", audience="api").validate(signed).valid
    assert not JWTValidator(SECRET, issuer="lab", audience="other").validate(signed).valid

