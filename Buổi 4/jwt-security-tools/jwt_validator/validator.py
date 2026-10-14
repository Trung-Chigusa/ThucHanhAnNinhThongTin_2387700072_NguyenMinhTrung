"""Strict HS256 JWT validation for the local Lab 04 exercises."""

from dataclasses import dataclass
from typing import Any

import jwt
from jwt import InvalidTokenError


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    payload: dict[str, Any] | None
    reason: str | None


class JWTValidator:
    def __init__(self, secret: str | bytes, *, issuer: str | None = None, audience: str | None = None):
        if not isinstance(secret, (str, bytes)) or not secret:
            raise ValueError("secret must be a non-empty string or bytes")
        self._secret = secret
        self._issuer = issuer
        self._audience = audience

    def validate(self, token: str) -> ValidationResult:
        if not isinstance(token, str) or not token:
            return ValidationResult(False, None, "invalid token")
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": ["exp"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iss": self._issuer is not None,
                    "verify_aud": self._audience is not None,
                },
            )
            return ValidationResult(True, payload, None)
        except (InvalidTokenError, TypeError, ValueError):
            return ValidationResult(False, None, "invalid token")
