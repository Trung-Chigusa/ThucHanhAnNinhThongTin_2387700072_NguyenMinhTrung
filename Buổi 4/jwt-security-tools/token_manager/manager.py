from dataclasses import dataclass
import hashlib
import secrets
import time
import threading
from collections.abc import Callable

import jwt
from jwt_validator import JWTValidator

@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_at: int

class TokenManager:
    def __init__(self, secret: str | bytes, *, access_ttl_seconds: int = 600, clock: Callable[[], float] = time.time):
        if not isinstance(secret, (str, bytes)) or not secret:
            raise ValueError("secret must be non-empty")
        if access_ttl_seconds < 1:
            raise ValueError("access_ttl_seconds must be positive")
        self._secret = secret
        self._ttl = access_ttl_seconds
        self._clock = clock
        self.validator = JWTValidator(secret)
        self._records: dict[str, dict[str, object]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _issue(self, subject: str, family: str) -> TokenPair:
        now = int(self._clock())
        expires = now + self._ttl
        access = jwt.encode({"sub": subject, "iat": now, "exp": expires, "jti": secrets.token_urlsafe(12)}, self._secret, algorithm="HS256")
        refresh = secrets.token_urlsafe(36)
        self._records[self._digest(refresh)] = {"family": family, "subject": subject, "used": False, "revoked": False}
        return TokenPair(access, refresh, expires)

    def issue_tokens(self, subject: str) -> TokenPair:
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError("subject is required")
        family = secrets.token_urlsafe(18)
        with self._lock:
            return self._issue(subject, family)

    def refresh(self, refresh_token: str) -> TokenPair:
        if not isinstance(refresh_token, str) or not refresh_token:
            raise ValueError("invalid refresh token")
        digest = self._digest(refresh_token)
        with self._lock:
            record = self._records.get(digest)
            if record is None:
                raise ValueError("invalid refresh token")
            family = record["family"]
            if record["revoked"] or record["used"]:
                for item in self._records.values():
                    if item["family"] == family:
                        item["revoked"] = True
                raise ValueError("invalid refresh token")
            record["used"] = True
            return self._issue(str(record["subject"]), str(family))

    def revoke(self, refresh_token: str) -> bool:
        if not isinstance(refresh_token, str) or not refresh_token:
            return False
        with self._lock:
            record = self._records.get(self._digest(refresh_token))
            if record is None:
                return False
            family = record["family"]
            for item in self._records.values():
                if item["family"] == family:
                    item["revoked"] = True
            return True

