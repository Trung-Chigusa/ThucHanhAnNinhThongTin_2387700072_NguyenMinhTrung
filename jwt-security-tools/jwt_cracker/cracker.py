from pathlib import Path
import jwt
from jwt import InvalidTokenError
from dataclasses import dataclass

@dataclass(frozen=True)
class CrackResult:
    matched: bool
    candidate_index: int | None
    candidate: str | None

class JWTCracker:
    def __init__(self, token: str, *, max_candidates: int = 1000, max_wordlist_bytes: int = 1_048_576):
        if not isinstance(token, str) or not token:
            raise ValueError("token must be non-empty")
        if not 1 <= max_candidates <= 1000:
            raise ValueError("max_candidates must be between 1 and 1000")
        if not 1 <= max_wordlist_bytes <= 1_048_576:
            raise ValueError("max_wordlist_bytes must be between 1 and 1048576")
        self._token = token
        self._max_candidates = max_candidates
        self._max_wordlist_bytes = max_wordlist_bytes

    def crack(self, wordlist_path: Path) -> CrackResult:
        path = Path(wordlist_path)
        try:
            if path.stat().st_size > self._max_wordlist_bytes:
                raise ValueError("wordlist exceeds the configured size limit")
            with path.open("rb") as stream:
                contents = stream.read(self._max_wordlist_bytes + 1)
        except FileNotFoundError as exc:
            raise ValueError("wordlist does not exist") from exc
        except OSError as exc:
            raise ValueError("wordlist could not be read") from exc
        if len(contents) > self._max_wordlist_bytes:
            raise ValueError("wordlist exceeds the configured size limit")
        try:
            candidates = contents.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as exc:
            raise ValueError("wordlist must be UTF-8 text") from exc
        for index, candidate in enumerate(candidates[:self._max_candidates], start=1):
            if not candidate:
                continue
            try:
                jwt.decode(self._token, candidate, algorithms=["HS256"], options={"verify_exp": False, "verify_signature": True})
                return CrackResult(True, index, candidate)
            except (InvalidTokenError, TypeError, ValueError):
                continue
        return CrackResult(False, None, None)
