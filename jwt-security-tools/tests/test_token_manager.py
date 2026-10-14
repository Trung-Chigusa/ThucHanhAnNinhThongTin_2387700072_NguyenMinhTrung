import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import pytest
from token_manager import TokenManager

def test_issue_returns_access_and_refresh_tokens():
    pair = TokenManager("x" * 48).issue_tokens("alice")
    assert pair.access_token and pair.refresh_token and pair.expires_at > int(time.time())

def test_refresh_rotates_token():
    manager = TokenManager("x" * 48)
    first = manager.issue_tokens("alice")
    second = manager.refresh(first.refresh_token)
    assert second.refresh_token != first.refresh_token and second.access_token != first.access_token

def test_reuse_revokes_family_and_descendants():
    manager = TokenManager("x" * 48)
    first = manager.issue_tokens("alice")
    second = manager.refresh(first.refresh_token)
    with pytest.raises(ValueError): manager.refresh(first.refresh_token)
    with pytest.raises(ValueError): manager.refresh(second.refresh_token)

def test_concurrent_refresh_replay_revokes_any_issued_descendant():
    manager = TokenManager("x" * 48)
    first = manager.issue_tokens("alice")
    barrier = Barrier(2)

    def attempt_refresh():
        barrier.wait()
        try:
            return manager.refresh(first.refresh_token)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt_refresh(), range(2)))

    issued = [result for result in results if result is not None]
    assert len(issued) == 1
    with pytest.raises(ValueError):
        manager.refresh(issued[0].refresh_token)

def test_revoke_invalidates_refresh_token():
    manager = TokenManager("x" * 48)
    pair = manager.issue_tokens("alice")
    assert manager.revoke(pair.refresh_token)
    with pytest.raises(ValueError): manager.refresh(pair.refresh_token)

def test_expired_access_token_rejected():
    now = [1000]
    manager = TokenManager("x" * 48, access_ttl_seconds=10, clock=lambda: now[0])
    pair = manager.issue_tokens("alice")
    now[0] += 11
    assert not manager.validator.validate(pair.access_token).valid
