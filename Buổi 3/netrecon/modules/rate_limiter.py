"""Shared rate and concurrency limits for probe socket operations."""

from threading import BoundedSemaphore, Lock
import time
from typing import Callable, TypeVar

T = TypeVar("T")


class ProbeScheduler:
    """Serialize probe starts to a configured rate and cap active operations."""

    def __init__(
        self,
        rate_per_second: int,
        max_concurrency: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if isinstance(rate_per_second, bool) or not isinstance(rate_per_second, int) or not 1 <= rate_per_second <= 10:
            raise ValueError("rate_per_second must be between 1 and 10")
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or not 1 <= max_concurrency <= 4:
            raise ValueError("max_concurrency must be between 1 and 4")
        self.rate_per_second = rate_per_second
        self.max_concurrency = max_concurrency
        self._clock = clock
        self._sleep = sleep
        self._semaphore = BoundedSemaphore(max_concurrency)
        self._rate_lock = Lock()
        self._next_probe_at: float | None = None

    def _wait_for_rate_slot(self) -> None:
        interval = 1.0 / self.rate_per_second
        with self._rate_lock:
            now = self._clock()
            if self._next_probe_at is not None and now < self._next_probe_at:
                self._sleep(self._next_probe_at - now)
                now = self._clock()
            scheduled_at = max(now, self._next_probe_at or now)
            self._next_probe_at = scheduled_at + interval

    def run_probe(self, operation: Callable[[], T]) -> T:
        """Run one operation after reserving a rate slot and concurrency slot."""
        with self._semaphore:
            self._wait_for_rate_slot()
            return operation()
