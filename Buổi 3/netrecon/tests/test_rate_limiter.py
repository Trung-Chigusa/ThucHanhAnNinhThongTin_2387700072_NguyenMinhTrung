import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from modules.rate_limiter import ProbeScheduler


class FakeClock:
    def __init__(self):
        self.value = 0.0
        self.lock = threading.Lock()
        self.sleeps = []

    def now(self):
        with self.lock:
            return self.value

    def sleep(self, seconds):
        with self.lock:
            self.sleeps.append(seconds)
            self.value += seconds


class ProbeSchedulerTests(unittest.TestCase):
    def test_rate_two_allows_at_most_two_probes_per_second(self):
        clock = FakeClock()
        scheduler = ProbeScheduler(2, 1, clock=clock.now, sleep=clock.sleep)
        starts = []

        for _ in range(6):
            scheduler.run_probe(lambda: starts.append(clock.now()))

        self.assertEqual(starts, [0.0, 0.5, 1.0, 1.5, 2.0, 2.5])
        self.assertTrue(all(right - left >= 0.5 for left, right in zip(starts, starts[1:])))

    def test_rate_bounds_accept_one_and_ten(self):
        ProbeScheduler(1, 1)
        ProbeScheduler(10, 4)
        for rate in (0, 11):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                ProbeScheduler(rate, 1)
        for concurrency in (0, 5):
            with self.subTest(concurrency=concurrency), self.assertRaises(ValueError):
                ProbeScheduler(2, concurrency)

    def test_shared_scheduler_caps_concurrency_at_four(self):
        scheduler = ProbeScheduler(10, 4)
        barrier = threading.Barrier(4)
        guard = threading.Lock()
        active = 0
        maximum = 0

        def operation():
            nonlocal active, maximum
            with guard:
                active += 1
                maximum = max(maximum, active)
            barrier.wait(timeout=3)
            with guard:
                active -= 1

        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = [pool.submit(scheduler.run_probe, operation) for _ in range(12)]
            for future in futures:
                future.result(timeout=5)

        self.assertEqual(maximum, 4)

    def test_probe_exception_releases_concurrency_slot(self):
        scheduler = ProbeScheduler(10, 1)
        with self.assertRaisesRegex(RuntimeError, "probe failed"):
            scheduler.run_probe(lambda: (_ for _ in ()).throw(RuntimeError("probe failed")))
        self.assertEqual(scheduler.run_probe(lambda: "recovered"), "recovered")


if __name__ == "__main__":
    unittest.main()
