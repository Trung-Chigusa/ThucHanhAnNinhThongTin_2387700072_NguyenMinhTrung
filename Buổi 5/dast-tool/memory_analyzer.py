"""Approximate Python process memory checks (not a native memory debugger)."""

import gc
import tracemalloc


class MemoryAnalyzer:
    def __init__(self):
        if not tracemalloc.is_tracing():
            tracemalloc.start()

    def sample(self):
        gc.collect()
        current, peak = tracemalloc.get_traced_memory()
        return {"current_bytes": current, "peak_bytes": peak, "tracked_objects": len(gc.get_objects())}

    def check_memory_leaks(self, samples=3, interval=0.01, growth_threshold_bytes=1_048_576):
        """Return a short trend; growth is a heuristic, not proof of a leak."""
        import time

        readings = []
        for _ in range(max(2, min(int(samples), 10))):
            readings.append(self.sample()["current_bytes"])
            time.sleep(max(0.0, min(float(interval), 0.1)))
        growth = readings[-1] - readings[0]
        return {
            "samples": len(readings),
            "growth_bytes": growth,
            "suspected_leak": growth > int(growth_threshold_bytes),
            "note": "Short tracemalloc trend only; a positive result requires investigation.",
        }

    @staticmethod
    def check_overflow(value):
        """Check whether an integer falls outside signed 64-bit range."""
        return isinstance(value, int) and not isinstance(value, bool) and not (-(2**63) <= value <= 2**63 - 1)
