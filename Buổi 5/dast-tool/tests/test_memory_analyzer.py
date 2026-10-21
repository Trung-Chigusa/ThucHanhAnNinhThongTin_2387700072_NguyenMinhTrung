import unittest

from memory_analyzer import MemoryAnalyzer


class MemoryAnalyzerTests(unittest.TestCase):
    def test_detects_signed_64_bit_range_exceeded(self):
        self.assertTrue(MemoryAnalyzer.check_overflow(2**63))
        self.assertFalse(MemoryAnalyzer.check_overflow(2**63 - 1))
        self.assertFalse(MemoryAnalyzer.check_overflow("large"))
        self.assertFalse(MemoryAnalyzer.check_overflow(True))

    def test_memory_sample_and_short_trend_have_expected_shape(self):
        analyzer = MemoryAnalyzer()
        sample = analyzer.sample()
        trend = analyzer.check_memory_leaks(samples=2, interval=0)
        self.assertGreaterEqual(sample["current_bytes"], 0)
        self.assertEqual(trend["samples"], 2)
        self.assertIn("suspected_leak", trend)


if __name__ == "__main__":
    unittest.main()
