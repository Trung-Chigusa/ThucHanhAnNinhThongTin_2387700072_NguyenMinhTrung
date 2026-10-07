import unittest

from modules.filter_utils import parse_ports


class PortFilterTests(unittest.TestCase):
    def test_parses_ports_and_ranges_in_order(self):
        self.assertEqual(parse_ports("80,443,8000-8002"), (80, 443, 8000, 8001, 8002))

    def test_deduplicates_ports(self):
        self.assertEqual(parse_ports("80,80,79-81,80"), (80, 79, 81))

    def test_rejects_empty_or_malformed_segments(self):
        for value in ("", "80,", ",80", "80,,81", "abc", "1-2-3", "-1", "2-"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_rejects_ports_outside_1_to_65535(self):
        for value in ("0", "65536", "0-2", "65535-65536"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_rejects_more_than_128_unique_ports(self):
        with self.assertRaises(ValueError):
            parse_ports("1-129")


if __name__ == "__main__":
    unittest.main()
