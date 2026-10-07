import unittest

from modules.service_detector import detect_service


class ServiceDetectorTests(unittest.TestCase):
    def test_service_name_uses_local_table(self):
        self.assertEqual(detect_service(22, "tcp", None), "ssh")
        self.assertEqual(detect_service(443, "tcp", None), "https")
        self.assertEqual(detect_service(53, "udp", None), "domain")

    def test_unknown_banner_stays_unknown(self):
        self.assertIsNone(detect_service(49152, "tcp", "unrecognized server greeting"))


if __name__ == "__main__":
    unittest.main()
