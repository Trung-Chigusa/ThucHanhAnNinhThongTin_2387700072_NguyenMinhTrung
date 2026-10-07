import logging
import tempfile
import unittest
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from modules.logging_setup import configure_logging


class LoggingSetupTests(unittest.TestCase):
    def test_rotating_logs_contain_status_but_not_target_or_banner(self):
        logger = None
        with tempfile.TemporaryDirectory() as temp:
            try:
                logger = configure_logging(Path(temp))
                self.assertEqual(len(logger.handlers), 1)
                handler = logger.handlers[0]
                self.assertIsInstance(handler, TimedRotatingFileHandler)
                self.assertEqual(handler.when, "MIDNIGHT")
                self.assertEqual(handler.backupCount, 7)

                logger.info("event=scan_complete count=3 status=200")
                logger.info("target=10.2.3.4 banner=PRIVATE-BANNER-MARKER")
                handler.flush()

                content = (Path(temp) / "netrecon.log").read_text(encoding="utf-8")
                self.assertIn("status=200", content)
                self.assertNotIn("10.2.3.4", content)
                self.assertNotIn("PRIVATE-BANNER-MARKER", content)
            finally:
                if logger is not None:
                    for handler in logger.handlers[:]:
                        logger.removeHandler(handler)
                        handler.close()


if __name__ == "__main__":
    unittest.main()
