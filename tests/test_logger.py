"""Tests for the logger secret redaction."""
import logging
import os
import tempfile
import unittest

from modules.logger import ScanLogger, _RedactFilter


class TestRedactFilter(unittest.TestCase):
    def test_redacts_password_in_url(self):
        rec = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="GET https://example.com/login?password=secret123",
            args=None, exc_info=None,
        )
        f = _RedactFilter()
        self.assertTrue(f.filter(rec))
        self.assertIn("***REDACTED***", str(rec.getMessage()))
        self.assertNotIn("secret123", str(rec.getMessage()))

    def test_redacts_token_param(self):
        rec = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="POST /api with token=abc123def456",
            args=None, exc_info=None,
        )
        f = _RedactFilter()
        f.filter(rec)
        self.assertIn("***REDACTED***", str(rec.getMessage()))

    def test_does_not_redact_normal_messages(self):
        rec = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Scan started | target=https://example.com | mode=standard",
            args=None, exc_info=None,
        )
        f = _RedactFilter()
        f.filter(rec)
        self.assertNotIn("***REDACTED***", str(rec.getMessage()))


class TestScanLogger(unittest.TestCase):
    def test_creates_log_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ScanLogger(logs_dir=tmpdir)
            logger.start("https://example.com", "standard")
            logger.module("discovery", "started")
            logger.finish(10.5, 3)
            self.assertTrue(os.path.exists(logger.log_path))
            with open(logger.log_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Scan started", content)
            self.assertIn("Scan completed", content)
            # close handlers so Windows releases the file lock before cleanup
            for handler in logger.logger.handlers:
                handler.close()
                logger.logger.removeHandler(handler)


if __name__ == "__main__":
    unittest.main()
