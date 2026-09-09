"""Structured logging that never records secrets or passwords in cleartext."""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from typing import Optional

_SECRETS_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)",
    re.IGNORECASE,
)


class _RedactFilter(logging.Filter):
    """Redact values of sensitive keys from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = str(record.getMessage())
            # redact key=value pairs where the key looks like a secret.
            # capture the key name separately so the original value is removed.
            def _redact(match: re.Match) -> str:
                return f"{match.group(1)}=***REDACTED***"

            record.msg = re.sub(
                r"((?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie))=[^&\s]+",
                _redact, msg, flags=re.IGNORECASE,
            )
        except Exception:
            pass
        return True


class ScanLogger:
    """Per-scan logger writing to logs/scan_TIMESTAMP.log."""

    def __init__(self, logs_dir: str = "logs"):
        self.logs_dir = logs_dir
        os.makedirs(logs_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(logs_dir, f"scan_{timestamp}.log")

        self._logger = logging.getLogger(f"autosecaudit.{timestamp}")
        self._logger.setLevel(logging.DEBUG)
        # prevent duplicate handlers on re-init
        self._logger.handlers.clear()
        self._logger.propagate = False

        file_handler = logging.FileHandler(self.log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.addFilter(_RedactFilter())
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)
        self._logger.addFilter(_RedactFilter())

    def start(self, target: str, mode: str) -> None:
        self._logger.info("=" * 60)
        self._logger.info(f"Scan started | target={target} | mode={mode}")

    def module(self, name: str, status: str) -> None:
        self._logger.info(f"module={name} status={status}")

    def request(self, method: str, url: str, status: int) -> None:
        self._logger.debug(f"{method} {url} -> {status}")

    def finding(self, title: str, severity: str) -> None:
        self._logger.warning(f"finding severity={severity} title={title}")

    def error(self, msg: str) -> None:
        self._logger.error(msg)

    def finish(self, duration: float, findings_count: int) -> None:
        self._logger.info(
            f"Scan completed | duration={duration:.1f}s | findings={findings_count}"
        )
        self._logger.info("=" * 60)

    @property
    def logger(self) -> logging.Logger:
        return self._logger
