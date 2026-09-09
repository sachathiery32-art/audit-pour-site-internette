"""Scan state tracker.

Keeps a per-target scan counter so reports are named:
  reports/<sanitized_url>_scan_1.html
  reports/<sanitized_url>_scan_2.html
  ...

The state file lives in reports/.scanstate.json and is a simple dict
mapping the normalized target string to an integer count.
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse


def _sanitize_target(target: str) -> str:
    """Turn a URL/IP into a filesystem-safe string."""
    parsed = urlparse(target)
    host = parsed.hostname or parsed.path or target
    # strip port, keep it short
    host = re.sub(r"[^a-zA-Z0-9._-]", "", host)
    if not host:
        host = "unknown"
    return host[:60]


class ScanState:
    """Track scan counts per target."""

    def __init__(self, state_dir: str = "reports"):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.state_path = os.path.join(state_dir, ".scanstate.json")
        self._state: dict = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.state_path):
            return {}
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self) -> None:
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
        except OSError:
            pass

    def get_next_scan_number(self, target: str) -> int:
        """Increment and return the scan counter for *target*."""
        key = _sanitize_target(target)
        current = self._state.get(key, 0)
        next_num = current + 1
        self._state[key] = next_num
        self._save()
        return next_num

    def get_basename(self, target: str) -> str:
        """Return the base filename: '<sanitized_url>_scan_<N>'."""
        key = _sanitize_target(target)
        num = self.get_next_scan_number(target)
        return f"{key}_scan_{num}"
