"""Shared utilities for false positive prevention.

The biggest source of false positives in web scanners is the SPA
(single-page application) catch-all: frameworks like Angular, React,
and Vue return the identical index.html for every path. This module
provides helpers to detect and avoid that trap.
"""
from __future__ import annotations

import hashlib
from typing import Optional


class BaselineCache:
    """Lazily fetches and caches the root page baseline.

    Used by every module to compare a probe response against the
    baseline. If they're byte-identical (or nearly so), the probe
    hit a catch-all route, not a real finding.
    """

    def __init__(self, http, target: str):
        self._http = http
        self._target = target
        self._baseline_body: Optional[str] = None
        self._baseline_hash: Optional[str] = None
        self._baseline_len: int = 0

    def _fetch(self) -> None:
        if self._baseline_body is not None:
            return
        resp = self._http.get(self._target)
        if resp:
            self._baseline_body = resp.body
            self._baseline_hash = hashlib.sha256(resp.body.encode("utf-8", errors="replace")).hexdigest()
            self._baseline_len = len(resp.body)

    @property
    def body(self) -> str:
        self._fetch()
        return self._baseline_body or ""

    @property
    def hash(self) -> str:
        self._fetch()
        return self._baseline_hash or ""

    @property
    def length(self) -> int:
        self._fetch()
        return self._baseline_len


def is_spa_catchall(response_body: str, baseline: BaselineCache,
                    threshold: int = 50) -> bool:
    """Return True if *response_body* is effectively identical to the
    baseline root page.

    SPAs return the same HTML shell for every route. We detect this by
    comparing body length and content hash. A difference of less than
    *threshold* bytes means it's the same page (minor dynamic content
    like CSRF tokens may cause tiny diffs).
    """
    if not response_body or not baseline.body:
        return False
    # fast path: exact hash match
    resp_hash = hashlib.sha256(
        response_body.encode("utf-8", errors="replace")
    ).hexdigest()
    if resp_hash == baseline.hash:
        return True
    # slow path: length-based heuristic
    resp_len = len(response_body)
    if abs(resp_len - baseline.length) < threshold:
        # double-check: first 500 chars match (ignoring minor diffs)
        return response_body[:500] == baseline.body[:500]
    return False


def content_appears_in_baseline(pattern_match: str, baseline_body: str) -> bool:
    """Return True if the matched content also appears in the baseline.

    If a regex match (e.g., 'invalid', 'error') is found in the probe
    response AND in the baseline, it's static text, not a real finding.
    """
    return pattern_match.lower() in baseline_body.lower()
