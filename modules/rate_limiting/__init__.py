"""Rate limiting detection module.

Tests for:
- Login brute force protection
- API rate limiting
- Password reset rate limiting
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class RateLimitModule(BaseModule):
    """Detect missing or weak rate limiting on sensitive endpoints."""

    name = "rate_limiting"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    SENSITIVE_ENDPOINTS = [
        "/login", "/api/login", "/auth/login", "/signin",
        "/forgot-password", "/reset-password", "/api/password/reset",
        "/register", "/signup",
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        endpoints = [base + p for p in self.SENSITIVE_ENDPOINTS]
        if self.discovery:
            for ep in (getattr(self.discovery, 'api_endpoints', []) or [])[:5]:
                endpoints.append(ep if ep.startswith("http") else base + ep)

        test_count = 8

        for ep in endpoints[:10]:
            try:
                statuses = []
                rate_limited = False

                for i in range(test_count):
                    resp = client.get(ep, timeout=timeout)
                    if not resp:
                        continue
                    status = resp.status_code if hasattr(resp, 'status_code') else 0
                    statuses.append(status)
                    if status in (429, 503):
                        rate_limited = True
                        break
                    headers = resp.headers if hasattr(resp, 'headers') else {}
                    if any(h.lower().startswith("x-ratelimit") or h.lower().startswith("retry-after")
                           for h in headers):
                        rate_limited = True
                        break

                if not rate_limited and len(statuses) >= test_count:
                    all_ok = all(s in (200, 301, 302, 404) for s in statuses)
                    if all_ok:
                        findings.append(Finding(
                            title="Missing Rate Limiting",
                            severity=Severity.MEDIUM,
                            confidence=70,
                            target=target,
                            endpoint=ep,
                            description=f"Sent {test_count} rapid requests without triggering rate limiting.",
                            module=self.name,
                            evidence=f"Status codes: {statuses}",
                            remediation="Implement rate limiting with progressive delays and account lockout.",
                            cwe="CWE-770",
                        ))
            except Exception:
                continue

        return findings
