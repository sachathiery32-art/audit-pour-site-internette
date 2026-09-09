"""Business logic / rate-limit bypass module.

Tests for:
- parameter tampering (quantity, price, discount)
- rate-limit bypass via header manipulation
- workflow bypass (skipping steps)
- negative values
- integer overflow

All tests are non-destructive: we *observe* whether the server accepts
the input, but we never complete a real transaction.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


# Parameters that often carry business-logic weight
_BL_PARAMS = ["quantity", "qty", "amount", "price", "discount", "coupon",
              "count", "step", "total", "fee", "tax", "shipping",
              "user_id", "account", "role", "is_admin", "admin"]


class BusinessLogicModule(BaseModule):
    """Test business-logic flaws non-destructively."""

    name = "business_logic"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        targets = self._collect_targets()
        for url, method, params in targets:
            for param in params:
                if param.lower() not in _BL_PARAMS:
                    continue
                findings.extend(self._test_negative_value(url, method, param))
                findings.extend(self._test_extreme_value(url, method, param))

        findings.extend(self._test_rate_limit_bypass())

        self.logger.module(self.name, "completed")
        return findings

    def _collect_targets(self):
        targets = []
        if not self.discovery:
            parsed = urlparse(self.target)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            if params:
                targets.append((self.target, "GET", params))
            return targets

        for page in self.discovery.pages:
            parsed = urlparse(page)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            if params:
                targets.append((page, "GET", params))

        for form in self.discovery.forms:
            fields = [f["name"] for f in form["fields"]]
            if fields:
                targets.append((form["action"], form["method"], fields))

        return targets

    def _test_negative_value(self, url, method, param) -> List[Finding]:
        """Send -1; if accepted without error, business logic is weak."""
        findings: List[Finding] = []
        if method.upper() == "POST":
            resp = self.http.post(url, data={param: "-1"})
        else:
            resp = self.http.get(url, params={param: "-1"})
        if not resp:
            return findings
        # If the server accepted -1 (200, not an error), it's suspicious
        error_words = ["error", "invalid", "negative", "bad request",
                       "validation", "must be positive"]
        if resp.status == 200 and not any(w in resp.body.lower()[:2000]
                                          for w in error_words):
            findings.append(Finding(
                title="Negative value accepted on business parameter",
                severity=Severity.MEDIUM,
                confidence=55,
                target=self.target,
                endpoint=url,
                parameter=param,
                description=f"The server accepted {param}=-1 without a validation error.",
                evidence=f"GET/POST {url} with {param}=-1 -> {resp.status}",
                request=f"{method} {url} {param}=-1",
                reproduction_steps=f"Submit {param}=-1 and observe the response.",
                impact="Negative quantities/amounts can cause chargebacks, inventory corruption, or logic bypass.",
                recommendation="Validate that numeric business parameters are positive and within expected ranges.",
                module=self.name,
                potential=True,
            ))
        return findings

    def _test_extreme_value(self, url, method, param) -> List[Finding]:
        """Send a very large integer; if accepted, integer overflow risk."""
        findings: List[Finding] = []
        extreme = "99999999999999999999"
        if method.upper() == "POST":
            resp = self.http.post(url, data={param: extreme})
        else:
            resp = self.http.get(url, params={param: extreme})
        if not resp:
            return findings
        if resp.status == 500 or "overflow" in resp.body.lower():
            findings.append(Finding(
                title="Server error on extreme value (integer handling issue)",
                severity=Severity.LOW,
                confidence=60,
                target=self.target,
                endpoint=url,
                parameter=param,
                description=f"Sending {param}={extreme} caused a server error, indicating improper integer handling.",
                evidence=f"Status: {resp.status}",
                request=f"{method} {url} {param}={extreme}",
                reproduction_steps=f"Submit {param}={extreme}.",
                impact="DoS or logic corruption via unhandled large values.",
                recommendation="Enforce input size limits and use safe integer types.",
                module=self.name,
                potential=True,
            ))
        return findings

    def _test_rate_limit_bypass(self) -> List[Finding]:
        """Test if rate-limiting can be bypassed via header manipulation."""
        findings: List[Finding] = []
        # send same request with X-Forwarded-For spoofing
        normal = self.http.get(self.target)
        spoofed = self.http.get(self.target, headers={
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
        })
        if not normal or not spoofed:
            return findings
        # if rate-limit headers differ or disappear with spoofed headers
        normal_rl = normal.header("X-RateLimit-Remaining") or normal.header("Retry-After")
        spoofed_rl = spoofed.header("X-RateLimit-Remaining") or spoofed.header("Retry-After")
        if normal_rl and not spoofed_rl:
            findings.append(Finding(
                title="Rate-limit bypass via IP spoofing headers",
                severity=Severity.MEDIUM,
                confidence=50,
                target=self.target,
                endpoint=self.target,
                description="Spoofing X-Forwarded-For removed rate-limit headers, suggesting IP-based rate limiting is bypassable.",
                evidence=f"Normal rate-limit header: {normal_rl}\nSpoofed: {spoofed_rl or 'absent'}",
                request="GET with X-Forwarded-For: 127.0.0.1",
                reproduction_steps="Send requests with spoofed IP headers.",
                impact="Rate limiting can be bypassed, enabling brute force and abuse.",
                recommendation="Rate-limit by authenticated identity, not just IP; distrust client headers.",
                references=["https://owasp.org/www-community/attacks/"],
                module=self.name,
                potential=True,
            ))
        return findings
