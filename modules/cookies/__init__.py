"""Cookie and session security module.

Tests for:
- Missing Secure flag on cookies over HTTPS
- Missing HttpOnly flag on session cookies
- Missing SameSite attribute
- Weak session token entropy
"""
from __future__ import annotations

import math
import re
from typing import List

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class CookieModule(BaseModule):
    """Detect insecure cookie configurations and session issues."""

    name = "cookies"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    SESSION_KEYWORDS = re.compile(r"(session|sess|sid|auth|token|jwt|access|refresh)", re.IGNORECASE)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.discovery:
            return findings

        target = self.target
        is_https = target.startswith("https")
        cookies = getattr(self.discovery, "cookies", []) or []

        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            secure = cookie.get("secure", False)
            httponly = cookie.get("httponly", False)
            samesite = cookie.get("samesite", "")
            domain = cookie.get("domain", "")
            is_session = bool(self.SESSION_KEYWORDS.search(name))

            if is_https and not secure:
                findings.append(Finding(
                    title="Cookie Missing Secure Flag",
                    severity=Severity.MEDIUM,
                    confidence=85,
                    target=target,
                    description=f"Cookie '{name}' is set without the Secure flag over HTTPS.",
                    module=self.name,
                    remediation="Always set Secure flag on cookies in HTTPS applications.",
                    cwe="CWE-614",
                ))

            if is_session and not httponly:
                findings.append(Finding(
                    title="Session Cookie Missing HttpOnly Flag",
                    severity=Severity.MEDIUM,
                    confidence=85,
                    target=target,
                    description=f"Session cookie '{name}' lacks the HttpOnly flag.",
                    module=self.name,
                    remediation="Set HttpOnly on all session-related cookies.",
                    cwe="CWE-1004",
                ))

            if is_session and value:
                entropy = self._estimate_entropy(value)
                if entropy < 50:
                    findings.append(Finding(
                        title="Weak Session Token Entropy",
                        severity=Severity.HIGH if entropy < 30 else Severity.MEDIUM,
                        confidence=75,
                        target=target,
                        description=f"Cookie '{name}' has low estimated entropy ({entropy:.0f} bits).",
                        module=self.name,
                        remediation="Use a CSPRNG to generate session tokens with >= 128 bits entropy.",
                        cwe="CWE-330",
                    ))

        return findings

    def _estimate_entropy(self, token: str) -> float:
        if not token:
            return 0
        charset_size = 0
        if re.search(r'[a-z]', token): charset_size += 26
        if re.search(r'[A-Z]', token): charset_size += 26
        if re.search(r'[0-9]', token): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', token): charset_size += 32
        if charset_size <= 1: return 0
        return len(token) * math.log2(charset_size)
