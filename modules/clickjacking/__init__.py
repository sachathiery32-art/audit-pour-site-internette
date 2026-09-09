"""Clickjacking detection module.

Tests for:
- Missing X-Frame-Options header
- Missing CSP frame-ancestors directive
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class ClickjackingModule(BaseModule):
    """Detect clickjacking vulnerabilities via missing frame protection."""

    name = "clickjacking"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            resp = client.get(base + "/", timeout=timeout)
            if not resp:
                return findings

            xfo = resp.headers.get("X-Frame-Options", "") if hasattr(resp, 'headers') else ""
            csp = resp.headers.get("Content-Security-Policy", "") if hasattr(resp, 'headers') else ""
            has_frame_ancestors = "frame-ancestors" in csp.lower()

            if not xfo and not has_frame_ancestors:
                findings.append(Finding(
                    title="Clickjacking - No Frame Protection",
                    severity=Severity.MEDIUM,
                    confidence=90,
                    target=target,
                    endpoint=base + "/",
                    description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
                    module=self.name,
                    remediation="Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                    cwe="CWE-1021",
                ))
            elif xfo and xfo.upper() == "SAMEORIGIN":
                findings.append(Finding(
                    title="Clickjacking - X-Frame-Options SameOrigin Only",
                    severity=Severity.LOW,
                    confidence=50,
                    target=target,
                    endpoint=base + "/",
                    description="X-Frame-Options is set to SAMEORIGIN. A subdomain XSS could still enable clickjacking.",
                    module=self.name,
                    remediation="Consider using DENY or CSP frame-ancestors for stricter control.",
                    cwe="CWE-1021",
                ))
        except Exception:
            pass

        return findings
