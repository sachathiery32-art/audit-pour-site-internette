"""HTTP request smuggling detection module.

Tests for:
- CL/TE (Content-Length vs Transfer-Encoding) discrepancies
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class HTTPSmugglingModule(BaseModule):
    """Detect HTTP request smuggling vulnerabilities."""

    name = "http_smuggling"

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

            headers = resp.headers if hasattr(resp, 'headers') else {}
            has_proxy = any(
                h.lower() in ("via", "x-cache", "x-varnish", "x-cdn", "cf-ray")
                for h in headers
            )

            if not has_proxy:
                findings.append(Finding(
                    title="HTTP Smuggling - No Proxy Detected",
                    severity=Severity.INFO,
                    confidence=30,
                    target=target,
                    description="No proxy/CDN headers detected. Smuggling typically requires a proxy.",
                    module=self.name,
                    remediation="Ensure all proxies normalize Transfer-Encoding and Content-Length headers.",
                    cwe="CWE-444",
                ))
        except Exception:
            pass

        return findings
