"""HTTP methods detection module.

Tests for:
- TRACE method enabled (XST risk)
- PUT/DELETE methods enabled
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class HTTPMethodsModule(BaseModule):
    """Detect dangerous or unnecessary HTTP methods."""

    name = "http_methods"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    DANGEROUS_METHODS = {"TRACE", "CONNECT", "TRACK"}
    WRITE_METHODS = {"PUT", "DELETE", "PATCH"}

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            resp = client.options(base + "/", timeout=timeout)
            if resp:
                allow = resp.headers.get("Allow", "") if hasattr(resp, 'headers') else ""
                methods = [m.strip().upper() for m in allow.split(",")]

                for method in self.DANGEROUS_METHODS:
                    if method in methods:
                        findings.append(Finding(
                            title=f"Dangerous HTTP Method Enabled: {method}",
                            severity=Severity.HIGH if method == "TRACE" else Severity.MEDIUM,
                            confidence=85,
                            target=target,
                            endpoint=base + "/",
                            description=f"The {method} method is enabled.",
                            module=self.name,
                            remediation=f"Disable the {method} method on the web server.",
                            cwe="CWE-16",
                        ))

                for method in self.WRITE_METHODS:
                    if method in methods:
                        findings.append(Finding(
                            title=f"Write Method Enabled: {method}",
                            severity=Severity.LOW,
                            confidence=40,
                            target=target,
                            endpoint=base + "/",
                            description=f"The {method} method is listed in Allow.",
                            module=self.name,
                            remediation=f"Ensure {method} requires proper authentication.",
                            cwe="CWE-16",
                        ))
        except Exception:
            pass

        return findings
