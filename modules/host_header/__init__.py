"""Host header injection detection module.

Tests for:
- Password reset poisoning via Host header
- Absolute URL generation using untrusted Host
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class HostHeaderModule(BaseModule):
    """Detect host header injection and related issues."""

    name = "host_header"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    RESET_PATHS = ["/forgot-password", "/reset-password", "/password/reset",
                   "/auth/forgot", "/api/password/reset", "/request-reset"]
    MALICIOUS_HOSTS = ["evil.com", "attacker.com"]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for ep in self.RESET_PATHS[:5]:
            url = base + ep
            for evil_host in self.MALICIOUS_HOSTS:
                try:
                    resp = client.get(url, headers={"Host": evil_host}, timeout=timeout)
                    if not resp:
                        continue

                    body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")

                    if evil_host in body:
                        findings.append(Finding(
                            title="Host Header Injection - Password Reset Poisoning",
                            severity=Severity.CRITICAL,
                            confidence=90,
                            target=target,
                            endpoint=url,
                            description=f"Password reset endpoint reflects the Host header value '{evil_host}' in the response.",
                            module=self.name,
                            evidence=f"Host header value '{evil_host}' found in response body.",
                            remediation="Never use the Host header to construct URLs.",
                            cwe="CWE-644",
                        ))
                        break

                    if re.search(r'https?://' + re.escape(evil_host), body):
                        findings.append(Finding(
                            title="Host Header Injection - Absolute URL Generation",
                            severity=Severity.HIGH,
                            confidence=85,
                            target=target,
                            endpoint=url,
                            description=f"Response contains an absolute URL using the injected Host header value '{evil_host}'.",
                            module=self.name,
                            remediation="Use a fixed, trusted base URL instead of the Host header.",
                            cwe="CWE-644",
                        ))
                        break
                except Exception:
                    continue

        return findings
