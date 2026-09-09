"""Cache poisoning detection module.

Tests for:
- Unkeyed headers (X-Forwarded-*, X-Original-URL, X-Rewrite-URL)
- Cache key inconsistencies
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class CacheModule(BaseModule):
    """Detect web cache poisoning vulnerabilities."""

    name = "cache"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    UNKEYED_HEADERS = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Host", "evil.com"),
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        test_endpoints = [base + "/"]
        if self.discovery:
            for page in (getattr(self.discovery, 'pages', []) or [])[:5]:
                test_endpoints.append(page if page.startswith("http") else base + page)

        for ep in test_endpoints[:5]:
            for header_name, header_value in self.UNKEYED_HEADERS:
                try:
                    resp1 = client.get(ep, headers={header_name: header_value}, timeout=timeout)
                    if not resp1:
                        continue

                    body1 = resp1.body if hasattr(resp1, 'body') else (resp1.text if hasattr(resp1, 'text') else "")

                    if header_value in body1:
                        resp2 = client.get(ep, timeout=timeout)
                        if resp2:
                            body2 = resp2.body if hasattr(resp2, 'body') else (resp2.text if hasattr(resp2, 'text') else "")
                            if header_value in body2:
                                findings.append(Finding(
                                    title=f"Cache Poisoning via {header_name}",
                                    severity=Severity.HIGH,
                                    confidence=75,
                                    target=target,
                                    endpoint=ep,
                                    description=f"The header '{header_name}' is not keyed by the cache.",
                                    module=self.name,
                                    evidence=f"Poisoned value '{header_value}' persisted in cached response.",
                                    remediation=f"Key the cache on '{header_name}' or strip it at the CDN.",
                                    cwe="CWE-525",
                                ))
                                break
                except Exception:
                    continue

        return findings
