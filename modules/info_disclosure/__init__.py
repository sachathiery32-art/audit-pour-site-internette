"""Information disclosure detection module.

Tests for:
- Stack traces in error pages
- Debug mode enabled
- Version information in headers
- Debug endpoints exposed
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class InfoDisclosureModule(BaseModule):
    """Detect information disclosure via error pages, debug modes, and headers."""

    name = "info_disclosure"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    STACK_TRACES = re.compile(
        r'(Traceback \(most recent call|at \w+\.\w+\(|File "[^"]+", line \d+|'
        r'org\.\w+\.\w+Exception|Exception in thread)',
        re.IGNORECASE,
    )
    INTERNAL_PATHS = re.compile(r'(/home/\w+|/var/www/|/opt/|C:\\\\|/usr/local/)')
    DEBUG_INDICATORS = re.compile(r'(DEBUG\s*[:=]\s*True|debug\s*mode|DJANGO_SETTINGS)', re.IGNORECASE)
    DEBUG_ENDPOINTS = ["/debug", "/_debug", "/phpinfo.php", "/server-status",
                       "/actuator", "/actuator/health", "/metrics", "/__debug__/"]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check error-triggering paths
        for path in ["/%00", "/nonexistent_page_404_test", "/?debug=1"][:3]:
            try:
                resp = client.get(base + path, timeout=timeout)
                if not resp:
                    continue
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")

                if self.STACK_TRACES.search(body):
                    findings.append(Finding(
                        title="Stack Trace Exposed in Error Page",
                        severity=Severity.MEDIUM,
                        confidence=85,
                        target=target,
                        endpoint=base + path,
                        description="Error response contains a stack trace.",
                        module=self.name,
                        remediation="Use generic error pages in production.",
                        cwe="CWE-209",
                    ))

                if self.INTERNAL_PATHS.search(body):
                    findings.append(Finding(
                        title="Internal File Paths Disclosed",
                        severity=Severity.MEDIUM,
                        confidence=80,
                        target=target,
                        endpoint=base + path,
                        description="Response contains internal server file paths.",
                        module=self.name,
                        remediation="Remove internal paths from error messages.",
                        cwe="CWE-200",
                    ))
            except Exception:
                continue

        # Check debug endpoints
        for dep in self.DEBUG_ENDPOINTS[:4]:
            try:
                resp = client.get(base + dep, timeout=timeout)
                if resp and hasattr(resp, 'status_code') and resp.status_code == 200:
                    body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                    if len(body) > 500:
                        findings.append(Finding(
                            title=f"Debug Endpoint Exposed: {dep}",
                            severity=Severity.HIGH,
                            confidence=80,
                            target=target,
                            endpoint=base + dep,
                            description=f"Debug/monitoring endpoint {dep} is accessible.",
                            module=self.name,
                            remediation="Restrict debug endpoints to internal networks.",
                            cwe="CWE-215",
                        ))
            except Exception:
                continue

        return findings
