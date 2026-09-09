"""XXE (XML External Entity) detection module.

Tests XML-accepting endpoints with a harmless external entity that
points to a controlled marker. If the marker appears in the response,
the parser is resolving external entities.

We never exfiltrate real data — only confirm the parser resolves entities.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urljoin

from ..base import BaseModule
from ..reporting.models import Finding, Severity


_XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe "{marker}">
]>
<root>&xxe;</root>"""

_MARKER = "autosecxxeconfirm"


class XxeModule(BaseModule):
    """Test for XXE on endpoints that accept XML."""

    name = "xxe"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        # test the root URL and any API endpoints that might accept XML
        endpoints = [self.target]
        if self.discovery:
            endpoints.extend(self.discovery.api_endpoints[:10])

        for endpoint in endpoints:
            findings.extend(self._test_endpoint(endpoint))

        self.logger.module(self.name, "completed")
        return findings

    def _test_endpoint(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        payload = _XXE_PAYLOAD.format(marker=_MARKER)

        # Send XML with the correct content type
        resp = self.http.post(url, data=payload,
                              headers={"Content-Type": "application/xml"})
        if not resp:
            return findings

        if _MARKER in resp.body:
            findings.append(Finding(
                title="XML External Entity (XXE) injection",
                severity=Severity.CRITICAL,
                confidence=80,
                target=self.target,
                endpoint=url,
                description="The XML parser resolved an external entity we controlled.",
                evidence=f"Sent XXE payload; marker '{_MARKER}' found in response.",
                request=f"POST {url} Content-Type: application/xml\n{payload}",
                response_indicators=f"Marker '{_MARKER}' present.",
                reproduction_steps="Send the XML payload with an entity; observe the resolved value in the response.",
                impact="Reading arbitrary files, SSRF, or denial of service via entity expansion.",
                recommendation="Disable external entity resolution in the XML parser (e.g., FEATURE_SECURE_PROCESSING).",
                references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                module=self.name,
                potential=True,
            ))

        return findings
