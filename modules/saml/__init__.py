"""SAML / SSO security detection module.

Tests for:
- SAML metadata endpoint exposure
- Weak SAML configuration indicators
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class SAMModule(BaseModule):
    """Detect SAML/SSO security misconfigurations."""

    name = "saml"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    SAML_PATHS = ["/saml/metadata", "/saml/acs", "/saml/sso",
                  "/simplesaml", "/.well-known/saml-metadata"]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.SAML_PATHS:
            try:
                resp = client.get(base + path, timeout=timeout)
                if not resp:
                    continue
                status = resp.status_code if hasattr(resp, 'status_code') else 0
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")

                if status == 200 and len(body) > 100:
                    if "entitydescriptor" in body.lower() or "samlp:" in body.lower():
                        findings.append(Finding(
                            title="SAML Metadata Endpoint Exposed",
                            severity=Severity.MEDIUM,
                            confidence=80,
                            target=target,
                            endpoint=base + path,
                            description="SAML metadata is publicly accessible.",
                            module=self.name,
                            remediation="Restrict SAML metadata access to trusted partners.",
                            cwe="CWE-200",
                        ))

                    if "simplesamlphp" in body.lower():
                        findings.append(Finding(
                            title="SimpleSAMLphp Default Installation Detected",
                            severity=Severity.MEDIUM,
                            confidence=75,
                            target=target,
                            endpoint=base + path,
                            description="SimpleSAMLphp is detected with default configuration.",
                            module=self.name,
                            remediation="Review SimpleSAMLphp configuration; restrict admin access.",
                            cwe="CWE-16",
                        ))
            except Exception:
                continue

        return findings
