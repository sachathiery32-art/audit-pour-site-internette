"""CORS misconfiguration detection module.

Tests for:
- Wildcard Origin with credentials
- Origin reflection (any origin accepted)
- Null origin acceptance
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class CORSModule(BaseModule):
    """Detect CORS misconfigurations that could allow cross-origin data theft."""

    name = "cors"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    EVIL_ORIGINS = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        endpoints = [base + "/"]
        if self.discovery:
            for ep in (getattr(self.discovery, 'api_endpoints', []) or [])[:15]:
                endpoints.append(ep if ep.startswith("http") else base + ep)
            for page in (getattr(self.discovery, 'pages', []) or [])[:10]:
                endpoints.append(page if page.startswith("http") else base + page)

        for ep in endpoints[:20]:
            for origin in self.EVIL_ORIGINS:
                try:
                    resp = client.get(ep, headers={"Origin": origin}, timeout=timeout)
                    if not resp:
                        continue

                    acao = resp.headers.get("Access-Control-Allow-Origin", "") if hasattr(resp, 'headers') else ""
                    acac = (resp.headers.get("Access-Control-Allow-Credentials", "") if hasattr(resp, 'headers') else "").lower()

                    if not acao:
                        continue

                    if acao == "*" and acac == "true":
                        findings.append(Finding(
                            title="CORS Wildcard with Credentials",
                            severity=Severity.HIGH,
                            confidence=95,
                            target=target,
                            endpoint=ep,
                            description="Access-Control-Allow-Origin is '*' with Access-Control-Allow-Credentials: true.",
                            module=self.name,
                            remediation="Remove wildcard; echo back only trusted origins.",
                            cwe="CWE-942",
                        ))
                        break

                    if acao == origin:
                        sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
                        findings.append(Finding(
                            title="CORS Origin Reflection" + (" with Credentials" if acac == "true" else ""),
                            severity=sev,
                            confidence=90,
                            target=target,
                            endpoint=ep,
                            description=f"Server reflects attacker-controlled Origin '{origin}' in Access-Control-Allow-Origin.",
                            module=self.name,
                            remediation="Validate Origin against a strict allowlist.",
                            cwe="CWE-942",
                        ))
                        break

                    if acao == "null" and origin == "null":
                        findings.append(Finding(
                            title="CORS Null Origin Accepted",
                            severity=Severity.MEDIUM,
                            confidence=80,
                            target=target,
                            endpoint=ep,
                            description="Server accepts 'null' as a valid Origin.",
                            module=self.name,
                            remediation="Reject 'null' origin; only allow trusted domains.",
                            cwe="CWE-942",
                        ))
                        break
                except Exception:
                    continue

        return findings
