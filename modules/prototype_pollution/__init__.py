"""Prototype pollution detection module.

Tests for:
- __proto__ parameter acceptance in JSON
- Vulnerable deep merge patterns in JS files
"""
from __future__ import annotations

import json
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class PrototypePollutionModule(BaseModule):
    """Detect potential prototype pollution vectors in JS applications."""

    name = "prototype_pollution"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    POLLUTION_PAYLOADS = [
        {"__proto__": {"testpollution": True}},
        {"constructor": {"prototype": {"testpollution": True}}},
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
            for ep in (getattr(self.discovery, 'api_endpoints', []) or [])[:10]:
                endpoints.append(ep if ep.startswith("http") else base + ep)

        for ep in endpoints[:10]:
            for payload in self.POLLUTION_PAYLOADS:
                try:
                    resp = client.post(ep, data=json.dumps(payload),
                                      headers={"Content-Type": "application/json"},
                                      timeout=timeout)
                    if not resp:
                        continue
                    body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                    if "testpollution" in str(body).lower():
                        findings.append(Finding(
                            title="Potential Prototype Pollution",
                            severity=Severity.HIGH,
                            confidence=60,
                            target=target,
                            endpoint=ep,
                            description="JSON payload with __proto__ was sent and probe key appears in response.",
                            module=self.name,
                            evidence=f"Payload: {json.dumps(payload)}",
                            remediation="Freeze Object.prototype; validate/whitelist input keys.",
                            cwe="CWE-1321",
                        ))
                        break
                except Exception:
                    continue

        # Check JS files for vulnerable patterns
        js_files = getattr(self.discovery, 'js_files', []) or []
        for js_url in js_files[:20]:
            try:
                resp = client.get(js_url, timeout=timeout)
                if not resp:
                    continue
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                for pat in ["Object.assign(", "deepMerge(", "_.extend(", "$.extend("]:
                    if pat in body:
                        findings.append(Finding(
                            title="Potentially Vulnerable Deep Merge Function",
                            severity=Severity.INFO,
                            confidence=40,
                            target=target,
                            endpoint=js_url,
                            description=f"JavaScript file contains '{pat}' which may be vulnerable to prototype pollution.",
                            module=self.name,
                            remediation="Use Object.create(null) or Map instead of plain objects.",
                            cwe="CWE-1321",
                        ))
                        break
            except Exception:
                continue

        return findings
