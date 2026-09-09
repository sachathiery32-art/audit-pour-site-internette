"""Mass assignment detection module.

Tests for:
- API endpoints accepting unexpected properties (role, admin, etc.)
"""
from __future__ import annotations

import json
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class MassAssignmentModule(BaseModule):
    """Detect mass assignment vulnerabilities in API endpoints."""

    name = "mass_assignment"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    SENSITIVE_PROPERTIES = [
        {"role": "admin"}, {"is_admin": True}, {"admin": True},
        {"is_superuser": True}, {"price": 0}, {"discount": 100},
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        endpoints = []
        if self.discovery:
            for ep in (getattr(self.discovery, 'api_endpoints', []) or [])[:15]:
                endpoints.append(ep if ep.startswith("http") else base + ep)

        for ep in endpoints[:10]:
            for props in self.SENSITIVE_PROPERTIES[:3]:
                try:
                    payload = json.dumps(props)
                    resp = client.post(ep, data=payload,
                                      headers={"Content-Type": "application/json"},
                                      timeout=timeout)
                    if not resp:
                        continue
                    status = resp.status_code if hasattr(resp, 'status_code') else 0
                    if 200 <= status < 300:
                        prop_name = list(props.keys())[0]
                        findings.append(Finding(
                            title=f"Potential Mass Assignment: {prop_name}",
                            severity=Severity.HIGH if prop_name in ("role", "is_admin", "admin") else Severity.MEDIUM,
                            confidence=50,
                            target=target,
                            endpoint=ep,
                            description=f"Endpoint accepted unexpected property '{prop_name}={props[prop_name]}'.",
                            module=self.name,
                            evidence=f"Payload: {payload} -> HTTP {status}",
                            remediation="Use allowlists for mass-assignmentable fields.",
                            cwe="CWE-915",
                        ))
                        break
                except Exception:
                    continue

        return findings
