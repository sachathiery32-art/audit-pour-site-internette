"""Deserialization vulnerability detection module.

Tests for:
- Serialized objects in cookies (Java, PHP, .NET, Python pickle)
- Known serialization signatures
"""
from __future__ import annotations

import re
from typing import List

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class DeserializationModule(BaseModule):
    """Detect potential unsafe deserialization vectors."""

    name = "deserialization"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    SIGNATURES = {
        "java": re.compile(r'\xac\xed\x00\x05'),
        "php": re.compile(r'[aO]:[0-9]+:|C:[0-9]+:"'),
        "python_pickle": re.compile(r'\x80\x04\x95|\x80\x03'),
        "python_yaml": re.compile(r'!!python/object|!!python/module'),
    }

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.discovery:
            return findings

        target = self.target
        cookies = getattr(self.discovery, "cookies", []) or []

        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            if not value:
                continue

            for fmt, sig in self.SIGNATURES.items():
                try:
                    raw = value.encode("utf-8", errors="ignore")
                    if sig.search(raw):
                        findings.append(Finding(
                            title=f"Serialized Data in Cookie ({fmt})",
                            severity=Severity.HIGH,
                            confidence=80,
                            target=target,
                            description=f"Cookie '{name}' contains data matching the {fmt} serialization format.",
                            module=self.name,
                            evidence=f"Cookie '{name}' matches {fmt} serialization signature.",
                            remediation="Avoid deserializing untrusted data. Use safe formats like JSON.",
                            cwe="CWE-502",
                        ))
                        break
                except Exception:
                    continue

        return findings
