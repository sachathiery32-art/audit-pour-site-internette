"""Secrets exposure detection module.

Scans responses and JavaScript files for:
- API keys (AWS, GCP, Azure, Stripe, etc.)
- Private keys (RSA, SSH, PGP)
- Hardcoded passwords and secrets
- Connection strings
"""
from __future__ import annotations

import re
from typing import List

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class SecretsExposureModule(BaseModule):
    """Detect exposed secrets, API keys, and credentials in responses."""

    name = "secrets_exposure"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    SECRET_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key", Severity.CRITICAL),
        (r'(?i)api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "API Key", Severity.HIGH),
        (r'(?i)secret[_-]?key\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Secret Key", Severity.HIGH),
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{6,}["\']', "Hardcoded Password", Severity.CRITICAL),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
        (r'(?i)(?:mysql|postgres|mongodb|redis|amqp)://[^\s"\']+', "Connection String", Severity.CRITICAL),
        (r'(?i)ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token", Severity.CRITICAL),
        (r'(?i)sk_live_[A-Za-z0-9]{24,}', "Stripe Secret Key", Severity.CRITICAL),
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        from urllib.parse import urlparse
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        pages_to_scan = [base + "/"]
        if self.discovery:
            for page in (getattr(self.discovery, 'pages', []) or [])[:15]:
                pages_to_scan.append(page if page.startswith("http") else base + page)

        seen_fingerprints = set()

        for url in pages_to_scan[:20]:
            try:
                resp = client.get(url, timeout=timeout)
                if not resp:
                    continue
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                self._scan_text(body, url, findings, seen_fingerprints)
            except Exception:
                continue

        js_files = getattr(self.discovery, 'js_files', []) or []
        for js_url in js_files[:20]:
            try:
                resp = client.get(js_url, timeout=timeout)
                if not resp:
                    continue
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                self._scan_text(body, js_url, findings, seen_fingerprints)
            except Exception:
                continue

        return findings

    def _scan_text(self, text: str, source: str, findings: list, seen: set):
        for pattern, name, severity in self.SECRET_PATTERNS:
            matches = re.findall(pattern, text)
            for match in matches:
                fp = f"{name}:{match[:20]}"
                if fp in seen:
                    continue
                seen.add(fp)
                findings.append(Finding(
                    title=f"Exposed Secret: {name}",
                    severity=severity,
                    confidence=85,
                    target=source,
                    description=f"Found what appears to be a {name} in the response.",
                    module=self.name,
                    evidence=f"Pattern matched: {match[:40]}...",
                    remediation="Remove secrets from client-facing code.",
                    cwe="CWE-798",
                ))
