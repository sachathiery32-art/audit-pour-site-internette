"""Race condition detection module.

Tests for:
- Concurrent requests to state-changing endpoints
- Inconsistent responses under concurrency
"""
from __future__ import annotations

import concurrent.futures
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class RaceConditionModule(BaseModule):
    """Detect race condition vulnerabilities via concurrent requests."""

    name = "race_condition"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        endpoints = []
        if self.discovery:
            for ep in (getattr(self.discovery, 'api_endpoints', []) or [])[:10]:
                endpoints.append(ep if ep.startswith("http") else base + ep)

        for ep in endpoints[:5]:
            try:
                responses = []

                def fetch():
                    try:
                        return client.get(ep, timeout=timeout)
                    except Exception:
                        return None

                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(fetch) for _ in range(5)]
                    for f in concurrent.futures.as_completed(futures):
                        resp = f.result()
                        if resp:
                            body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                            responses.append({
                                "status": resp.status_code if hasattr(resp, 'status_code') else 0,
                                "body_len": len(body),
                            })

                if len(responses) < 3:
                    continue

                status_codes = set(r["status"] for r in responses)
                if len(status_codes) > 1:
                    findings.append(Finding(
                        title="Race Condition - Inconsistent Status Codes",
                        severity=Severity.MEDIUM,
                        confidence=60,
                        target=target,
                        endpoint=ep,
                        description=f"Concurrent requests returned different HTTP status codes: {status_codes}.",
                        module=self.name,
                        evidence=f"Status codes observed: {status_codes}",
                        remediation="Use proper locking/serialization for state-changing operations.",
                        cwe="CWE-362",
                    ))
            except Exception:
                continue

        return findings
