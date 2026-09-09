"""Open redirect detection module.

Tests redirect-like parameters by supplying a safe external URL and
checking whether the response redirects to it.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from ..base import BaseModule
from ..reporting.models import Finding, Severity


_REDIRECT_PARAMS = ["url", "redirect", "next", "dest", "target", "rurl",
                    "return", "goto", "continue", "to", "from", "back",
                    "returnurl", "returnto", "redirect_url", "redirect_to"]

_SAFE_EXTERNAL = "https://evil-autosec-redirect.example"


class OpenRedirectModule(BaseModule):
    """Test for open redirect vulnerabilities."""

    name = "redirect"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        targets = self._collect_targets()
        for url, method, params in targets:
            for param in params:
                if param.lower() not in _REDIRECT_PARAMS:
                    continue
                findings.extend(self._test_param(url, method, param))

        self.logger.module(self.name, "completed")
        return findings

    def _collect_targets(self):
        targets = []
        if not self.discovery:
            parsed = urlparse(self.target)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            if params:
                targets.append((self.target, "GET", params))
            return targets

        for page in self.discovery.pages:
            parsed = urlparse(page)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            if params:
                targets.append((page, "GET", params))

        return targets

    def _test_param(self, url: str, method: str, param: str) -> List[Finding]:
        findings: List[Finding] = []
        if method.upper() == "POST":
            resp = self.http.post(url, data={param: _SAFE_EXTERNAL})
        else:
            resp = self.http.get(url, params={param: _SAFE_EXTERNAL})
        if not resp:
            return findings

        # Check Location header for redirect
        location = resp.header("Location")
        if location and "evil-autosec-redirect" in location:
            findings.append(Finding(
                title="Open redirect",
                severity=Severity.MEDIUM,
                confidence=85,
                target=self.target,
                endpoint=url,
                parameter=param,
                description=f"The '{param}' parameter redirects to an arbitrary external URL.",
                evidence=f"Sent {param}={_SAFE_EXTERNAL}\nLocation: {location}",
                request=f"{method} {url} {param}={_SAFE_EXTERNAL}",
                response_indicators=f"Location header: {location}",
                reproduction_steps=f"Set {param} to an external URL; observe the redirect.",
                impact="Phishing via trusted domain; OAuth token theft via redirect.",
                recommendation="Validate redirect targets against an allowlist; do not accept absolute URLs.",
                references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"],
                module=self.name,
            ))
        elif resp.redirected and "evil-autosec-redirect" in resp.final_url:
            findings.append(Finding(
                title="Open redirect",
                severity=Severity.MEDIUM,
                confidence=75,
                target=self.target,
                endpoint=url,
                parameter=param,
                description=f"The '{param}' parameter caused a redirect to an external URL.",
                evidence=f"Final URL: {resp.final_url}",
                request=f"{method} {url} {param}={_SAFE_EXTERNAL}",
                response_indicators=f"Redirected to: {resp.final_url}",
                reproduction_steps=f"Set {param} to an external URL; follow the redirect.",
                impact="Phishing via trusted domain; OAuth token theft.",
                recommendation="Validate redirect targets against an allowlist.",
                references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"],
                module=self.name,
                potential=True,
            ))
        return findings
