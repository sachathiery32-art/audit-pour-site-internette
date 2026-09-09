"""OAuth / OpenID Connect security detection module.

Tests for:
- Missing state parameter
- Missing PKCE protection
- OpenID configuration exposure
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class OAuthModule(BaseModule):
    """Detect OAuth/OIDC security misconfigurations."""

    name = "oauth"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    OAUTH_PATHS = ["/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
                   "/.well-known/openid-configuration"]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check for OpenID configuration
        try:
            resp = client.get(base + "/.well-known/openid-configuration", timeout=timeout)
            if resp and hasattr(resp, 'status_code') and resp.status_code == 200:
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                if "registration_endpoint" in body:
                    findings.append(Finding(
                        title="OAuth Dynamic Client Registration Enabled",
                        severity=Severity.MEDIUM,
                        confidence=70,
                        target=target,
                        endpoint=base + "/.well-known/openid-configuration",
                        description="OpenID configuration exposes a registration endpoint.",
                        module=self.name,
                        remediation="Disable dynamic registration or require admin approval.",
                        cwe="CWE-601",
                    ))
        except Exception:
            pass

        # Check for authorization pages
        for path in self.OAUTH_PATHS[:3]:
            try:
                resp = client.get(base + path, timeout=timeout)
                if not resp:
                    continue
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                status = resp.status_code if hasattr(resp, 'status_code') else 0

                if status == 200 and "authorize" in path.lower():
                    has_state = bool(re.search(r'name=["\']state["\']', body))
                    has_pkce = bool(re.search(r'name=["\']code_challenge["\']', body))

                    if not has_state:
                        findings.append(Finding(
                            title="OAuth Missing State Parameter",
                            severity=Severity.HIGH,
                            confidence=75,
                            target=target,
                            endpoint=base + path,
                            description="OAuth authorization endpoint does not use a state parameter.",
                            module=self.name,
                            remediation="Always use a cryptographically random state parameter.",
                            cwe="CWE-352",
                        ))

                    if not has_pkce:
                        findings.append(Finding(
                            title="OAuth Missing PKCE Protection",
                            severity=Severity.MEDIUM,
                            confidence=60,
                            target=target,
                            endpoint=base + path,
                            description="OAuth authorization endpoint does not use PKCE.",
                            module=self.name,
                            remediation="Implement PKCE (RFC 7636) for all OAuth flows.",
                            cwe="CWE-345",
                        ))
            except Exception:
                continue

        return findings
