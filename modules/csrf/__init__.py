"""CSRF detection module.

Tests for:
- Forms performing state-changing actions without CSRF tokens
- SameSite cookie attribute missing on session cookies
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class CSRFModule(BaseModule):
    """Detect CSRF vulnerabilities in forms and state-changing endpoints."""

    name = "csrf"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    STATE_CHANGING_PATTERNS = re.compile(
        r'(password|email|delete|remove|update|create|edit|transfer|'
        r'payment|admin|settings|profile|account|subscribe|unsubscribe|'
        r'purchase|order|cancel|approve|reject)',
        re.IGNORECASE,
    )
    TOKEN_NAMES = re.compile(
        r'(csrf|xsrf|_token|authenticity_token|csrfmiddlewaretoken|'
        r'__RequestVerificationToken|csrf_token|antiForgery)',
        re.IGNORECASE,
    )
    SENSITIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        # Check session cookies for SameSite
        if self.discovery:
            for cookie in (getattr(self.discovery, 'cookies', []) or []):
                name = cookie.get("name", "")
                samesite = cookie.get("samesite", "")
                is_session = any(kw in name.lower() for kw in ["session", "sess", "sid", "auth", "token"])
                if is_session and not samesite:
                    findings.append(Finding(
                        title="Session Cookie Missing SameSite Attribute",
                        severity=Severity.LOW,
                        confidence=85,
                        target=target,
                        description=(
                            f"Session cookie '{name}' lacks the SameSite attribute. "
                            "Without SameSite=Lax or SameSite=Strict, the cookie will be "
                            "sent on cross-site requests, enabling CSRF attacks."
                        ),
                        module=self.name,
                        remediation="Set SameSite=Lax or SameSite=Strict on all session cookies.",
                        cwe="CWE-1275",
                    ))

        # Check main page for forms without CSRF tokens
        try:
            resp = client.get(base + "/", timeout=timeout)
            if resp:
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")
                if "<form" in body.lower():
                    has_csrf = bool(self.TOKEN_NAMES.search(body))
                    forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
                    for form_content in forms:
                        method_match = re.search(r'method=["\']?(\w+)["\']?', body, re.IGNORECASE)
                        method = method_match.group(1).upper() if method_match else "GET"
                        if method in self.SENSITIVE_METHODS and not has_csrf:
                            action_match = re.search(r'action=["\']([^"\']*)["\']', body, re.IGNORECASE)
                            action = action_match.group(1) if action_match else "/"
                            findings.append(Finding(
                                title="Missing CSRF Token",
                                severity=Severity.MEDIUM,
                                confidence=75,
                                target=target,
                                endpoint=base + action,
                                description=(
                                    f"State-changing form ({method}) does not include a CSRF token. "
                                    "An attacker could craft a page that submits this form on behalf "
                                    "of an authenticated user."
                                ),
                                module=self.name,
                                remediation="Add a unique, server-validated CSRF token to all state-changing forms.",
                                cwe="CWE-352",
                            ))
                            break
        except Exception:
            pass

        return findings
