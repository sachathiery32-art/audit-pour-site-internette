"""Authentication and session testing module.

Tests (non-destructively):
- session cookie configuration
- session expiration behavior
- missing CSRF protection on state-changing forms
- logout handling
- session fixation markers
- abnormal session reuse

No brute force. Only a small number of controlled probes with user-supplied
test credentials when configured.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class AuthSessionModule(BaseModule):
    """Test authentication and session-related issues."""

    name = "auth_session"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        findings.extend(self._test_csrf())
        findings.extend(self._test_session_expiry())
        findings.extend(self._test_logout())
        findings.extend(self._test_session_fixation())

        self.logger.module(self.name, "completed")
        return findings

    def _test_csrf(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.discovery:
            return findings
        for form in self.discovery.forms:
            if form["method"].upper() != "POST":
                continue
            field_names = [f["name"].lower() for f in form["fields"]]
            csrf_indicators = ["csrf", "token", "_token", "authenticity_token", "requesttoken"]
            has_csrf = any(any(ind in name for ind in csrf_indicators) for name in field_names)
            if not has_csrf:
                param_list = [f["name"] for f in form["fields"][:3]]
                findings.append(Finding(
                    title="Missing CSRF token on state-changing form",
                    severity=Severity.MEDIUM,
                    confidence=70,
                    target=self.target,
                    endpoint=form["action"],
                    parameter=", ".join(param_list),
                    description=(
                        f"A {form['method']} form at {form['action']} has no "
                        "anti-CSRF token field."
                    ),
                    evidence=f"Form fields: {field_names}",
                    request=f"{form['method']} {form['action']}",
                    reproduction_steps=(
                        "1. Inspect the form HTML.\n"
                        "2. Confirm no token field exists.\n"
                        "3. Submit the form cross-site to verify forgery."
                    ),
                    impact="Authenticated users can be tricked into submitting unwanted actions.",
                    recommendation="Add per-session CSRF tokens to all state-changing forms.",
                    references=["https://owasp.org/www-community/attacks/csrf"],
                    module=self.name,
                    potential=True,
                ))
        return findings

    def _test_session_expiry(self) -> List[Finding]:
        findings: List[Finding] = []
        resp = self.http.get(self.target)
        if not resp:
            return findings
        set_cookie = resp.header("Set-Cookie")
        if not set_cookie:
            return findings
        has_session_cookie = any(
            re.match(r'^(JSESSIONID|PHPSESSID|sid|sessionid|connect\.sid|_session)=',
                     c, re.IGNORECASE) for c in re.split(r',\s*(?=[A-Za-z0-9_-]+=)', set_cookie)
        )
        if has_session_cookie and "expires=" not in set_cookie.lower():
            findings.append(Finding(
                title="Session cookie without explicit expiry",
                severity=Severity.LOW,
                confidence=60,
                target=self.target,
                endpoint=resp.url,
                description="A session cookie is set without an Expires or Max-Age attribute.",
                impact="Session cookies may persist longer than intended on browser close.",
                recommendation="Set explicit Expires/Max-Age consistent with session lifetime.",
                module=self.name,
                potential=True,
            ))
        return findings

    def _test_logout(self) -> List[Finding]:
        findings: List[Finding] = []
        logout_paths = ["/logout", "/logout.php", "/auth/logout", "/account/logout",
                        "/api/logout", "/signout"]
        for path in logout_paths:
            url = urljoin(self.target, path)
            resp = self.http.get(url)
            if not resp:
                continue
            if resp.status == 200:
                findings.append(Finding(
                    title="Logout via GET request",
                    severity=Severity.LOW,
                    confidence=60,
                    target=self.target,
                    endpoint=url,
                    description="Logout is reachable via GET without CSRF protection.",
                    impact="An attacker can log users out via cross-site request.",
                    recommendation="Require POST and a CSRF token for logout.",
                    module=self.name,
                    potential=True,
                ))
                break
        return findings

    def _test_session_fixation(self) -> List[Finding]:
        findings: List[Finding] = []
        login_paths = ["/login", "/login.php", "/auth/login", "/account/login"]
        for path in login_paths:
            url = urljoin(self.target, path)
            before = self.http.get(url)
            after = self.http.get(url)
            if not before or not after:
                continue
            before_cookie = before.header("Set-Cookie")
            after_cookie = after.header("Set-Cookie")
            if before_cookie and after_cookie and before_cookie == after_cookie:
                sid_match = re.search(r'(JSESSIONID|PHPSESSID|sid|sessionid)=([a-zA-Z0-9]+)', before_cookie)
                if sid_match:
                    findings.append(Finding(
                        title="Potential session fixation",
                        severity=Severity.MEDIUM,
                        confidence=50,
                        target=self.target,
                        endpoint=url,
                        description="Session ID did not change between two requests to the login page.",
                        evidence=f"Cookie repeated: {sid_match.group(0)}",
                        impact="If the app reuses the session ID post-login, fixation is possible.",
                        recommendation="Regenerate the session ID upon authentication.",
                        references=["https://owasp.org/www-community/attacks/Session_fixation"],
                        module=self.name,
                        potential=True,
                    ))
                    break
        return findings
