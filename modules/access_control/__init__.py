"""Access control testing module.

Tests (non-destructively):
- IDOR / BOLA via parameter manipulation
- unauthenticated access to protected resources
- privilege differences
- exposed admin endpoints
- vertical and horizontal access control

Authenticated tests use *only* test credentials explicitly supplied
by the user in config.yaml.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse, urljoin

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity
from modules.utils import BaselineCache, is_spa_catchall


_ADMIN_PATHS = [
    "/admin", "/administrator", "/admin.php", "/wp-admin", "/manager/html",
    "/console", "/phpmyadmin", "/adminpanel", "/dashboard/admin",
    "/wp-login.php", "/cp", "/controlpanel", "/admin/login",
]

_NUMERIC_ID_RE = re.compile(r'(\d+)')


class AccessControlModule(BaseModule):
    """Test access control issues non-destructively."""

    name = "access_control"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery
        self._baseline_cache = BaselineCache(http, target)

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        findings.extend(self._test_idor())
        findings.extend(self._test_unauthenticated_access())
        findings.extend(self._test_admin_endpoints())

        self.logger.module(self.name, "completed")
        return findings

    def _test_idor(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.discovery:
            return findings
        for page in self.discovery.pages:
            parsed = urlparse(page)
            params = [p.split("=") for p in parsed.query.split("&") if "=" in p]
            for key, value in params:
                if not _NUMERIC_ID_RE.fullmatch(value):
                    continue
                num = int(value)
                for delta in (-1, 1):
                    new_val = str(max(0, num + delta))
                    test_url = page.replace(f"{key}={value}", f"{key}={new_val}")
                    resp = self.http.get(test_url)
                    if not resp:
                        continue
                    # skip SPA catch-all (returns same HTML for every path)
                    if is_spa_catchall(resp.body, self._baseline_cache):
                        continue
                    if resp.status == 200 and len(resp.body) > 500:
                        auth_indicators = ["login", "sign in", "unauthorized", "forbidden",
                                           "access denied", "403", "log in"]
                        if not any(ind in resp.body.lower()[:2000] for ind in auth_indicators):
                            findings.append(Finding(
                                title="Potential IDOR / BOLA",
                                severity=Severity.HIGH,
                                confidence=55,
                                target=self.target,
                                endpoint=test_url,
                                parameter=key,
                                description=(
                                    f"Changing {key} from {value} to {new_val} returned a "
                                    "200 response without an authentication wall."
                                ),
                                evidence=f"Original: {page}\nMutated: {test_url}\nStatus: {resp.status}",
                                request=f"GET {test_url}",
                                reproduction_steps=(
                                    f"1. Access {page}\n"
                                    f"2. Change {key} to {new_val}\n"
                                    f"3. Observe the response."
                                ),
                                impact="Unauthorized access to other users' resources.",
                                recommendation=(
                                    "Enforce object-level authorization on every request; "
                                    "verify the caller owns the requested resource."
                                ),
                                references=["https://owasp.org/www-project-top-ten/"],
                                module=self.name,
                                potential=True,
                            ))
                            break
        return findings

    def _test_unauthenticated_access(self) -> List[Finding]:
        findings: List[Finding] = []
        sensitive_paths = ["/api/users", "/api/account", "/account", "/profile",
                           "/settings", "/user", "/users", "/api/admin"]
        for path in sensitive_paths:
            url = urljoin(self.target, path)
            resp = self.http.get(url)
            if not resp:
                continue
            # skip SPA catch-all
            if is_spa_catchall(resp.body, self._baseline_cache):
                continue
            if resp.status == 200 and len(resp.body) > 200:
                lower = resp.body.lower()
                auth_walls = ["login", "sign in", "unauthorized", "forbidden",
                              "access denied", "log in", "401", "must be logged in"]
                if not any(w in lower[:1500] for w in auth_walls):
                    findings.append(Finding(
                        title="Sensitive endpoint accessible without authentication",
                        severity=Severity.HIGH,
                        confidence=60,
                        target=self.target,
                        endpoint=url,
                        description="The endpoint returned content without requiring authentication.",
                        evidence=f"GET {url} -> {resp.status}, {len(resp.body)} bytes",
                        request=f"GET {url}",
                        reproduction_steps=f"Access {url} without any credentials.",
                        impact="Unauthenticated data exposure.",
                        recommendation="Require authentication on all sensitive endpoints.",
                        module=self.name,
                        potential=True,
                    ))
        return findings

    def _test_admin_endpoints(self) -> List[Finding]:
        findings: List[Finding] = []
        for path in _ADMIN_PATHS:
            url = urljoin(self.target, path)
            resp = self.http.get(url)
            if not resp:
                continue
            # skip SPA catch-all (returns same HTML for every path)
            if is_spa_catchall(resp.body, self._baseline_cache):
                continue
            if resp.status == 200:
                lower = resp.body.lower()
                login_indicators = ["login", "password", "sign in", "username", "log in"]
                has_login = any(ind in lower for ind in login_indicators)
                if not has_login and len(resp.body) > 200:
                    findings.append(Finding(
                        title="Administrative interface exposed without authentication",
                        severity=Severity.HIGH,
                        confidence=70,
                        target=self.target,
                        endpoint=url,
                        description=f"Admin path {path} returned content without a login challenge.",
                        evidence=f"GET {url} -> {resp.status}, {len(resp.body)} bytes",
                        request=f"GET {url}",
                        reproduction_steps=f"Access {url}; note the absence of authentication.",
                        impact="Administrative functionality reachable without credentials.",
                        recommendation="Restrict admin interfaces via network ACL and authentication.",
                        module=self.name,
                        potential=True,
                    ))
                elif has_login:
                    findings.append(Finding(
                        title="Administrative interface exposed",
                        severity=Severity.INFO,
                        confidence=90,
                        target=self.target,
                        endpoint=url,
                        description=f"Admin path {path} is reachable and presents a login form.",
                        impact="Attack surface for credential attacks.",
                        recommendation="Restrict access by network and add rate limiting.",
                        module=self.name,
                    ))
        return findings
