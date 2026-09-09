"""Sensitive parameter mining module.

Mines hidden or undocumented parameters by:
- testing common parameter names on every endpoint
- checking JS files for parameter references
- guessing via common naming conventions

This is the red-team "parameter discovery" phase.
"""
from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urlparse, urlencode

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


# High-value parameters to probe
_HIDDEN_PARAMS = [
    "admin", "debug", "test", "internal", "debug_mode", "verbose",
    "role", "is_admin", "admin_mode", "dev", "staging", "mock",
    "callback", "redirect", "next", "url", "file", "path",
    "cmd", "exec", "command", "system", "source",
    "user_id", "userid", "uid", "account_id", "owner",
    "token", "key", "secret", "password", "auth",
    "id", "uuid", "guid", "ref",
    "name", "email", "username", "login",
    "file", "filename", "document", "attachment",
    "api_key", "apikey", "access_token",
    "preview", "draft", "template",
    "bypass", "skip", "ignore", "override",
]

_JS_PARAM_RE = re.compile(
    r'(?:params|data|query|body)\s*[=:]\s*\{([^}]+)\}',
    re.IGNORECASE,
)
_PARAM_NAME_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*):')


class ParamMiningModule(BaseModule):
    """Mine for hidden parameters on discovered endpoints."""

    name = "param_mining"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        # mine parameters from JS
        js_params = self._mine_js_params()

        # test endpoints for hidden parameters that change behavior
        endpoints = self._collect_endpoints()
        for url in endpoints[:15]:
            findings.extend(self._probe_params(url, js_params))

        self.logger.module(self.name, "completed")
        return findings

    def _mine_js_params(self) -> Set[str]:
        """Extract parameter names from JS files."""
        params: Set[str] = set()
        if not self.discovery:
            return params
        for js_url in (self.discovery.js_files or [])[:20]:
            resp = self.http.get(js_url)
            if not resp:
                continue
            for m in _JS_PARAM_RE.finditer(resp.body):
                block = m.group(1)
                for pm in _PARAM_NAME_RE.finditer(block):
                    params.add(pm.group(1))
        return params

    def _collect_endpoints(self) -> List[str]:
        endpoints = [self.target]
        if self.discovery:
            endpoints.extend(self.discovery.api_endpoints[:10])
            endpoints.extend(self.discovery.pages[:10])
        return list(set(endpoints))

    def _probe_params(self, url: str, js_params: Set[str]) -> List[Finding]:
        """Send a benign value for each hidden param and compare to baseline."""
        findings: List[Finding] = []
        baseline = self.http.get(url)
        if not baseline:
            return findings

        # combine predefined and JS-mined params
        all_params = set(_HIDDEN_PARAMS) | js_params
        base_len = len(baseline.body)

        for param in list(all_params)[:30]:
            resp = self.http.get(url, params={param: "autosec-probe"})
            if not resp:
                continue
            # if response length differs significantly, the param might be accepted
            diff = abs(len(resp.body) - base_len)
            if diff > 200 and resp.status == 200:
                # verify it's not just a random fluctuation
                verify = self.http.get(url, params={param + "_fake": "autosec-probe"})
                if verify and abs(len(verify.body) - base_len) < 50:
                    findings.append(Finding(
                        title=f"Hidden parameter detected: '{param}'",
                        severity=Severity.LOW,
                        confidence=50,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description=(
                            f"The '{param}' parameter changed the response by {diff} bytes "
                            "compared to baseline, suggesting it is accepted by the server."
                        ),
                        evidence=(
                            f"baseline_len={base_len} param_len={len(resp.body)} diff={diff}"
                        ),
                        request=f"GET {url}?{param}=autosec-probe",
                        reproduction_steps=f"Compare response with and without {param}.",
                        impact="Hidden parameters may enable access control bypass or logic flaws.",
                        recommendation="Audit all accepted parameters; remove undocumented ones.",
                        module=self.name,
                        potential=True,
                    ))
        return findings
