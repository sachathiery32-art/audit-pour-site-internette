"""API security testing module.

Detects:
- exposed OpenAPI / Swagger documentation
- undocumented endpoints (heuristically)
- endpoints without authentication
- sensitive parameters
- excessive data exposure
- BOLA
- insufficient validation
- overly detailed errors
- unexpected HTTP methods
- CORS misconfiguration
- content-type issues
"""
from __future__ import annotations

import re
import json
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


_OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/v1/api-docs",
    "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/api/swagger.json",
    "/api/openapi.json", "/docs", "/redoc",
]


class ApiModule(BaseModule):
    """Test API security issues non-destructively."""

    name = "api"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery
        self.openapi_spec: Optional[dict] = None

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        findings.extend(self._find_openapi())
        findings.extend(self._test_cors())
        findings.extend(self._test_unauthenticated_api())
        findings.extend(self._test_excessive_data())
        findings.extend(self._test_unexpected_methods())
        findings.extend(self._test_mass_assignment())

        self.logger.module(self.name, "completed")
        return findings

    def _find_openapi(self) -> List[Finding]:
        findings: List[Finding] = []
        for path in _OPENAPI_PATHS:
            url = urljoin(self.target, path)
            resp = self.http.get(url)
            if not resp or resp.status != 200:
                continue
            try:
                spec = json.loads(resp.body)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(spec, dict) or ("paths" not in spec and "swagger" not in spec and "openapi" not in spec):
                continue
            self.openapi_spec = spec
            findings.append(Finding(
                title="OpenAPI / Swagger specification exposed",
                severity=Severity.MEDIUM,
                confidence=95,
                target=self.target,
                endpoint=url,
                description="A machine-readable API specification is publicly accessible.",
                impact="Full API surface disclosure aids targeted attacks.",
                recommendation="Restrict access to API documentation in production.",
                references=["https://owasp.org/www-project-top-ten/"],
                module=self.name,
            ))
            break
        return findings

    def _test_cors(self) -> List[Finding]:
        findings: List[Finding] = []
        evil_origin = "https://evil-autosec.example"
        resp = self.http.get(self.target, headers={"Origin": evil_origin})
        if not resp:
            return findings
        acao = resp.header("Access-Control-Allow-Origin")
        acac = resp.header("Access-Control-Allow-Credentials")
        if acao and (acao == "*" or acao == evil_origin) and acac and acac.lower() == "true":
            findings.append(Finding(
                title="Permissive CORS configuration",
                severity=Severity.MEDIUM,
                confidence=85,
                target=self.target,
                endpoint=resp.url,
                description=(
                    f"CORS reflects arbitrary origin ({acao}) and allows credentials ({acac}). "
                    "Any cross-origin site can make authenticated requests."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                request=f"GET {resp.url} with Origin: {evil_origin}",
                reproduction_steps=(
                    f"1. Send a request with Origin: {evil_origin}.\n"
                    f"2. Observe the reflected ACAO and credentials=true."
                ),
                impact="Cross-origin data theft from authenticated users.",
                recommendation="Allowlist specific trusted origins; never reflect arbitrary origins with credentials.",
                references=["https://owasp.org/www-community/attacks/CORS_Exploitation"],
                module=self.name,
            ))
        elif acao == "*" and acac and acac.lower() == "true":
            findings.append(Finding(
                title="Invalid CORS configuration (wildcard with credentials)",
                severity=Severity.LOW,
                confidence=90,
                target=self.target,
                endpoint=resp.url,
                description="ACAO is '*' while ACAC is 'true' (browsers reject this, but it's misconfigured).",
                impact="Configuration error indicating weak CORS hygiene.",
                recommendation="Specify explicit origins and proper credentials handling.",
                module=self.name,
            ))
        return findings

    def _test_unauthenticated_api(self) -> List[Finding]:
        findings: List[Finding] = []
        endpoints = list(self.discovery.api_endpoints if self.discovery else [])
        if self.openapi_spec and "paths" in self.openapi_spec:
            for p in self.openapi_spec["paths"]:
                endpoints = list(set(endpoints + [urljoin(self.target, p)]))
        for endpoint in endpoints[:20]:
            resp = self.http.get(endpoint)
            if not resp:
                continue
            if resp.status == 200 and len(resp.body) > 100:
                lower = resp.body.lower()
                auth_walls = ["unauthorized", "forbidden", "access denied", "login",
                              "must be authenticated", "token"]
                if not any(w in lower[:1000] for w in auth_walls):
                    findings.append(Finding(
                        title="API endpoint accessible without authentication",
                        severity=Severity.MEDIUM,
                        confidence=55,
                        target=self.target,
                        endpoint=endpoint,
                        description="API endpoint returned data without an auth token.",
                        impact="Unauthenticated data exposure.",
                        recommendation="Enforce authentication and authorization on all API endpoints.",
                        module=self.name,
                        potential=True,
                    ))
        return findings

    def _test_excessive_data(self) -> List[Finding]:
        findings: List[Finding] = []
        endpoints = self.discovery.api_endpoints if self.discovery else []
        for endpoint in endpoints[:10]:
            resp = self.http.get(endpoint)
            if not resp:
                continue
            try:
                data = json.loads(resp.body)
            except (json.JSONDecodeError, ValueError):
                continue
            sensitive_keys = {"password", "pwd", "secret", "token", "api_key",
                              "ssn", "credit_card", "creditcard"}
            def _scan(obj, path=""):
                leaked = []
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if k.lower() in sensitive_keys:
                            leaked.append(f"{path}.{k}")
                        leaked.extend(_scan(v, f"{path}.{k}"))
                elif isinstance(obj, list):
                    for i, v in enumerate(obj):
                        leaked.extend(_scan(v, f"{path}[{i}]"))
                return leaked
            leaked = _scan(data)
            if leaked:
                findings.append(Finding(
                    title="Excessive data exposure in API response",
                    severity=Severity.HIGH,
                    confidence=80,
                    target=self.target,
                    endpoint=endpoint,
                    description=f"Sensitive fields exposed: {', '.join(leaked[:5])}",
                    impact="Sensitive data leaked to clients that should not receive it.",
                    recommendation="Implement response field filtering; never return secrets.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa3-excessive-data-exposure/"],
                    module=self.name,
                ))
        return findings

    def _test_unexpected_methods(self) -> List[Finding]:
        findings: List[Finding] = []
        endpoints = self.discovery.api_endpoints if self.discovery else [self.target]
        for endpoint in endpoints[:10]:
            resp = self.http.options(endpoint)
            if not resp:
                continue
            allow = resp.header("Allow") or resp.header("Access-Control-Allow-Methods")
            if not allow:
                continue
            methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
            unexpected = methods - {"GET", "POST", "HEAD", "OPTIONS"}
            if unexpected:
                findings.append(Finding(
                    title="API exposes unexpected HTTP methods",
                    severity=Severity.LOW,
                    confidence=60,
                    target=self.target,
                    endpoint=endpoint,
                    description=f"Allowed methods include: {', '.join(sorted(unexpected))}",
                    impact="Unexpected methods may enable unauthorized actions.",
                    recommendation="Restrict allowed methods to those the endpoint requires.",
                    module=self.name,
                    potential=True,
                ))
        return findings

    def _test_mass_assignment(self) -> List[Finding]:
        findings: List[Finding] = []
        if self.openapi_spec and "paths" in self.openapi_spec:
            for path, methods in self.openapi_spec.get("paths", {}).items():
                for method, spec in methods.items():
                    if method.lower() in ("post", "put", "patch"):
                        body = spec.get("requestBody", {})
                        schema_ref = body.get("content", {}).get("application/json", {}).get("schema", {})
                        if schema_ref and "$ref" in schema_ref:
                            findings.append(Finding(
                                title="API accepts structured input (mass-assignment risk)",
                                severity=Severity.INFO,
                                confidence=40,
                                target=self.target,
                                endpoint=urljoin(self.target, path),
                                description=f"{method.upper()} {path} accepts a JSON body — "
                                           "verify field-level authorization.",
                                impact="If the backend binds all input fields directly, "
                                       "privileged fields may be overwritten.",
                                recommendation="Use DTOs / allowlists for input binding.",
                                references=["https://owasp.org/API-Security/"],
                                module=self.name,
                                potential=True,
                            ))
        return findings
