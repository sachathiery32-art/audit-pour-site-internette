"""GraphQL testing module.

Detects:
- exposed GraphQL endpoints
- introspection enabled (full schema leak)
- query batching / DoS potential
- field suggestions (information leak)
"""
from __future__ import annotations

import json
from typing import List
from urllib.parse import urljoin

from ..base import BaseModule
from ..reporting.models import Finding, Severity


_INTROSPECTION_QUERY = {"query": "{__schema{types{name fields{name}}}}"}
_FIELD_SUGGESTION_QUERY = {"query": "{nonExistentField}"}
_BATCH_QUERY = [
    {"query": "{__typename}"},
    {"query": "{__typename}"},
]


class GraphQLModule(BaseModule):
    """Test GraphQL endpoints for common misconfigurations."""

    name = "graphql"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        endpoints = self._find_endpoints()
        for ep in endpoints:
            findings.extend(self._test_introspection(ep))
            findings.extend(self._test_field_suggestions(ep))
            findings.extend(self._test_batching(ep))

        self.logger.module(self.name, "completed")
        return findings

    def _find_endpoints(self) -> List[str]:
        endpoints = []
        # standard paths
        standard = ["/graphql", "/api/graphql", "/graphql.php",
                    "/api/v1/graphql", "/query"]
        for path in standard:
            endpoints.append(urljoin(self.target, path))
        # discovered endpoints that contain "graphql"
        if self.discovery:
            for ep in self.discovery.api_endpoints:
                if "graphql" in ep.lower():
                    endpoints.append(ep)
        # avoid duplicates
        seen = set()
        unique = []
        for ep in endpoints:
            if ep not in seen:
                seen.add(ep)
                unique.append(ep)
        return unique

    def _post(self, url: str, payload) -> object:
        return self.http.post(url, json=payload,
                             headers={"Content-Type": "application/json"})

    def _test_introspection(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        resp = self._post(url, _INTROSPECTION_QUERY)
        if not resp:
            return findings
        try:
            data = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return findings
        if "data" in data and "__schema" in str(data.get("data", {})):
            findings.append(Finding(
                title="GraphQL introspection enabled",
                severity=Severity.MEDIUM,
                confidence=90,
                target=self.target,
                endpoint=url,
                description="The GraphQL endpoint allows introspection, exposing the full schema.",
                evidence=f"Introspection query returned schema data: {str(data)[:300]}",
                request=f"POST {url} {json.dumps(_INTROSPECTION_QUERY)}",
                reproduction_steps="Send an introspection query; receive the full schema.",
                impact="Complete API surface disclosure; attackers see every type and field.",
                recommendation="Disable introspection in production.",
                references=["https://owasp.org/www-project-top-ten/"],
                module=self.name,
            ))
        return findings

    def _test_field_suggestions(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        resp = self._post(url, _FIELD_SUGGESTION_QUERY)
        if not resp:
            return findings
        if "did you mean" in resp.body.lower() or "suggestion" in resp.body.lower():
            findings.append(Finding(
                title="GraphQL field suggestions enabled",
                severity=Severity.LOW,
                confidence=70,
                target=self.target,
                endpoint=url,
                description="The GraphQL server suggests valid field names for invalid queries.",
                evidence=f"Response contains suggestion text: {resp.body[:300]}",
                request=f"POST {url} {json.dumps(_FIELD_SUGGESTION_QUERY)}",
                reproduction_steps="Send a query for a non-existent field; observe suggestions.",
                impact="Schema information leak even with introspection disabled.",
                recommendation="Disable field suggestions in production.",
                module=self.name,
                potential=True,
            ))
        return findings

    def _test_batching(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        resp = self._post(url, _BATCH_QUERY)
        if not resp:
            return findings
        try:
            data = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return findings
        # If the server accepted an array of queries, batching is enabled
        if isinstance(data, list) and len(data) >= 2:
            findings.append(Finding(
                title="GraphQL query batching enabled",
                severity=Severity.LOW,
                confidence=70,
                target=self.target,
                endpoint=url,
                description="The GraphQL server accepts batched queries (array of queries).",
                evidence=f"Batch of 2 queries returned 2 results: {str(data)[:300]}",
                request=f"POST {url} {json.dumps(_BATCH_QUERY)}",
                reproduction_steps="Send an array of queries; observe multiple results.",
                impact="Bypassed rate limiting; potential DoS via large batches.",
                recommendation="Limit batch size or disable batching.",
                module=self.name,
                potential=True,
            ))
        return findings
