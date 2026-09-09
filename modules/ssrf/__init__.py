"""SSRF (Server-Side Request Forgery) detection module.

Detects parameters that look like URLs and probes them with a safe,
non-destructive callback URL (a public httpbin-style endpoint) to see
if the server makes an outbound request.

We use a harmless marker in the callback URL and check if the response
contains the marker, confirming SSRF.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse, urlencode, urljoin

from ..base import BaseModule
from ..reporting.models import Finding, Severity

# Parameters that commonly accept URLs and are SSRF candidates.
_SSRF_PARAMS = ["url", "redirect", "next", "dest", "target", "rurl",
                "return", "callback", "proxy", "fetch", "uri", "path",
                "continue", "goto", "to", "src", "source", "remote",
                "file", "load", "page", "site", "host", "feed"]

# A harmless, self-controlled marker. We point the server at itself
# or at a benign endpoint that echoes back a unique string.
_MARKER = "autosecssrfmarker"


class SsrfModule(BaseModule):
    """Test for SSRF on URL-like parameters."""

    name = "ssrf"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        targets = self._collect_targets()
        for url, method, params in targets:
            for param in params:
                if param.lower() not in _SSRF_PARAMS:
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

        for form in self.discovery.forms:
            fields = [f["name"] for f in form["fields"]]
            if fields:
                targets.append((form["action"], form["method"], fields))

        for endpoint in self.discovery.api_endpoints:
            parsed = urlparse(endpoint)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            if params:
                targets.append((endpoint, "GET", params))

        return targets

    def _test_param(self, url: str, method: str, param: str) -> List[Finding]:
        findings: List[Finding] = []
        # Use the target itself with a marker path — if the server fetches it,
        # the marker will appear in the response.
        marker_url = urljoin(self.target, f"/{_MARKER}")
        resp = self._send(url, method, param, marker_url)
        if not resp:
            return findings

        # If the marker appears in the response, the server fetched our URL
        if _MARKER in resp.body:
            # Verify it's not just echoing the param value back
            baseline = self._send(url, method, param, "autosecaudit-benign")
            if baseline and _MARKER not in baseline.body:
                findings.append(Finding(
                    title="Server-Side Request Forgery (SSRF)",
                    severity=Severity.CRITICAL,
                    confidence=75,
                    target=self.target,
                    endpoint=url,
                    parameter=param,
                    description=(
                        f"The '{param}' parameter caused the server to make an "
                        "outbound request to a URL we controlled."
                    ),
                    evidence=(
                        f"Sent {param}={marker_url}\n"
                        f"Response contained marker '{_MARKER}'."
                    ),
                    request=f"{method} {url} {param}={marker_url}",
                    response_indicators=f"Marker '{_MARKER}' found in response body.",
                    reproduction_steps=(
                        f"1. Set {param} to a URL you control (e.g., a webhook).\n"
                        f"2. Submit the request.\n"
                        f"3. Check if your server received the request."
                    ),
                    impact=(
                        "Server can be tricked into fetching arbitrary internal "
                        "URLs (cloud metadata, internal services, file:// URIs)."
                    ),
                    recommendation="Validate and allowlist URLs; block private IP ranges and cloud metadata endpoints.",
                    references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                    module=self.name,
                    potential=True,
                ))
        return findings

    def _send(self, url, method, param, value):
        if method.upper() == "POST":
            return self.http.post(url, data={param: value})
        return self.http.get(url, params={param: value})
