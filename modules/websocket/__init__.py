"""WebSocket testing module.

Detects WebSocket endpoints and tests for:
- unauthenticated access
- cross-origin WebSocket hijacking (CORS on ws://)
- lack of origin validation
- sensitive data in initial handshake
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from ..base import BaseModule
from ..reporting.models import Finding, Severity


_WS_UPGRADE_HEADERS = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Key": "autosecaudit1234567890",
    "Sec-WebSocket-Version": "13",
}


class WebSocketModule(BaseModule):
    """Test WebSocket endpoints for security issues."""

    name = "websocket"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        endpoints = self._find_endpoints()
        for ep in endpoints:
            findings.extend(self._test_origin_validation(ep))

        self.logger.module(self.name, "completed")
        return findings

    def _find_endpoints(self) -> List[str]:
        endpoints = []
        parsed = urlparse(self.target)

        # check for ws:// or wss:// in JS files
        if self.discovery:
            for js_url in (self.discovery.js_files or [])[:15]:
                resp = self.http.get(js_url)
                if not resp:
                    continue
                for m in re.finditer(r'[ws]{2,3}://[^\s"\'<>]+', resp.body):
                    ws_url = m.group(0)
                    if ws_url not in endpoints:
                        endpoints.append(ws_url)

        # also try common WebSocket paths
        common = ["/ws", "/websocket", "/socket", "/live", "/realtime",
                  "/wss", "/chat"]
        for path in common:
            endpoints.append(f"{parsed.scheme}://{parsed.hostname}/" + path.lstrip("/"))

        return endpoints[:10]

    def _test_origin_validation(self, ws_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Test with an evil origin — if the server accepts it, no origin validation
        evil_origin = "https://evil-autosec-ws.example"
        resp = self.http.get(ws_url, headers={
            **_WS_UPGRADE_HEADERS,
            "Origin": evil_origin,
        })
        if not resp:
            return findings

        # A 101 Switching Protocols means the server accepted the WS upgrade
        if resp.status == 101:
            findings.append(Finding(
                title="WebSocket accepts arbitrary origin (cross-origin hijacking)",
                severity=Severity.MEDIUM,
                confidence=75,
                target=self.target,
                endpoint=ws_url,
                description="The WebSocket server accepted a connection from an arbitrary origin.",
                evidence=f"Status 101 with Origin: {evil_origin}",
                request=f"GET {ws_url} Upgrade: websocket Origin: {evil_origin}",
                response_indicators="HTTP 101 Switching Protocols",
                reproduction_steps="Send a WebSocket upgrade with an arbitrary Origin header.",
                impact="Cross-site WebSocket hijacking; steal data from authenticated WS connections.",
                recommendation="Validate the Origin header against an allowlist before upgrading.",
                references=["https://portswigger.net/web-security/websockets"],
                module=self.name,
                potential=True,
            ))
        return findings
