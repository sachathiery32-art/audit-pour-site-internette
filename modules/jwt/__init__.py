"""JWT (JSON Web Token) analysis module.

Detects JWTs in cookies, headers, and URL parameters, then analyzes:
- weak signing algorithm (none, HS256 with weak secret)
- missing signature
- sensitive data in payload (base64 is not encryption)
- expired tokens
- algorithm confusion potential (RS256 vs HS256)
"""
from __future__ import annotations

import base64
import json
import re
import time
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from ..base import BaseModule
from ..reporting.models import Finding, Severity


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")


class JwtModule(BaseModule):
    """Analyze JWT tokens found in the application."""

    name = "jwt"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        tokens = self._find_tokens()
        for token, source in tokens:
            findings.extend(self._analyze_token(token, source))

        self.logger.module(self.name, "completed")
        return findings

    def _find_tokens(self) -> List[Tuple[str, str]]:
        """Find JWTs in cookies, URL params, and response bodies."""
        tokens: List[Tuple[str, str]] = []
        seen: set = set()

        # check discovery cookies
        if self.discovery:
            for cookie in (self.discovery.cookies or []):
                name = cookie.get("name", "").lower()
                value = cookie.get("value", "")
                if "token" in name or "jwt" in name or "auth" in name:
                    for m in _JWT_RE.finditer(value):
                        tok = m.group(0)
                        if tok not in seen:
                            seen.add(tok)
                            tokens.append((tok, f"cookie:{cookie.get('name')}"))

        # check response bodies
        resp = self.http.get(self.target)
        if resp:
            for m in _JWT_RE.finditer(resp.body):
                tok = m.group(0)
                if tok not in seen:
                    seen.add(tok)
                    tokens.append((tok, "response body"))

        # check JS files
        if self.discovery:
            for js_url in (self.discovery.js_files or [])[:10]:
                js_resp = self.http.get(js_url)
                if not js_resp:
                    continue
                for m in _JWT_RE.finditer(js_resp.body):
                    tok = m.group(0)
                    if tok not in seen:
                        seen.add(tok)
                        tokens.append((tok, f"JS:{js_url}"))

        return tokens

    def _decode_part(self, part: str) -> Optional[dict]:
        """Decode a base64url JWT part (header or payload)."""
        # add padding
        padded = part + "=" * (4 - len(part) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    def _analyze_token(self, token: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        parts = token.split(".")
        if len(parts) < 2:
            return findings

        header = self._decode_part(parts[0])
        payload = self._decode_part(parts[1])

        if not header or not payload:
            return findings

        algo = header.get("alg", "").upper()

        # Check for 'none' algorithm
        if algo == "NONE" or algo == "":
            findings.append(Finding(
                title="JWT uses 'none' algorithm (unsigned token accepted)",
                severity=Severity.CRITICAL,
                confidence=85,
                target=self.target,
                endpoint=self.target,
                parameter=source,
                description="The JWT allows the 'none' algorithm, meaning unsigned tokens are accepted.",
                evidence=f"Header: {json.dumps(header)}",
                request=f"Token found in {source}",
                reproduction_steps="Forge a JWT with alg:none and no signature.",
                impact="Complete authentication bypass.",
                recommendation="Reject tokens with 'none' algorithm; enforce a strong algorithm.",
                references=["https://owasp.org/www-community/attacks/JSON_Web_Token_(JWT)_attacks"],
                module=self.name,
                potential=True,
            ))

        # Check for missing signature (3 parts expected, but only 2 present)
        if len(parts) < 3 or not parts[2]:
            findings.append(Finding(
                title="JWT has no signature",
                severity=Severity.HIGH,
                confidence=90,
                target=self.target,
                endpoint=self.target,
                parameter=source,
                description="The JWT has no signature part, meaning it is not signed.",
                evidence=f"Token has {len(parts)} parts; expected 3.",
                request=f"Token found in {source}",
                reproduction_steps="Modify the payload and re-submit the unsigned token.",
                impact="Token forgery; authentication bypass.",
                recommendation="Enforce signed tokens; reject unsigned ones.",
                module=self.name,
                potential=True,
            ))

        # Check for sensitive data in payload
        sensitive_keys = {"password", "pwd", "secret", "ssn", "credit",
                          "email", "phone", "address"}
        leaked = [k for k in payload if k.lower() in sensitive_keys]
        if leaked:
            findings.append(Finding(
                title="Sensitive data in JWT payload (base64 is not encryption)",
                severity=Severity.MEDIUM,
                confidence=85,
                target=self.target,
                endpoint=self.target,
                parameter=source,
                description=f"JWT payload contains sensitive keys: {leaked}",
                evidence=f"Payload: {json.dumps(payload)[:300]}",
                request=f"Token found in {source}",
                reproduction_steps="Decode the JWT payload (base64url) to read the data.",
                impact="Sensitive user data is readable by anyone who obtains the token.",
                recommendation="Do not store sensitive data in JWT payloads; use opaque server-side sessions.",
                module=self.name,
            ))

        # Check for expiration
        exp = payload.get("exp")
        if exp:
            try:
                exp_ts = int(exp)
                now_ts = int(time.time())
                if exp_ts < now_ts:
                    findings.append(Finding(
                        title="Expired JWT token in use",
                        severity=Severity.LOW,
                        confidence=80,
                        target=self.target,
                        endpoint=self.target,
                        parameter=source,
                        description=f"Token expired at timestamp {exp_ts}.",
                        evidence=f"exp={exp_ts}, current={now_ts}",
                        request=f"Token found in {source}",
                        reproduction_steps="Check the 'exp' claim against the current time.",
                        impact="Expired tokens should not be valid; if they are, session management is broken.",
                        recommendation="Enforce token expiration server-side.",
                        module=self.name,
                    ))
            except (ValueError, TypeError):
                pass
        else:
            findings.append(Finding(
                title="JWT without expiration claim",
                severity=Severity.LOW,
                confidence=70,
                target=self.target,
                endpoint=self.target,
                parameter=source,
                description="The JWT has no 'exp' claim, meaning it may never expire.",
                evidence=f"Payload: {json.dumps(payload)[:300]}",
                request=f"Token found in {source}",
                reproduction_steps="Decode the payload and check for 'exp'.",
                impact="Long-lived tokens increase the window of compromise if stolen.",
                recommendation="Always set a short 'exp' claim.",
                module=self.name,
                potential=True,
            ))

        # Check for weak algorithm
        if algo == "HS256":
            findings.append(Finding(
                title="JWT uses HS256 (potential weak key / algorithm confusion)",
                severity=Severity.INFO,
                confidence=50,
                target=self.target,
                endpoint=self.target,
                parameter=source,
                description="JWT uses HS256; if the secret is weak, the token can be forged.",
                evidence=f"Algorithm: {algo}",
                request=f"Token found in {source}",
                reproduction_steps="Attempt to crack the HS256 secret offline.",
                impact="If the secret is weak, tokens can be forged.",
                recommendation="Use a strong random secret (>= 256 bits) or switch to RS256.",
                module=self.name,
                potential=True,
            ))

        return findings
