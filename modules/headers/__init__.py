"""Security headers and TLS inspection module.

Checks:
- absence of HTTPS / TLS misconfiguration
- expired or mismatched certificates
- missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- cookie flags (Secure, HttpOnly, SameSite)
- exposed server info / banners
- dangerous HTTP methods
- overly detailed error responses
"""
from __future__ import annotations

import ssl
import socket
import re
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity

_SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "max-age=63072000; includeSubDomains; preload"),
    "content-security-policy": ("CSP", "default-src 'self'"),
    "x-frame-options": ("X-Frame-Options", "DENY or SAMEORIGIN"),
    "x-content-type-options": ("X-Content-Type-Options", "nosniff"),
    "referrer-policy": ("Referrer-Policy", "no-referrer or strict-origin-when-cross-origin"),
    "permissions-policy": ("Permissions-Policy", "restrict sensitive features"),
}

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


class HeadersTlsModule(BaseModule):
    """Inspect HTTP security headers, cookies, methods, and TLS config."""

    name = "headers_tls"

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        resp = self.http.get(self.target)
        if not resp:
            self.logger.error(f"Cannot reach target {self.target}")
            return findings

        findings.extend(self._check_https())
        findings.extend(self._check_tls_cert())
        findings.extend(self._check_security_headers(resp))
        findings.extend(self._check_cookies(resp))
        findings.extend(self._check_server_info(resp))
        findings.extend(self._check_dangerous_methods())
        findings.extend(self._check_error_disclosure(resp))

        self.logger.module(self.name, "completed")
        return findings

    def _check_https(self) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            findings.append(Finding(
                title="Traffic not over HTTPS",
                severity=Severity.HIGH,
                confidence=95,
                target=self.target,
                endpoint=self.target,
                description="The target is served over plain HTTP. "
                            "Traffic is unencrypted and susceptible to interception.",
                evidence=f"Scheme: {parsed.scheme}",
                impact="Credentials, session tokens, and personal data can be intercepted.",
                recommendation="Enforce HTTPS with automatic redirects and HSTS.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                module=self.name,
            ))
        return findings

    def _check_tls_cert(self) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            return findings
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.http.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            if cert:
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (expiry - now).days
                        if days_left < 0:
                            findings.append(Finding(
                                title="Expired TLS certificate",
                                severity=Severity.HIGH,
                                confidence=100,
                                target=self.target,
                                description=f"Certificate expired on {not_after}.",
                                impact="Users see browser warnings; MITM risk.",
                                recommendation="Renew the TLS certificate immediately.",
                                module=self.name,
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                title="TLS certificate expiring soon",
                                severity=Severity.LOW,
                                confidence=100,
                                target=self.target,
                                description=f"Certificate expires in {days_left} days ({not_after}).",
                                impact="Imminent expiry will cause trust failures.",
                                recommendation="Renew before expiry.",
                                module=self.name,
                            ))
                    except ValueError:
                        pass

                san = cert.get("subjectAltName", [])
                names = [v for _, v in san] if san else []
                subject = dict(x[0] for x in cert.get("subject", ()))
                cn = subject.get("commonName", "")
                if cn and cn not in names:
                    names.append(cn)
                match = any(hostname == n or (n.startswith("*.") and hostname.endswith(n[1:]))
                            for n in names)
                if not match and names:
                    findings.append(Finding(
                        title="TLS certificate hostname mismatch",
                        severity=Severity.MEDIUM,
                        confidence=90,
                        target=self.target,
                        description=f"Certificate names {names} do not match {hostname}.",
                        impact="Browser trust warnings; possible MITM.",
                        recommendation="Issue a certificate valid for this hostname.",
                        module=self.name,
                    ))
        except ssl.SSLError as exc:
            findings.append(Finding(
                title="TLS handshake error",
                severity=Severity.MEDIUM,
                confidence=80,
                target=self.target,
                description=f"TLS handshake failed: {exc}",
                impact="Weak or misconfigured TLS configuration.",
                recommendation="Review TLS configuration and supported protocols.",
                module=self.name,
                potential=True,
            ))
        except Exception:
            pass
        return findings

    def _check_security_headers(self, resp) -> List[Finding]:
        findings: List[Finding] = []
        for header, (label, recommendation_text) in _SECURITY_HEADERS.items():
            value = resp.header(header)
            if not value:
                findings.append(Finding(
                    title=f"Missing security header: {label}",
                    severity=Severity.MEDIUM if label in ("HSTS", "CSP") else Severity.LOW,
                    confidence=100,
                    target=self.target,
                    endpoint=resp.url,
                    description=f"The {header} header is not set.",
                    impact=self._header_impact(label),
                    recommendation=f"Set {header}: {recommendation_text}",
                    references=["https://owasp.org/www-project-secure-headers/"],
                    module=self.name,
                ))
            elif label == "CSP" and ("unsafe-inline" in value or "unsafe-eval" in value):
                findings.append(Finding(
                    title="Weak Content-Security-Policy",
                    severity=Severity.MEDIUM,
                    confidence=85,
                    target=self.target,
                    endpoint=resp.url,
                    description=f"CSP allows unsafe directives: {value}",
                    impact="XSS protections weakened by 'unsafe-inline' or 'unsafe-eval'.",
                    recommendation="Remove unsafe directives; use nonces or hashes.",
                    module=self.name,
                ))
            elif label == "HSTS":
                m = re.search(r"max-age=(\d+)", value)
                if m:
                    max_age = int(m.group(1))
                    if max_age < 31536000:
                        findings.append(Finding(
                            title="Short HSTS max-age",
                            severity=Severity.LOW,
                            confidence=90,
                            target=self.target,
                            endpoint=resp.url,
                            description=f"HSTS max-age={max_age} is below recommended 1 year.",
                            impact="Shorter protection window against protocol downgrade.",
                            recommendation="Set max-age=63072000 (2 years) or higher.",
                            module=self.name,
                        ))
        return findings

    @staticmethod
    def _header_impact(label: str) -> str:
        impacts = {
            "HSTS": "No protection against protocol downgrade and cookie hijacking.",
            "CSP": "No defense-in-depth against XSS and data injection.",
            "X-Frame-Options": "Site is vulnerable to clickjacking.",
            "X-Content-Type-Options": "Browser may MIME-sniff, enabling type confusion attacks.",
            "Referrer-Policy": "Referer may leak sensitive path data to third parties.",
            "Permissions-Policy": "Browser features (camera, geolocation) may be abused by XSS.",
        }
        return impacts.get(label, "Missing header weakens security posture.")

    def _check_cookies(self, resp) -> List[Finding]:
        findings: List[Finding] = []
        raw_cookies = resp.headers.get("set-cookie", "")
        if not raw_cookies:
            return findings
        for cookie_part in re.split(r',\s*(?=[A-Za-z0-9_-]+=)', raw_cookies):
            name_match = re.match(r'([A-Za-z0-9_-]+)=', cookie_part)
            if not name_match:
                continue
            name = name_match.group(1)
            lower = cookie_part.lower()
            flags = {
                "Secure": "secure" in lower,
                "HttpOnly": "httponly" in lower,
                "SameSite": "samesite" in lower,
            }
            for flag, present in flags.items():
                if not present:
                    sev = Severity.HIGH if flag == "Secure" else Severity.MEDIUM if flag == "HttpOnly" else Severity.LOW
                    findings.append(Finding(
                        title=f"Cookie '{name}' missing {flag} flag",
                        severity=sev,
                        confidence=95,
                        target=self.target,
                        endpoint=resp.url,
                        parameter=name,
                        description=f"The cookie '{name}' does not set the {flag} flag.",
                        evidence=cookie_part[:200],
                        impact=self._cookie_impact(flag),
                        recommendation=f"Set {flag} on cookie '{name}'.",
                        module=self.name,
                    ))
        return findings

    @staticmethod
    def _cookie_impact(flag: str) -> str:
        return {
            "Secure": "Cookie can be transmitted over unencrypted HTTP.",
            "HttpOnly": "JavaScript can read the cookie, enabling theft via XSS.",
            "SameSite": "Cookie may be sent in cross-site requests, enabling CSRF.",
        }.get(flag, "Misconfigured cookie flag.")

    def _check_server_info(self, resp) -> List[Finding]:
        findings: List[Finding] = []
        server = resp.header("Server")
        powered = resp.header("X-Powered-By")
        if server and len(server) > 0:
            findings.append(Finding(
                title="Server banner discloses technology",
                severity=Severity.INFO,
                confidence=100,
                target=self.target,
                endpoint=resp.url,
                description=f"Server header reveals: {server}",
                impact="Version disclosure aids targeted exploitation.",
                recommendation="Suppress or obfuscate the Server header.",
                module=self.name,
            ))
        if powered:
            findings.append(Finding(
                title="X-Powered-By discloses technology",
                severity=Severity.LOW,
                confidence=100,
                target=self.target,
                endpoint=resp.url,
                description=f"X-Powered-By: {powered}",
                impact="Technology and version disclosure aids attackers.",
                recommendation="Remove the X-Powered-By header.",
                module=self.name,
            ))
        return findings

    def _check_dangerous_methods(self) -> List[Finding]:
        findings: List[Finding] = []
        resp = self.http.options(self.target)
        if not resp:
            return findings
        allow = resp.header("Allow")
        if not allow:
            return findings
        enabled = {m.strip().upper() for m in allow.split(",") if m.strip()}
        dangerous = enabled & _DANGEROUS_METHODS
        if dangerous:
            findings.append(Finding(
                title="Dangerous HTTP methods enabled",
                severity=Severity.MEDIUM,
                confidence=85,
                target=self.target,
                endpoint=resp.url,
                description=f"Methods enabled: {', '.join(sorted(dangerous))}",
                evidence=f"Allow: {allow}",
                impact="PUT/DELETE/TRACE can modify data or leak internal info.",
                recommendation="Disable unnecessary HTTP methods.",
                module=self.name,
            ))
        return findings

    def _check_error_disclosure(self, resp) -> List[Finding]:
        findings: List[Finding] = []
        error_url = self.target.rstrip("/") + "/autosecaudit_nonexistent_" + "x" * 8
        err_resp = self.http.get(error_url)
        if not err_resp:
            return findings
        body = err_resp.body.lower()
        indicators = ["stack trace", "traceback", "exception in", "/usr/lib/python",
                      "php warning", "mysql_fetch", "ora-", "syntax error"]
        for ind in indicators:
            if ind in body:
                findings.append(Finding(
                    title="Verbose error messages disclose internals",
                    severity=Severity.LOW,
                    confidence=75,
                    target=self.target,
                    endpoint=error_url,
                    description=f"Error response contains '{ind}'.",
                    impact="Internal paths, libraries, and versions leak to attackers.",
                    recommendation="Return generic error pages in production.",
                    references=["https://owasp.org/www-community/Improper_Error_Handling"],
                    module=self.name,
                ))
                break
        return findings
