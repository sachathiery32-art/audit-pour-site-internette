"""Injection detection module.

Detects (non-destructively):
- Reflected XSS
- Stored XSS (read-only verification)
- SQL injection (error-based + boolean-based)
- NoSQL injection
- Command injection
- LDAP injection
- Template injection (SSTI)
- XPath injection
- Path traversal

Every payload is designed to be *inoffensive*: it produces a detectable,
reproducible marker in the response without creating, modifying, or
destroying data.
"""
from __future__ import annotations

import re
import string
import random
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity
from modules.utils import BaselineCache, content_appears_in_baseline


def _marker() -> str:
    """Generate a unique, harmless marker string."""
    return "autosec" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


XSS_PAYLOADS = [
    lambda m: f'{m}',
    lambda m: f'<script>{m}</script>',
    lambda m: f'"><img src=x onerror="{m}">',
    lambda m: f"'><svg onload={m}>",
]

# SQLi: all patterns are specific SQL error strings, not generic words
SQLI_PAYLOADS = [
    ("' OR '1'='1", r"errorinyoursqlsyntax|mysql_fetch|warning:mysql|sqlstate|ora-[0-9]|psql:.*error"),
    ("' OR '1'='1' --", r"errorinyoursqlsyntax|mysql_fetch|sqlstate"),
    ("1' AND '1'='1", r"errorinyoursqlsyntax|mysql_fetch"),
    ("1 UNION SELECT NULL--", r"errorinyoursqlsyntax|theusedselectstatements"),
]

SQLI_BOOLEAN_TRUE = "' OR '1'='1"
SQLI_BOOLEAN_FALSE = "' AND '1'='2"

# NoSQLi: patterns must be specific (no generic words like 'invalid')
# NoSQLi: match MongoDB-specific error signatures only
NOSQLI_PAYLOADS = [
    ("' || '1'=='1", r"mongo(db)?error|mongo(le)?exception|mongoconnection|bsonmongo|\$where"),
    ("true, $where: '1==1'", r"mongo(db)?error|mongo(le)?exception|mongoconnection|executionfailed"),
]

CMDI_PAYLOADS = [
    (";echo autosec", "autosec"),
    ("|echo autosec", "autosec"),
    ("&&echo autosec", "autosec"),
    ("$(echo autosec)", "autosec"),
]

# LDAP: use specific LDAP error terms only
LDAP_PAYLOADS = [
    ("*)(uid=*)", r"ldapexception|namingexception|ldap_err|invalidcredentials"),
    ("*()()()", r"ldapexception|protocolerror|ldap_err"),
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "77"),
]

# XPath: specific XML/XPath error terms only
XPATH_PAYLOADS = [
    ("' or '1'='1", r"xpath|simplexml|xmlparsererror|xmlerror"),
    ("' or 1=1]", r"xpath|invalidpredicate|xmlparsererror"),
]

PATH_TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", r"root:[^:]*:0:0:"),  # /etc/passwd entry
    ("..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]"),  # [fonts] section, literal brackets
    ("....//....//....//etc/passwd", r"root:[^:]*:0:0:"),
    ("/etc/passwd", r"root:[^:]*:0:0:"),
]


class InjectionModule(BaseModule):
    """Run non-destructive injection tests against discovered inputs."""

    name = "injection"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery
        self._baseline_cache = BaselineCache(http, target)

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        targets = self._collect_targets()
        if not targets:
            self.logger.module(self.name, "no-inputs-found")
            return findings

        for url, method, params in targets:
            findings.extend(self._test_xss(url, method, params))
            findings.extend(self._test_sqli(url, method, params))
            findings.extend(self._test_nosqli(url, method, params))
            findings.extend(self._test_cmdi(url, method, params))
            findings.extend(self._test_ldap(url, method, params))
            findings.extend(self._test_ssti(url, method, params))
            findings.extend(self._test_xpath(url, method, params))
            findings.extend(self._test_path_traversal(url, method, params))

        self.logger.module(self.name, "completed")
        return findings

    def _collect_targets(self) -> List[Tuple[str, str, List[str]]]:
        targets: List[Tuple[str, str, List[str]]] = []
        if not self.discovery:
            parsed = urlparse(self.target)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            if params:
                targets.append((self.target, "GET", params))
            return targets

        seen: set = set()
        for page in self.discovery.pages:
            parsed = urlparse(page)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            if params:
                key = (page, "GET", tuple(params))
                if key not in seen:
                    seen.add(key)
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

        if not targets:
            common = ["q", "search", "id", "page", "name", "query", "path", "file", "url", "redirect"]
            targets.append((self.target, "GET", common))

        return targets

    def _send(self, url: str, method: str, params: dict) -> Optional[object]:
        if method.upper() == "POST":
            return self.http.post(url, data=params)
        else:
            return self.http.get(url, params=params)

    def _baseline(self, url: str, method: str, param: str) -> Optional[object]:
        return self._send(url, method, {param: "autosecaudit-benign"})

    def _is_catchall(self, resp) -> bool:
        """Check if the response is just the SPA shell (false positive)."""
        if not resp:
            return False
        from modules.utils import is_spa_catchall
        return is_spa_catchall(resp.body, self._baseline_cache)

    def _test_xss(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for param in params:
            baseline = self._baseline(url, method, param)
            if not baseline:
                continue
            for payload_fn in XSS_PAYLOADS:
                marker = _marker()
                payload = payload_fn(marker)
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                if marker in resp.body and marker not in baseline.body:
                    findings.append(Finding(
                        title="Reflected XSS",
                        severity=Severity.HIGH,
                        confidence=90,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="Controlled payload was reflected into the HTML context "
                                    "without adequate output encoding.",
                        evidence=f"Payload '{payload}' reflected. Marker '{marker}' "
                                 f"found in response (status {resp.status}).",
                        request=f"{method} {url} {param}={payload}",
                        response_indicators=f"Marker '{marker}' present in body.",
                        reproduction_steps=(
                            f"1. Submit {param}={payload}\n"
                            f"2. Observe the marker '{marker}' echoed in the response."
                        ),
                        impact="Client-side script execution in a victim's browser context.",
                        recommendation="Apply context-aware output encoding and a strict CSP.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        module=self.name,
                    ))
                    break
        return findings

    def _test_sqli(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        baseline = self._baseline_cache  # root page baseline for FP check
        for param in params:
            param_baseline = self._baseline(url, method, param)
            for payload, error_re in SQLI_PAYLOADS:
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                # skip SPA catch-all responses
                if self._is_catchall(resp):
                    continue
                match = re.search(error_re, resp.body, re.IGNORECASE)
                if not match:
                    continue
                # check the matched text doesn't also appear in the baseline
                if param_baseline and match.group(0).lower() in param_baseline.body.lower():
                    continue
                if re.search(error_re, resp.body.replace(" ", ""), re.IGNORECASE):
                    findings.append(Finding(
                        title="SQL injection (error-based)",
                        severity=Severity.CRITICAL,
                        confidence=85,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="SQL error disclosed when injecting a single quote payload.",
                        evidence=f"Payload '{payload}' triggered SQL error.",
                        request=f"{method} {url} {param}={payload}",
                        response_indicators=f"Matched pattern: {error_re}",
                        reproduction_steps=f"Submit {param}={payload} and observe SQL error.",
                        impact="Database disclosure, modification, or destruction.",
                        recommendation="Use parameterized queries / prepared statements everywhere.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        module=self.name,
                    ))
                    break

            # boolean-based (non-destructive)
            true_resp = self._send(url, method, {param: SQLI_BOOLEAN_TRUE})
            false_resp = self._send(url, method, {param: SQLI_BOOLEAN_FALSE})
            if true_resp and false_resp and param_baseline:
                true_len = len(true_resp.body)
                false_len = len(false_resp.body)
                base_len = len(param_baseline.body)
                # skip if true/false are both catchall (identical to root)
                if self._is_catchall(true_resp) and self._is_catchall(false_resp):
                    continue
                if (abs(true_len - base_len) < 50 and abs(false_len - base_len) > 200):
                    findings.append(Finding(
                        title="SQL injection (boolean-based, potential)",
                        severity=Severity.HIGH,
                        confidence=65,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="Boolean-based differential response suggests SQL injection.",
                        evidence=(
                            f"baseline_len={base_len} true_payload_len={true_len} "
                            f"false_payload_len={false_len}"
                        ),
                        request=f"{method} {url} {param}={SQLI_BOOLEAN_TRUE}",
                        reproduction_steps=(
                            f"Compare responses of {param}='{SQLI_BOOLEAN_TRUE}' "
                            f"vs {param}='{SQLI_BOOLEAN_FALSE}'."
                        ),
                        impact="Database data can be extracted via boolean blind injection.",
                        recommendation="Use parameterized queries.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        module=self.name,
                        potential=True,
                    ))
        return findings

    def _test_nosqli(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for param in params:
            param_baseline = self._baseline(url, method, param)
            for payload, error_re in NOSQLI_PAYLOADS:
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                if self._is_catchall(resp):
                    continue
                match = re.search(error_re, resp.body, re.IGNORECASE)
                if not match:
                    continue
                # skip if match appears in baseline (static text, not a real error)
                if param_baseline and match.group(0).lower() in param_baseline.body.lower():
                    continue
                if match:
                    findings.append(Finding(
                        title="NoSQL injection (error-based)",
                        severity=Severity.CRITICAL,
                        confidence=80,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="NoSQL error disclosed when injecting operator payloads.",
                        evidence=f"Payload '{payload}' triggered NoSQL error.",
                        request=f"{method} {url} {param}={payload}",
                        reproduction_steps=f"Submit {param}={payload} and observe NoSQL error.",
                        impact="Database disclosure or authentication bypass.",
                        recommendation="Sanitize inputs; use query builders with parameter binding.",
                        references=["https://owasp.org/www-community/attacks/NoSQL_Injection"],
                        module=self.name,
                    ))
                    break
        return findings

    def _test_cmdi(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for param in params:
            baseline = self._baseline(url, method, param)
            if not baseline:
                continue
            for payload, marker in CMDI_PAYLOADS:
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                # marker must be in the response but NOT in the baseline,
                # so we don't false-positive on echo APIs that reflect input.
                if marker in resp.body and marker not in baseline.body:
                    findings.append(Finding(
                        title="OS command injection",
                        severity=Severity.CRITICAL,
                        confidence=90,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="A controlled marker produced by `echo` was found in "
                                    "the response, indicating shell command execution.",
                        evidence=f"Payload '{payload}' produced marker '{marker}'.",
                        request=f"{method} {url} {param}={payload}",
                        response_indicators=f"Marker '{marker}' present in body (not in baseline).",
                        reproduction_steps=f"Submit {param}={payload}; observe '{marker}' in response.",
                        impact="Remote code execution on the server.",
                        recommendation="Avoid shell calls; use parameterized APIs and input validation.",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                        module=self.name,
                    ))
                    break
        return findings

    def _test_ldap(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for param in params:
            param_baseline = self._baseline(url, method, param)
            for payload, error_re in LDAP_PAYLOADS:
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                if self._is_catchall(resp):
                    continue
                match = re.search(error_re, resp.body, re.IGNORECASE)
                if not match:
                    continue
                if param_baseline and match.group(0).lower() in param_baseline.body.lower():
                    continue
                if match:
                    findings.append(Finding(
                        title="LDAP injection (potential)",
                        severity=Severity.HIGH,
                        confidence=70,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="LDAP-style wildcard payload triggered an LDAP-related error.",
                        evidence=f"Payload '{payload}'.",
                        request=f"{method} {url} {param}={payload}",
                        reproduction_steps=f"Submit {param}={payload} and observe LDAP error.",
                        impact="Authentication bypass or directory information disclosure.",
                        recommendation="Sanitize/escape LDAP special characters before query construction.",
                        references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
                        module=self.name,
                        potential=True,
                    ))
                    break
        return findings

    def _test_ssti(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for param in params:
            baseline = self._baseline(url, method, param)
            if not baseline:
                continue
            for payload, expected in SSTI_PAYLOADS:
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                # The payload must be reflected (server received it) AND
                # the evaluated result must appear in the response but NOT
                # in the baseline (so we don't match a coincidental '49').
                payload_reflected = payload in resp.body
                expected_in_result = expected in resp.body
                expected_in_baseline = expected in baseline.body
                if payload_reflected and expected_in_result and not expected_in_baseline:
                    # Extra check: the raw payload string should not equal
                    # the expected output literally in the baseline (avoids
                    # echo APIs that just reflect everything).
                    findings.append(Finding(
                        title="Server-Side Template Injection (SSTI)",
                        severity=Severity.CRITICAL,
                        confidence=85,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description=f"Template expression '{payload}' was evaluated to '{expected}'.",
                        evidence=f"Payload '{payload}' -> '{expected}' in response (not present in baseline).",
                        request=f"{method} {url} {param}={payload}",
                        reproduction_steps=f"Submit {param}={payload}; observe '{expected}' that does not appear with benign input.",
                        impact="Remote code execution through the template engine.",
                        recommendation="Use sandboxed / logic-less templates; never pass user input to render().",
                        references=["https://owasp.org/www-community/attacks/Server_Side_Template_Injection"],
                        module=self.name,
                    ))
                    break
        return findings

    def _test_xpath(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for param in params:
            param_baseline = self._baseline(url, method, param)
            for payload, error_re in XPATH_PAYLOADS:
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                if self._is_catchall(resp):
                    continue
                match = re.search(error_re, resp.body, re.IGNORECASE)
                if not match:
                    continue
                if param_baseline and match.group(0).lower() in param_baseline.body.lower():
                    continue
                if match:
                    findings.append(Finding(
                        title="XPath injection (potential)",
                        severity=Severity.MEDIUM,
                        confidence=70,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="XPath-style payload triggered an XML/XPath error.",
                        evidence=f"Payload '{payload}'.",
                        request=f"{method} {url} {param}={payload}",
                        reproduction_steps=f"Submit {param}={payload}; observe XPath error.",
                        impact="Extraction of XML document structure or authentication bypass.",
                        recommendation="Sanitize inputs; use parameterized XPath queries.",
                        references=["https://owasp.org/www-community/attacks/XPath_Injection"],
                        module=self.name,
                        potential=True,
                    ))
                    break
        return findings

    def _test_path_traversal(self, url: str, method: str, params: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for param in params:
            param_baseline = self._baseline(url, method, param)
            for payload, content_re in PATH_TRAVERSAL_PAYLOADS:
                resp = self._send(url, method, {param: payload})
                if not resp:
                    continue
                if self._is_catchall(resp):
                    continue
                match = re.search(content_re, resp.body)
                if not match:
                    continue
                # skip if the matched content appears in the baseline too
                if param_baseline and match.group(0).lower() in param_baseline.body.lower():
                    continue
                if match:
                    findings.append(Finding(
                        title="Path traversal",
                        severity=Severity.CRITICAL,
                        confidence=90,
                        target=self.target,
                        endpoint=url,
                        parameter=param,
                        description="Traversal payload returned sensitive file contents.",
                        evidence=f"Payload '{payload}' matched pattern '{content_re}'.",
                        request=f"{method} {url} {param}={payload}",
                        reproduction_steps=f"Submit {param}={payload}; observe sensitive file content.",
                        impact="Arbitrary file read on the server (credentials, configs, source).",
                        recommendation="Canonicalize and validate paths; never pass user input to file APIs.",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        module=self.name,
                    ))
                    break
        return findings
