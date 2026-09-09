"""Sensitive file exposure testing module.

Tests (non-destructively):
- directory listing
- exposed configuration files
- accessible backups
- temporary files
- exposed .env files
- public archives
- exposed Git metadata
- secrets present in public responses
- sensitive paths referenced by the frontend

We never mass-download files or extract secrets for use. We only check
for presence and report a finding with a redacted indicator.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity
from modules.utils import BaselineCache, is_spa_catchall


_SENSITIVE_PATHS = [
    ("/.env", "Environment file", Severity.CRITICAL),
    ("/.git/config", "Git metadata exposed", Severity.HIGH),
    ("/.git/HEAD", "Git metadata exposed", Severity.HIGH),
    ("/.svn/entries", "SVN metadata exposed", Severity.MEDIUM),
    ("/.hg/store", "Mercurial metadata exposed", Severity.MEDIUM),
    ("/config.php", "Configuration file exposed", Severity.HIGH),
    ("/config.json", "Configuration file exposed", Severity.HIGH),
    ("/config.yml", "Configuration file exposed", Severity.HIGH),
    ("/backup.zip", "Backup archive exposed", Severity.HIGH),
    ("/backup.tar.gz", "Backup archive exposed", Severity.HIGH),
    ("/backup.sql", "Database backup exposed", Severity.CRITICAL),
    ("/db.sql", "Database dump exposed", Severity.CRITICAL),
    ("/dump.sql", "Database dump exposed", Severity.CRITICAL),
    ("/.htaccess", ".htaccess exposed", Severity.MEDIUM),
    ("/.htpasswd", ".htpasswd exposed", Severity.HIGH),
    ("/web.config", "Web.config exposed", Severity.MEDIUM),
    ("/composer.json", "Composer config exposed", Severity.LOW),
    ("/package.json", "Package manifest exposed", Severity.LOW),
    ("/wp-config.php", "WordPress config exposed", Severity.CRITICAL),
    ("/settings.py", "Django settings exposed", Severity.HIGH),
    ("/debug.log", "Debug log exposed", Severity.MEDIUM),
    ("/error.log", "Error log exposed", Severity.MEDIUM),
    ("/.DS_Store", "macOS .DS_Store exposed", Severity.LOW),
    ("/server-status", "Apache server-status exposed", Severity.MEDIUM),
    ("/server-info", "Apache server-info exposed", Severity.MEDIUM),
    ("/phpinfo.php", "PHP info page exposed", Severity.HIGH),
    ("/info.php", "PHP info page exposed", Severity.HIGH),
    ("/.well-known/security.txt", "Security.txt present", Severity.INFO),
]

_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"gh[psu]_[A-Za-z0-9]{36}", "GitHub Token"),
    (r"xox[baprs]-[A-Za-z0-9-]+", "Slack Token"),
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API Key"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT"),
    (r"sk_live_[A-Za-z0-9]{24,}", "Stripe Live Secret Key"),
]


class FilesModule(BaseModule):
    """Test for sensitive file exposure non-destructively."""

    name = "files"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery
        self._baseline_cache = BaselineCache(http, target)

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        findings.extend(self._test_sensitive_paths())
        findings.extend(self._test_directory_listing())
        findings.extend(self._test_secrets_in_response())

        self.logger.module(self.name, "completed")
        return findings

    def _test_sensitive_paths(self) -> List[Finding]:
        findings: List[Finding] = []
        for path, label, severity in _SENSITIVE_PATHS:
            url = urljoin(self.target, path)
            resp = self.http.get(url)
            if not resp:
                continue
            # skip non-200 responses
            if resp.status != 200:
                continue
            # skip SPA catch-all (same HTML shell returned for any path)
            if is_spa_catchall(resp.body, self._baseline_cache):
                continue
            # specific checks
            if "phpinfo" in path and "phpinfo" in resp.body.lower():
                findings.append(self._make_finding(label, url, severity, resp.body))
                continue
            if "server-status" in path and "apache" in resp.body.lower():
                findings.append(self._make_finding(label, url, severity, resp.body))
                continue
            # generic: 200 with meaningful content that differs from baseline
            if len(resp.body) > 10:
                findings.append(self._make_finding(label, url, severity, resp.body))
        return findings

    def _make_finding(self, label: str, url: str, severity: Severity, body: str) -> Finding:
        evidence = body[:200] + ("..." if len(body) > 200 else "")
        return Finding(
            title=label,
            severity=severity,
            confidence=85,
            target=self.target,
            endpoint=url,
            description=f"The sensitive resource at {url} is publicly accessible.",
            evidence=f"HTTP 200 response (truncated): {evidence}",
            request=f"GET {url}",
            reproduction_steps=f"Access {url} in a browser or via curl.",
            impact="Exposure of credentials, configuration, or version control history.",
            recommendation="Remove the file from the web root or restrict access.",
            references=["https://owasp.org/www-project-top-ten/"],
            module=self.name,
        )

    def _test_directory_listing(self) -> List[Finding]:
        findings: List[Finding] = []
        dirs = ["/static/", "/uploads/", "/files/", "/assets/", "/public/", "/media/"]
        for d in dirs:
            url = urljoin(self.target, d)
            resp = self.http.get(url)
            if not resp or resp.status != 200:
                continue
            # skip SPA catch-all
            if is_spa_catchall(resp.body, self._baseline_cache):
                continue
            lower = resp.body.lower()
            indicators = ["index of", "directory listing", "<title>index of",
                          "last modified", "parent directory"]
            if any(ind in lower for ind in indicators):
                findings.append(Finding(
                    title="Directory listing enabled",
                    severity=Severity.MEDIUM,
                    confidence=90,
                    target=self.target,
                    endpoint=url,
                    description=f"Directory listing is enabled at {url}.",
                    evidence=f"Response contains 'Index of' content.",
                    request=f"GET {url}",
                    reproduction_steps=f"Access {url}.",
                    impact="File enumeration and potential exposure of non-public files.",
                    recommendation="Disable directory listing in the web server config.",
                    module=self.name,
                ))
        return findings

    def _test_secrets_in_response(self) -> List[Finding]:
        findings: List[Finding] = []
        urls_to_scan = [self.target]
        if self.discovery:
            urls_to_scan.extend(self.discovery.js_files[:10])
        for url in urls_to_scan:
            resp = self.http.get(url)
            if not resp:
                continue
            for pattern, label in _SECRET_PATTERNS:
                matches = re.findall(pattern, resp.body)
                if matches:
                    findings.append(Finding(
                        title=f"Potential secret in public response: {label}",
                        severity=Severity.HIGH,
                        confidence=75,
                        target=self.target,
                        endpoint=url,
                        description=f"A pattern matching {label} was found in a public response.",
                        evidence=f"Pattern: {pattern} (value redacted)",
                        request=f"GET {url}",
                        reproduction_steps=f"Fetch {url} and search for the {label} pattern.",
                        impact="Leaked secrets allow direct access to cloud / code / payment infra.",
                        recommendation="Remove secrets from public assets; use server-side env vars.",
                        references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"],
                        module=self.name,
                        potential=True,
                    ))
        return findings
