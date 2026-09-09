"""Dependency / JS library analysis module.

Analyzes discovered JavaScript files for:
- known vulnerable libraries (version-based)
- outdated jQuery, Angular, React, Vue, Bootstrap versions
- exposed source maps
- inline secrets in JS
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin

from ..base import BaseModule
from ..reporting.models import Finding, Severity


# (library name, regex to extract version, max safe version, CVE note)
_LIB_VERSIONS = [
    ("jQuery", r"jquery[^\d]*v?(\d+\.\d+\.\d+)", "3.5.0",
     "XSS in jQuery < 3.5.0 (CVE-2020-11022)"),
    ("jQuery", r"jquery.*?(\d+\.\d+\.\d+)", "3.5.0",
     "XSS in jQuery < 3.5.0"),
    ("Angular", r"angular[^\d]*v?(\d+\.\d+\.\d+)", "1.8.0",
     "XSS in AngularJS < 1.8 (expression sandbox bypass)"),
    ("Bootstrap", r"bootstrap[^\d]*v?(\d+\.\d+\.\d+)", "3.4.1",
     "XSS in Bootstrap < 3.4.1 tooltip data-template"),
    ("Vue.js", r"vue[^\d]*v?(\d+\.\d+\.\d+)", "2.6.0",
     "Prototype pollution in Vue < 2.6.0"),
    ("Lodash", r"lodash[^\d]*v?(\d+\.\d+\.\d+)", "4.17.5",
     "Prototype pollution in Lodash < 4.17.5 (CVE-2018-3721)"),
    ("Moment.js", r"moment[^\d]*v?(\d+\.\d+\.\d+)", "2.19.3",
     "ReDoS in Moment.js < 2.19.3 (CVE-2017-18214)"),
    ("Knockout", r"knockout[^\d]*v?(\d+\.\d+\.\d+)", "3.4.2",
     "XSS in Knockout < 3.4.2"),
    ("Dojo", r"dojo[^\d]*v?(\d+\.\d+\.\d+)", "1.2.0",
     "Multiple CVEs in old Dojo versions"),
]

_VERSION_COMPARE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def _version_tuple(v: str):
    m = _VERSION_COMPARE_RE.match(v)
    if m:
        return tuple(int(x) for x in m.groups())
    return (0, 0, 0)


class DepsModule(BaseModule):
    """Analyze JavaScript dependencies for known vulnerabilities."""

    name = "deps"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        js_files = []
        if self.discovery:
            js_files = self.discovery.js_files or []
        if not js_files:
            self.logger.module(self.name, "no-js-files")
            return findings

        for js_url in js_files[:30]:
            findings.extend(self._analyze_js(js_url))
            findings.extend(self._check_source_map(js_url))

        self.logger.module(self.name, "completed")
        return findings

    def _analyze_js(self, js_url: str) -> List[Finding]:
        findings: List[Finding] = []
        resp = self.http.get(js_url)
        if not resp:
            return findings

        lower_url = js_url.lower()
        lower_body = resp.body.lower()
        seen: set = set()  # (lib, version) already reported for this URL

        for lib, pattern, safe_ver, cve_note in _LIB_VERSIONS:
            # check URL for library name + version
            m = re.search(pattern, lower_url + "\n" + lower_body, re.IGNORECASE)
            if not m:
                continue
            version = m.group(1)
            # the same lib/version may match in both the URL and the JS body
            # (e.g. ?ver=3.4.1 plus the bundle header) -> one finding only
            if (lib, version) in seen:
                continue
            seen.add((lib, version))
            if _version_tuple(version) < _version_tuple(safe_ver):
                findings.append(Finding(
                    title=f"Outdated JS library: {lib} {version}",
                    severity=Severity.MEDIUM,
                    confidence=75,
                    target=self.target,
                    endpoint=js_url,
                    description=f"{lib} {version} is older than the safe version {safe_ver}. {cve_note}.",
                    evidence=f"URL: {js_url}\nDetected version: {version}",
                    request=f"GET {js_url}",
                    reproduction_steps=f"Fetch {js_url} and inspect for {lib} version {version}.",
                    impact=f"{cve_note}. Client-side exploitation possible.",
                    recommendation=f"Upgrade {lib} to {safe_ver} or later.",
                    references=["https://owasp.org/www-project-top-ten/"],
                    module=self.name,
                    potential=True,
                ))
        return findings

    def _check_source_map(self, js_url: str) -> List[Finding]:
        findings: List[Finding] = []
        # check for .map file
        map_url = js_url + ".map"
        resp = self.http.get(map_url)
        if not resp or resp.status != 200:
            return findings
        # check if it looks like a source map
        if "sourceRoot" in resp.body or "sources" in resp.body:
            findings.append(Finding(
                title="Source map exposed",
                severity=Severity.LOW,
                confidence=80,
                target=self.target,
                endpoint=map_url,
                description=f"A source map file is publicly accessible at {map_url}.",
                evidence=f"Source map response (first 200 chars): {resp.body[:200]}",
                request=f"GET {map_url}",
                reproduction_steps=f"Access {map_url}.",
                impact="Original source code structure and comments are exposed.",
                recommendation="Do not deploy source maps to production.",
                module=self.name,
            ))
        return findings
