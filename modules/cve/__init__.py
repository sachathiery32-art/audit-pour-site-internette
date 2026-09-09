"""CVE detection / correlation engine.

Correlates detected technologies and versions against a small built-in
CVE database. We never assert a version is vulnerable without a
confidence value; findings are always marked as potential when version
data is inferred from banners rather than confirmed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity, severity_from_cvss


@dataclass
class CveEntry:
    """A single CVE entry in the local knowledge base."""
    cve_id: str
    product: str
    affected_versions: str  # a regex matching vulnerable versions
    cvss: float
    description: str
    references: list


_CVE_KB: List[CveEntry] = [
    CveEntry(
        cve_id="CVE-2021-44228",
        product="log4j",
        affected_versions=r"^2\.(0|1[0-7])\.|2\.(1[0-6])\.",
        cvss=10.0,
        description="Log4Shell: JNDI injection in Apache Log4j <=2.14.1 (RCE).",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    ),
    CveEntry(
        cve_id="CVE-2022-22965",
        product="spring-framework",
        affected_versions=r"^5\.(3\.(0|1[0-7]))",
        cvss=9.8,
        description="Spring4Shell: RCE via data binding on JDK 9+.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    ),
    CveEntry(
        cve_id="CVE-2021-41773",
        product="apache-httpd",
        affected_versions=r"^2\.4\.49$",
        cvss=7.5,
        description="Apache path traversal and RCE in 2.4.49.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    ),
    CveEntry(
        cve_id="CVE-2019-3398",
        product="confluence",
        affected_versions=r"^6\.(6\.(0|1[0-2])|7\.(0|1[0-3]))",
        cvss=8.8,
        description="Atlassian Confluence server-side template injection.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-3398"],
    ),
    CveEntry(
        cve_id="CVE-2017-5638",
        product="struts2",
        affected_versions=r"^2\.5\.(0|1[0-9])",
        cvss=10.0,
        description="Apache Struts 2 RCE via Content-Type header.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
    ),
    CveEntry(
        cve_id="CVE-2023-23752",
        product="joomla",
        affected_versions=r"^4\.0\.[0-3]$|^4\.1\.[0-5]$",
        cvss=9.8,
        description="Joomla unauthenticated API access in 4.0.0-4.1.5.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-23752"],
    ),
    CveEntry(
        cve_id="CVE-2022-40684",
        product="fortios",
        affected_versions=r"^7\.(0\.[0-5]|2\.[0-1])",
        cvss=9.6,
        description="FortiOS auth bypass via crafted HTTP request.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-40684"],
    ),
]


class CveModule(BaseModule):
    """Correlate detected technologies with the CVE KB."""

    name = "cve"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery
        self.tech_versions: List[dict] = []

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        self._extract_versions()
        for tech in self.tech_versions:
            for entry in _CVE_KB:
                if entry.product.lower() not in tech["product"].lower():
                    continue
                if re.search(entry.affected_versions, tech["version"]):
                    findings.append(Finding(
                        title=f"Potential CVE: {entry.cve_id} ({tech['product']} {tech['version']})",
                        severity=severity_from_cvss(entry.cvss),
                        confidence=60,
                        target=self.target,
                        endpoint=self.target,
                        description=(
                            f"{tech['product']} {tech['version']} may be affected by "
                            f"{entry.cve_id}. {entry.description}"
                        ),
                        evidence=f"Detected: {tech['product']} {tech['version']}",
                        reproduction_steps=(
                            "Manual verification required: confirm the exact version "
                            "and review the CVE advisory."
                        ),
                        impact=f"CVSS {entry.cvss}: {entry.description}",
                        recommendation="Upgrade to a patched version per the vendor advisory.",
                        references=entry.references,
                        cve=entry.cve_id,
                        cvss=entry.cvss,
                        module=self.name,
                        potential=True,
                    ))
        self.logger.module(self.name, "completed")
        return findings

    def _extract_versions(self) -> None:
        resp = self.http.get(self.target)
        if not resp:
            return

        server = resp.header("Server")
        powered = resp.header("X-Powered-By")
        if server:
            m = re.search(r'(apache|nginx|httpd)[/\s]v?([\d.]+)', server, re.IGNORECASE)
            if m:
                product = "apache-httpd" if "apache" in m.group(1).lower() or "httpd" in m.group(1).lower() else "nginx"
                self.tech_versions.append({"product": product, "version": m.group(2)})
        if powered:
            m = re.search(r'(PHP)[/\s]v?([\d.]+)', powered, re.IGNORECASE)
            if m:
                self.tech_versions.append({"product": "php", "version": m.group(2)})
            m = re.search(r'(ASP\.NET)[/\s]v?([\d.]+)', powered, re.IGNORECASE)
            if m:
                self.tech_versions.append({"product": "asp.net", "version": m.group(2)})
            m = re.search(r'(Express)[/\s]v?([\d.]+)', powered, re.IGNORECASE)
            if m:
                self.tech_versions.append({"product": "express", "version": m.group(2)})

        body = resp.body
        if self.discovery:
            for tech in self.discovery.technologies:
                self.tech_versions.append({"product": tech.lower(), "version": ""})
        m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', body)
        if m:
            self.tech_versions.append({"product": "wordpress", "version": m.group(1)})
        m = re.search(r'<meta name="generator" content="Joomla! ([\d.]+)', body)
        if m:
            self.tech_versions.append({"product": "joomla", "version": m.group(1)})
        m = re.search(r'Drupal ([\d.]+)', body, re.IGNORECASE)
        if m:
            self.tech_versions.append({"product": "drupal", "version": m.group(1)})
