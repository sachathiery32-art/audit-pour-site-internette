"""Subdomain takeover detection module.

Checks DNS CNAME records pointing to vulnerable services:
- GitHub Pages (404 on *.github.io)
- Heroku (No such app)
- S3 (NoSuchBucket)
- Azure (*.cloudapp.net)
- Tumblr (No such blog)
- etc.

Only checks subdomains explicitly in allowed_hosts (authorized scope).
"""
from __future__ import annotations

import re
from typing import List

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity

try:
    import dns.resolver as _dns_resolver
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False


# (service name, CNAME pattern, response fingerprint, severity)
_TAKEOVER_SIGS = [
    ("GitHub Pages", r"github\.io", r"404|There isn't a GitHub Pages site here",
     Severity.HIGH),
    ("Heroku", r"herokuapp\.com", r"No such app|No app found",
     Severity.HIGH),
    ("S3", r"s3[.\-].*amazonaws\.com", r"NoSuchBucket|The specified bucket does not exist",
     Severity.HIGH),
    ("Azure", r"\.cloudapp\.net|\.azurewebsites\.net", r"404 Web Site does not exist",
     Severity.HIGH),
    ("Tumblr", r"tumblr\.com", r"Whatever you were looking for doesn't exist",
     Severity.MEDIUM),
    ("Shopify", r"myshopify\.com", r"Shopify|Sorry, this shop is currently unavailable",
     Severity.MEDIUM),
    ("Fastly", r"fastly\.net", r"Fastly|domain not found",
     Severity.MEDIUM),
    ("Ghost", r"ghost\.io", r"Domain not found|The page you are looking for",
     Severity.MEDIUM),
    ("Pantheon", r"pantheonsite\.io", r"The gods are wise|404 error",
     Severity.MEDIUM),
    ("Tilda", r"tilda\.ws", r"Please renew your subscription",
     Severity.MEDIUM),
    ("WordPress", r"wordpress\.com", r"Do you want to register|blog doesn't exist",
     Severity.MEDIUM),
    ("Teamwork", r"teamwork\.com", r"Oops! We couldn't find that page",
     Severity.LOW),
    ("Help Scout", r"helpscoutdocs\.com", r"domain is not configured",
     Severity.MEDIUM),
    ("Cargo", r"cargocollective\.com", r"If you're moving your domain",
     Severity.MEDIUM),
    ("Strikingly", r"strikingly\.com", r"page not found|Domain not registered",
     Severity.MEDIUM),
]


class TakeoverModule(BaseModule):
    """Check for subdomain takeover on in-scope hosts."""

    name = "takeover"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        # gather hosts to check: the target hostname + any allowed_hosts
        from urllib.parse import urlparse
        hosts = set()
        host = urlparse(self.target).hostname or ""
        if host:
            hosts.add(host)
        if self.config and getattr(self.config, "allowed_hosts", None):
            hosts.update(self.config.allowed_hosts)

        for hostname in hosts:
            findings.extend(self._check_host(hostname))

        self.logger.module(self.name, "completed")
        return findings

    def _check_host(self, hostname: str) -> List[Finding]:
        findings: List[Finding] = []
        if not _HAS_DNS:
            return findings

        # get CNAME records
        try:
            answers = _dns_resolver.resolve(hostname, "CNAME")
            cnames = [str(r).rstrip(".") for r in answers]
        except Exception:
            cnames = []

        if not cnames:
            return findings

        for cname in cnames:
            for service, pattern, fingerprint, severity in _TAKEOVER_SIGS:
                if not re.search(pattern, cname, re.IGNORECASE):
                    continue
                # fetch the URL and check the fingerprint
                url = f"https://{hostname}"
                resp = self.http.get(url)
                if not resp:
                    # try http
                    resp = self.http.get(f"http://{hostname}")
                if not resp:
                    continue
                if re.search(fingerprint, resp.body, re.IGNORECASE):
                    findings.append(Finding(
                        title=f"Potential subdomain takeover: {service}",
                        severity=severity,
                        confidence=75,
                        target=hostname,
                        endpoint=f"https://{hostname}",
                        description=(
                            f"The subdomain '{hostname}' has a CNAME pointing to {service} "
                            f"({cname}), and the service returned a 'not found' page, "
                            "indicating the resource is unclaimed and can be taken over."
                        ),
                        evidence=(
                            f"CNAME: {cname}\n"
                            f"Fingerprint matched: {fingerprint}\n"
                            f"Response snippet: {resp.body[:200]}"
                        ),
                        request=f"GET https://{hostname}",
                        response_indicators=f"Body matched: {fingerprint}",
                        reproduction_steps=(
                            f"1. Resolve CNAME for {hostname}.\n"
                            f"2. Access https://{hostname}.\n"
                            f"3. Observe the '{service}' not-found page.\n"
                            f"4. Claim the resource on {service} to verify."
                        ),
                        impact="Full control of the subdomain's content; phishing, cookie theft, reputation damage.",
                        recommendation="Remove dangling DNS records for decommissioned services.",
                        references=["https://owasp.org/www-community/attacks/"],
                        module=self.name,
                        potential=True,
                    ))
        return findings
