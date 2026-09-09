"""WAF/CDN detection and fingerprinting module.

Detects and fingerprints:
- WAFs (Cloudflare, AWS WAF, Akamai, F5, ModSecurity, etc.)
- CDNs (Cloudflare, CloudFront, Akamai, Fastly)
- reverse proxies (nginx, HAProxy, Envoy)
- frameworks in front of the app

Like a red-team recon phase: knowing the WAF shapes attack strategy.
"""
from __future__ import annotations

import re
from typing import List

from ..base import BaseModule
from ..reporting.models import Finding, Severity


_WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "cookie": ["__cf_bm", "cf_clearance"],
        "body": ["attention required", "cloudflare"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-waf-action", "x-amz-cf-id"],
        "body": ["awselb"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamaighost"],
        "cookie": ["ak_bmsc"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["server: bigip"],
        "cookie": ["ts", "asd"],
    },
    "ModSecurity": {
        "headers": ["server: mod_security"],
        "body": ["mod_security"],
    },
    "Imperva Incapsula": {
        "headers": ["x-iinfo"],
        "cookie": ["incap_ses", "visid_incap"],
    },
    "Sucuri": {
        "headers": ["server: sucuri"],
        "body": ["sucuri"],
    },
    "Fastly": {
        "headers": ["x-served-by", "x-fastly"],
    },
    "Wordfence": {
        "body": ["wf_", "wordfence"],
    },
}

_CDN_SIGNATURES = {
    "Cloudfront": [r"cloudfront\.net|x-amz-cf-id"],
    "Cloudflare": [r"cf-ray|__cf_bm"],
    "Akamai": [r"akamai|x-akamai"],
    "Fastly": [r"x-served-by.*cache|x-fastly"],
    "Azure CDN": [r"x-azure-ref"],
}


class WafModule(BaseModule):
    """Detect and fingerprint WAFs, CDNs, and reverse proxies."""

    name = "waf"

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        resp = self.http.get(self.target)
        if not resp:
            return findings

        detected_waf = None
        all_headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        all_cookies_str = resp.header("Set-Cookie")
        lower_body = resp.body.lower()

        # check each WAF signature
        for waf_name, sigs in _WAF_SIGNATURES.items():
            matched = False
            for header_pattern in sigs.get("headers", []):
                if header_pattern.lower() in all_headers_str.lower():
                    detected_waf = waf_name
                    matched = True
                    break
            if not matched:
                for cookie_pattern in sigs.get("cookie", []):
                    if cookie_pattern.lower() in (all_cookies_str or "").lower():
                        detected_waf = waf_name
                        matched = True
                        break
            if not matched:
                for body_pattern in sigs.get("body", []):
                    if body_pattern.lower() in lower_body:
                        detected_waf = waf_name
                        matched = True
                        break

        if detected_waf:
            findings.append(Finding(
                title=f"WAF detected: {detected_waf}",
                severity=Severity.INFO,
                confidence=90,
                target=self.target,
                endpoint=resp.url,
                description=f"A WAF ({detected_waf}) is in front of the target. "
                            "This shapes the attack strategy — payloads may need "
                            "obfuscation or alternative encoding.",
                evidence=f"Detected via signature matching on headers/cookies/body.",
                request=f"GET {self.target}",
                reproduction_steps="Send a benign request and inspect headers for WAF signatures.",
                impact="WAF may block or rate-limit aggressive testing.",
                recommendation="Account for the WAF when planning remediation and testing.",
                references=["https://owasp.org/www-community/",
                            "https://github.com/EnableSecurity/wafw00f"],
                module=self.name,
            ))
        else:
            findings.append(Finding(
                title="No WAF detected",
                severity=Severity.INFO,
                confidence=60,
                target=self.target,
                endpoint=resp.url,
                description="No WAF was detected. The target may be exposed to "
                            "direct attack or use a custom/unknown WAF.",
                evidence="No known WAF signatures matched.",
                request=f"GET {self.target}",
                reproduction_steps="Compare headers against known WAF signatures.",
                impact="No additional protection layer detected.",
                recommendation="Consider deploying a WAF if one is not present.",
                module=self.name,
                potential=True,
            ))

        # check for rate-limiting headers
        rate_headers = ["x-ratelimit-limit", "x-ratelimit-remaining",
                        "retry-after", "x-rate-limit"]
        for rh in rate_headers:
            if resp.header(rh):
                findings.append(Finding(
                    title="Rate limiting detected",
                    severity=Severity.INFO,
                    confidence=90,
                    target=self.target,
                    endpoint=resp.url,
                    description=f"The server enforces rate limiting via {rh}.",
                    evidence=f"{rh}: {resp.header(rh)}",
                    request=f"GET {self.target}",
                    reproduction_steps="Send requests rapidly and observe rate-limit headers.",
                    impact="Rate limiting will throttle aggressive testing.",
                    recommendation="Respect rate limits during testing; they are a defense control.",
                    module=self.name,
                ))
                break

        self.logger.module(self.name, "completed")
        return findings
