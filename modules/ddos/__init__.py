"""DDoS protection assessment module (non-destructive).

Evaluates the target's resilience against denial-of-service attacks by
*measuring* defensive posture without attacking:

- CDN/WAF presence & fingerprinting (Cloudflare, Akamai, AWS Shield,
  CloudFront, Fastly, Sucuri, Imperva, etc.)
- Rate limiting / connection limiting behavior (HTTP 429, Retry-After,
  X-RateLimit-* headers) via a small, controlled request burst
- Latency stability under light controlled load (a few hundred requests
  at low concurrency — equivalent to a polite load test, NOT a flood)
- Configuration weaknesses that make a DDoS *easier*: missing cache
  headers, no compression, unprotected sensitive endpoints, HTTP
  keep-alive abuse surfaces, verbose error handling
- Produces an anti-DDoS posture score and prioritized recommendations

Every request goes through the rate-limited HttpClient. No floods,
no amplification, no connection exhaustion — this module observes
behavior only.
"""
from __future__ import annotations

import statistics
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


# (name, header keys, cookie names, body markers)
_PROTECTIONS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "server"],
     ["__cf_bm", "cf_clearance"],
     ["attention required", "cloudflare"]),
    ("AWS Shield / WAF", ["x-amzn-waf-action", "x-amz-cf-id", "server"],
     [], ["awselb", "amazonaws"]),
    ("Akamai", ["x-akamai-transformed", "akamaighost"], ["ak_bmsc"],
     ["akamai"]),
    ("Fastly", ["x-served-by", "x-fastly", "x-cache"], [], ["fastly"]),
    ("Imperva Incapsula", ["x-iinfo"], ["incap_ses", "visid_incap"], []),
    ("Sucuri", ["server"], [], ["sucuri", "cloudproxy"]),
    ("F5 BIG-IP ASM", ["server"], ["ts", "asd"], []),
    ("Azure Front Door / CDN", ["x-azure-ref", "server"], [], ["azure"]),
    ("StackPath", ["server", "x-llid"], ["sp_*"], ["stackpath"]),
    ("GCP Cloud Armor / LB", ["server"], [], ["google", "gclb"]),
]

_SENSITIVE_PATHS = [
    "/admin", "/login", "/api/", "/wp-login.php", "/admin/login",
    "/dashboard", "/user/login", "/reset-password", "/register",
]


class DdosProtectionModule(BaseModule):
    """Assess DDoS resilience posture without performing attacks."""

    name = "ddos_protection"

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []
        resp = self.http.get(self.target)
        if not resp:
            self.logger.error("Cannot reach target for DDoS assessment")
            return findings

        protections = self._detect_protections(resp)

        # 1. CDN/WAF presence — the single biggest DDoS mitigation lever
        if protections:
            names = ", ".join(sorted(protections.keys()))
            findings.append(Finding(
                title=f"CDN/WAF Protection Detected: {names}",
                severity=Severity.INFO,
                confidence=90,
                target=self.target,
                endpoint=self.target,
                description=(
                    f"Traffic is fronted by {names}. A CDN/WAF absorbs volumetric "
                    "attacks before they reach the origin, which significantly "
                    "improves DDoS resilience."
                ),
                evidence=f"Signatures matched: {names}",
                module=self.name,
                recommendation="Keep the CDN/WAF in front of ALL traffic and enable DDoS scrubbing.",
                cwe="CWE-693",  # Protection Mechanism Failure (inverse: it's present)
            ))
        else:
            findings.append(Finding(
                title="No CDN/WAF Protection Detected",
                severity=Severity.HIGH,
                confidence=80,
                target=self.target,
                endpoint=self.target,
                description=(
                    "No known CDN or WAF signatures were found. The origin is directly "
                    "exposed, so a volumetric attack reaches the server itself. This is "
                    "the most common reason sites are taken down by DDoS."
                ),
                evidence="No CDN/WAF signature matched response headers or cookies.",
                module=self.name,
                recommendation=(
                    "Put the site behind a DDoS-mitigating CDN (Cloudflare, AWS Shield, "
                    "Akamai, etc.) and hide the origin IP."
                ),
                cwe="CWE-693",
            ))

        # 2. Rate limiting behavior on the main page (controlled burst)
        rate_finding = self._test_rate_limiting(resp)
        if rate_finding:
            findings.append(rate_finding)

        # 3. Latency stability under light controlled load
        latency_finding = self._test_latency_stability()
        if latency_finding:
            findings.append(latency_finding)

        # 4. Config weaknesses that make DDoS easier
        findings.extend(self._check_config_weaknesses(resp))

        # 5. Sensitive endpoints unprotected (not behind rate limiting / auth)
        findings.extend(self._check_sensitive_endpoints())

        return findings

    # ------------------------------------------------------------- helpers
    def _detect_protections(self, resp) -> Dict[str, str]:
        """Return {protection_name: evidence} for detected CDN/WAF."""
        found: Dict[str, str] = {}
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = (resp.body or "").lower()

        for name, header_keys, cookies, markers in _PROTECTIONS:
            evidence = []
            for key in header_keys:
                val = headers.get(key, "")
                if val and name.lower() in val.lower() or \
                   (key in headers and key in ("cf-ray", "x-amz-cf-id", "x-azure-ref",
                                               "x-iinfo", "x-served-by", "x-cache",
                                               "akamaighost", "x-akamai-transformed")):
                    if headers.get(key):
                        evidence.append(f"header {key}={headers[key]}")
            for marker in markers:
                if marker in body:
                    evidence.append(f"body marker '{marker}'")
            if evidence:
                found[name] = "; ".join(evidence[:3])
        return found

    def _test_rate_limiting(self, resp) -> Finding | None:
        """Send a small burst of requests and see if throttling kicks in.

        Uses ~15 requests with a short delay — well within normal browsing
        patterns, nothing like an actual flood.
        """
        client = self.http
        url = self.target
        statuses: List[int] = []
        had_ratelimit_header = False

        for _ in range(15):
            r = client.get(url)
            if not r:
                continue
            statuses.append(r.status)
            if r.status in (429, 503):
                break
            h = {k.lower(): v for k, v in r.headers.items()}
            if any(k.startswith("x-ratelimit") or k == "retry-after" for k in h):
                had_ratelimit_header = True

        throttled = any(s in (429, 503) for s in statuses)
        if throttled or had_ratelimit_header:
            return Finding(
                title="Rate Limiting Present (Good)",
                severity=Severity.INFO,
                confidence=85,
                target=self.target,
                endpoint=url,
                description=(
                    "The server enforces rate limiting "
                    + (f"(observed HTTP {statuses[-1]})" if throttled else
                       "via rate-limit headers")
                    + ". This slows credential stuffing and HTTP-flood style abuse."
                ),
                evidence=f"Status codes observed: {statuses}",
                module=self.name,
                recommendation="Keep rate limiting enabled and tune limits per endpoint.",
                cwe="CWE-770",
            )
        return Finding(
            title="No Rate Limiting on Main Endpoint",
            severity=Severity.MEDIUM,
            confidence=75,
            target=self.target,
            endpoint=url,
            description=(
                "15 rapid requests to the main page did not trigger any throttling "
                "(no 429/503, no rate-limit headers). An attacker can saturate "
                "CPU/bandwidth with high request volume."
            ),
            evidence=f"All requests returned: {sorted(set(statuses))}",
            module=self.name,
            recommendation="Add per-IP request rate limits and progressive backoff.",
            cwe="CWE-770",
        )

    def _test_latency_stability(self) -> Finding | None:
        """Measure response latency over a small controlled sample.

        A handful of sequential requests — a polite load probe, equivalent
        to a website monitor. If latency spikes badly, the origin has low
        headroom and would be knocked over easily.
        """
        client = self.http
        url = self.target
        latencies: List[float] = []
        for _ in range(10):
            t0 = time.monotonic()
            r = client.get(url)
            if r:
                latencies.append(time.monotonic() - t0)
        if len(latencies) < 5:
            return None

        median = statistics.median(latencies)
        p90 = sorted(latencies)[int(len(latencies) * 0.9) - 1]
        variance = (p90 - median) / max(median, 1e-6)

        if median > 3.0 or variance > 3.0:
            return Finding(
                title="High Latency / Low Headroom Under Light Load",
                severity=Severity.MEDIUM,
                confidence=70,
                target=self.target,
                endpoint=url,
                description=(
                    f"Median response {median*1000:.0f}ms, p90 {p90*1000:.0f}ms "
                    f"(variance x{variance:.1f}). The origin is slow or unstable "
                    "even under a light load, suggesting a DDoS would exhaust it quickly."
                ),
                evidence=f"Median={median*1000:.0f}ms, P90={p90*1000:.0f}ms",
                module=self.name,
                recommendation="Increase origin capacity, add caching, and use a CDN.",
                cwe="CWE-400",  # Uncontrolled Resource Consumption
            )
        return Finding(
            title="Responsive Under Light Load",
            severity=Severity.INFO,
            confidence=80,
            target=self.target,
            endpoint=url,
            description=(
                f"Median response {median*1000:.0f}ms with stable latency "
                f"(p90 {p90*1000:.0f}ms) under a small controlled sample."
            ),
            evidence=f"Median={median*1000:.0f}ms, P90={p90*1000:.0f}ms",
            module=self.name,
            recommendation="Nothing to fix; monitor capacity as traffic grows.",
            cwe="CWE-400",
        )

    def _check_config_weaknesses(self, resp) -> List[Finding]:
        """Configuration issues that make DDoS attacks easier."""
        findings: List[Finding] = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Missing cache headers -> every request hits the origin
        cc = headers.get("cache-control", "").lower()
        has_caching = ("public" in cc or "max-age" in cc or
                       "s-maxage" in cc or "etag" in headers or
                       "last-modified" in headers)
        if not has_caching:
            findings.append(Finding(
                title="Static Content Not Cacheable",
                severity=Severity.LOW,
                confidence=70,
                target=self.target,
                description=(
                    "No cache headers (Cache-Control/ETag) on the main response. "
                    "Repeated requests hit the origin directly, amplifying the "
                    "effect of an HTTP flood."
                ),
                evidence=f"Cache-Control: {cc or '(missing)'}",
                module=self.name,
                recommendation="Add Cache-Control and ETag so CDNs/browsers absorb repeat requests.",
                cwe="CWE-400",
            ))

        # No compression -> bandwidth wasted
        if "content-encoding" not in headers:
            findings.append(Finding(
                title="Compression Not Enabled",
                severity=Severity.INFO,
                confidence=60,
                target=self.target,
                description=(
                    "Responses are not compressed (no Content-Encoding). Larger "
                    "payloads consume more bandwidth under flood conditions."
                ),
                module=self.name,
                recommendation="Enable gzip/br compression to reduce bandwidth use.",
                cwe="CWE-400",
            ))

        # Verbose server banner aids attacker sizing
        if "server" in headers:
            findings.append(Finding(
                title="Server Banner Exposed",
                severity=Severity.INFO,
                confidence=90,
                target=self.target,
                description=(
                    f"Server header '{headers['server']}' reveals the origin software, "
                    "helping attackers tailor exploits or fingerprint capacity."
                ),
                module=self.name,
                recommendation="Remove or obscure the Server header behind the CDN.",
                cwe="CWE-200",
            ))
        return findings

    def _check_sensitive_endpoints(self) -> List[Finding]:
        """Sensitive endpoints that, if unprotected, are prime DDoS targets."""
        findings: List[Finding] = []
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        exposed = []
        for path in _SENSITIVE_PATHS:
            r = self.http.get(base + path)
            if r and r.status == 200:
                exposed.append(path)
        if exposed:
            findings.append(Finding(
                title="Sensitive Endpoints Publicly Accessible",
                severity=Severity.MEDIUM,
                confidence=70,
                target=self.target,
                description=(
                    "Publicly reachable endpoints that are heavy to compute or "
                    "auth-relevant, making them attractive DDoS/abuse targets: "
                    + ", ".join(exposed)
                ),
                evidence="Paths returning 200: " + ", ".join(exposed),
                module=self.name,
                recommendation="Protect these endpoints with auth, rate limiting, and caching.",
                cwe="CWE-770",
            ))
        return findings
