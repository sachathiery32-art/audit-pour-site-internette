"""Site OSINT reconnaissance module.

Passively gathers public information about the target:
- IP addresses (DNS resolution)
- Geolocation, ISP, organization, ASN (via ip-api.com)
- Domain registrar, creation date, expiry, emails, nameservers (RDAP)
- Site age / first archived snapshot (Wayback Machine CDX)
- security.txt contact email
- Server headers, technologies, protections (WAF/CDN/rate-limit)

All data is *passive* OSINT — no intrusive scanning, just public records
and metadata. Output is a :class:`SiteInfo` object plus INFO findings.
"""
from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity

try:
    import dns.resolver as _dns_resolver
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False


@dataclass
class SiteInfo:
    """Aggregated passive OSINT data about the target site."""
    domain: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    country: str = ""
    city: str = ""
    region: str = ""
    isp: str = ""
    organization: str = ""
    asn: str = ""
    registrar: str = ""
    created: str = ""
    expires: str = ""
    updated: str = ""
    emails: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    first_snapshot: str = ""
    security_contact: str = ""
    server_header: str = ""
    powered_by: str = ""
    technologies: List[str] = field(default_factory=list)
    protections: List[str] = field(default_factory=list)  # WAF/CDN/rate-limit
    days_since_created: Optional[int] = None
    # DNS records (SPF / DKIM / DMARC / MX / TXT / CAA) — OSINT goldmine
    dns_records: Dict = field(default_factory=dict)
    reverse_dns: str = ""
    mailto_emails: List[str] = field(default_factory=list)
    github_repos: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "ip_addresses": self.ip_addresses,
            "geolocation": {
                "country": self.country, "city": self.city, "region": self.region,
            },
            "isp": self.isp,
            "organization": self.organization,
            "asn": self.asn,
            "registrar": self.registrar,
            "created": self.created,
            "expires": self.expires,
            "updated": self.updated,
            "days_since_created": self.days_since_created,
            "emails": self.emails,
            "nameservers": self.nameservers,
            "first_snapshot": self.first_snapshot,
            "security_contact": self.security_contact,
            "server_header": self.server_header,
            "powered_by": self.powered_by,
            "technologies": self.technologies,
            "protections": self.protections,
            "dns_records": self.dns_records,
            "reverse_dns": self.reverse_dns,
            "mailto_emails": self.mailto_emails,
        }


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


class SiteInfoModule(BaseModule):
    """Gather passive OSINT information about the target site."""

    name = "siteinfo"

    def __init__(self, http, logger, target, config=None):
        super().__init__(http, logger, target, config)
        parsed = urlparse(target)
        self.domain = parsed.hostname or target.strip("/")
        self.info = SiteInfo(domain=self.domain)

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        self._resolve_dns()
        self._collect_dns_records()      # SPF/DKIM/DMARC/MX/CAA + emails
        self._reverse_dns()
        self._fetch_geolocation()
        self._fetch_rdap()
        self._fetch_wayback()
        self._fetch_security_txt()
        self._collect_mailto_emails()    # emails in page bodies
        self._collect_headers()

        # protections detected in other modules / headers
        resp = self.http.get(self.target)
        if resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            if "cf-ray" in hdrs or "__cf_bm" in str(hdrs):
                self.info.protections.append("Cloudflare")
            if "x-amz-cf-id" in hdrs:
                self.info.protections.append("CloudFront")
            if any("ratelimit" in k or "rate-limit" in k for k in hdrs):
                self.info.protections.append("Rate limiting")
            if resp.header("Strict-Transport-Security"):
                self.info.protections.append("HSTS")

        # compute days since creation
        if self.info.created:
            try:
                dt = datetime.fromisoformat(self.info.created.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                self.info.days_since_created = (datetime.now(timezone.utc) - dt).days
            except (ValueError, TypeError):
                pass

        findings.extend(self._build_findings())
        self.logger.module(self.name, "completed")
        return findings

    # --- data gathering ---
    def _resolve_dns(self) -> None:
        if _HAS_DNS:
            try:
                answers = _dns_resolver.resolve(self.domain, "A")
                self.info.ip_addresses = [str(r) for r in answers]
            except Exception:
                pass
        if not self.info.ip_addresses:
            try:
                import socket
                self.info.ip_addresses = [
                    socket.gethostbyname(self.domain),
                ]
            except Exception:
                pass

    def _collect_dns_records(self) -> None:
        """Collect SPF / DKIM / DMARC / MX / TXT / CAA records.

        Mails published in DNS (DMARC rua=, SPF includes) are real OSINT
        finds: they name the admin address of the domain.
        """
        if not _HAS_DNS:
            return
        records: Dict[str, list] = {"spf": [], "dkim": [], "dmarc": [],
                                    "mx": [], "txt": [], "caa": [],
                                    "ns": []}
        # TXT (SPF, DKIM selectors, misc)
        try:
            answers = _dns_resolver.resolve(self.domain, "TXT")
            for r in answers:
                txt = " ".join(r.strings if hasattr(r, "strings") else [str(r)])
                low = txt.lower()
                if "v=spf1" in low:
                    records["spf"].append(txt)
                elif "._domainkey" in low or "k=rsa" in low or "v=dkim1" in low:
                    records["dkim"].append(txt)
                else:
                    records["txt"].append(txt)
        except Exception:
            pass
        # MX
        try:
            answers = _dns_resolver.resolve(self.domain, "MX")
            for r in answers:
                records["mx"].append(str(r.exchange).rstrip("."))
        except Exception:
            pass
        # NS (fallback if RDAP empty)
        try:
            answers = _dns_resolver.resolve(self.domain, "NS")
            records["ns"] = [str(r).rstrip(".") for r in answers]
        except Exception:
            pass
        # CAA
        try:
            answers = _dns_resolver.resolve(self.domain, "CAA")
            for r in answers:
                records["caa"].append(str(r))
        except Exception:
            pass
        # DMARC (separate subdomain record)
        try:
            answers = _dns_resolver.resolve("_dmarc." + self.domain, "TXT")
            for r in answers:
                txt = " ".join(r.strings if hasattr(r, "strings") else [str(r)])
                records["dmarc"].append(txt)
        except Exception:
            pass
        self.info.dns_records = records

        # extract emails from DMARC / SPF / DKIM text
        text = " ".join(records["dmarc"] + records["spf"])
        for m in _EMAIL_RE.finditer(text):
            email = m.group(0).lower()
            if email not in self.info.emails:
                self.info.emails.append(email)

    def _reverse_dns(self) -> None:
        if not self.info.ip_addresses:
            return
        try:
            name = socket.gethostbyaddr(self.info.ip_addresses[0])[0]
            self.info.reverse_dns = name
        except Exception:
            pass

    def _collect_mailto_emails(self) -> None:
        """Find mailto: links and contact emails in public pages."""
        pages = [self.target]
        for path in ("/contact", "/contact-us", "/about", "/mentions-legales",
                     "/legal", "/impressum", "/team", "/a-propos"):
            pages.append(self.target.rstrip("/") + path)
        found: List[str] = []
        mailto_re = re.compile(r"mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.IGNORECASE)
        for url in pages:
            try:
                resp = self.http.get(url)
            except Exception:
                resp = None
            if not resp or not resp.body:
                continue
            for m in (_EMAIL_RE.finditer(resp.body)
                      if mailto_re.search(resp.body) else mailto_re.finditer(resp.body)):
                email = m.group(1).lower() if m.lastindex and m.group(1) else m.group(0).lower()
                if email not in found and "example" not in email:
                    found.append(email)
            if len(found) >= 15:
                break
        self.info.mailto_emails = found[:20]
        for e in found:
            if e not in self.info.emails:
                self.info.emails.append(e)

    def _fetch_geolocation(self) -> None:
        if not self.info.ip_addresses:
            return
        ip = self.info.ip_addresses[0]
        resp = self.http.get(f"http://ip-api.com/json/{ip}")
        if not resp:
            return
        try:
            data = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return
        if data.get("status") == "success":
            self.info.country = data.get("country", "")
            self.info.city = data.get("city", "")
            self.info.region = data.get("regionName", "")
            self.info.isp = data.get("isp", "")
            self.info.organization = data.get("org", "")
            self.info.asn = data.get("as", "")

    def _fetch_rdap(self) -> None:
        """Fetch WHOIS-style data via RDAP (https://rdap.org)."""
        # rdap.org redirects to the appropriate registry
        rdap_url = f"https://rdap.org/domain/{self.domain}"
        resp = self.http.get(rdap_url, allow_redirects=True)
        if not resp:
            return
        try:
            data = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return

        entities = data.get("entities", [])
        for ent in entities:
            roles = " ".join(ent.get("roles", []))
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [[], []])
                for item in vcard[1] if len(vcard) > 1 else []:
                    if item[0] == "fn":
                        self.info.registrar = item[3]
            # collect emails from vcard
            vcard = ent.get("vcardArray", [[], []])
            for item in vcard[1] if len(vcard) > 1 else []:
                if item[0] == "email":
                    self.info.emails.append(item[3])

        events = data.get("events", [])
        for ev in events:
            action = ev.get("eventAction", "")
            when = ev.get("eventDate", "")
            if action == "registration":
                self.info.created = when
            elif action == "expiration":
                self.info.expires = when
            elif action == "last changed":
                self.info.updated = when

        ns = data.get("nameservers", [])
        self.info.nameservers = [n.get("ldhName", "") for n in ns if n.get("ldhName")]

    def _fetch_wayback(self) -> None:
        """Get the first archived snapshot date via the CDX API."""
        cdx = (
            f"https://web.archive.org/cdx/search/cdx?url={self.domain}&output=json"
            "&limit=1&fl=timestamp&filter=statuscode:200&from=1996"
        )
        resp = self.http.get(cdx)
        if not resp:
            return
        try:
            data = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return
        if isinstance(data, list) and len(data) > 1:
            ts = data[1][0]  # e.g. "19981111195532"
            if len(ts) >= 8:
                self.info.first_snapshot = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"

    def _fetch_security_txt(self) -> None:
        url = self.target.rstrip("/") + "/.well-known/security.txt"
        resp = self.http.get(url)
        if not resp or resp.status != 200:
            return
        for m in _EMAIL_RE.finditer(resp.body):
            if "example" not in m.group(0):
                self.info.security_contact = m.group(0)
                break

    def _collect_headers(self) -> None:
        resp = self.http.get(self.target)
        if not resp:
            return
        self.info.server_header = resp.header("Server")
        self.info.powered_by = resp.header("X-Powered-By")
        body_lower = resp.body.lower()
        tech_sigs = {
            "WordPress": ["wp-content", "wp-includes"],
            "React": ["react", "_next"],
            "Vue.js": ["vue", "__nuxt"],
            "Angular": ["angular", "ng-"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "ASP.NET": ["__viewstate", "asp.net"],
            "PHP": ["x-powered-by"],
        }
        for tech, sigs in tech_sigs.items():
            if any(s in body_lower for s in sigs):
                if tech not in self.info.technologies:
                    self.info.technologies.append(tech)

    # --- findings ---
    def _build_findings(self) -> List[Finding]:
        findings: List[Finding] = []

        # summary finding: hosting & location
        lines = []
        if self.info.ip_addresses:
            lines.append(f"IP: {', '.join(self.info.ip_addresses)}")
        if self.info.country:
            lines.append(f"Geolocation: {self.info.city}, {self.info.region}, {self.info.country}")
        if self.info.isp:
            lines.append(f"ISP: {self.info.isp}")
        if self.info.organization:
            lines.append(f"Organization: {self.info.organization}")
        if self.info.asn:
            lines.append(f"ASN: {self.info.asn}")
        if self.info.registrar:
            lines.append(f"Registrar: {self.info.registrar}")
        if self.info.created:
            lines.append(f"Domain created: {self.info.created}")
            if self.info.days_since_created is not None:
                lines.append(f"Domain age: {self.info.days_since_created} days")
        if self.info.expires:
            lines.append(f"Domain expires: {self.info.expires}")
        if self.info.first_snapshot:
            lines.append(f"First archived: {self.info.first_snapshot}")
        if lines:
            findings.append(Finding(
                title="Site information (hosting & domain)",
                severity=Severity.INFO,
                confidence=95,
                target=self.target,
                description="Passive OSINT summary of the target's hosting and domain records.",
                evidence="\n".join(lines),
                impact="Public metadata used for footprinting and social engineering.",
                recommendation="Review what public records reveal about your infrastructure.",
                module=self.name,
            ))

        # emails
        emails = list(self.info.emails)
        if self.info.security_contact:
            emails.append(self.info.security_contact)
        emails = list(dict.fromkeys(emails))[:10]
        if emails:
            findings.append(Finding(
                title="Public email addresses found",
                severity=Severity.INFO,
                confidence=80,
                target=self.target,
                description="Email addresses exposed via WHOIS/RDAP or security.txt.",
                evidence="\n".join(emails),
                impact="Phishing and credential-stuffing targets.",
                recommendation="Use privacy protection on WHOIS records where available.",
                module=self.name,
                potential=True,
            ))

        # protections
        if self.info.protections:
            findings.append(Finding(
                title="Detected protections",
                severity=Severity.INFO,
                confidence=85,
                target=self.target,
                description="Security layers detected in front of the target.",
                evidence=", ".join(self.info.protections),
                impact="Protections shape attack strategy; they may block aggressive testing.",
                recommendation="Keep protections updated and tuned.",
                module=self.name,
            ))

        return findings
