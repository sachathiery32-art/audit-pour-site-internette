"""Subdomain enumeration and per-subdomain attack-surface probing.

Discovers subdomains of the authorized target using:
- Certificate Transparency (crt.sh) — no DNS wordlist needed
- DNS brute force with a small common-prefix wordlist
- CNAME records of each discovered host

Then, for every *alive* subdomain, runs a light probe:
- HTTP/HTTPS reachability, redirects, server banner, technologies
- login page / admin panel / api path detection (the "find a login"
  behaviour the user wants)
- basic security headers check
- subdomain takeover fingerprint (reuses the takeover logic)

Every check is passive or uses harmless GET requests, stays inside the
authorized domain, and is rate-limited through the shared HttpClient.
"""

from __future__ import annotations

import json
import re
import socket
import time
from typing import Dict, List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity

try:
    import dns.resolver as _dns_resolver
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False

try:
    import requests as _requests
    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False


# Common subdomain prefixes — small, targeted, respectful of rate limits.
_COMMON_PREFIXES = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
    "ssh", "vpn", "remote", "portal", "intranet", "extranet", "api",
    "api2", "api3", "dev", "test", "staging", "stage", "qa", "uat",
    "preprod", "pre-prod", "demo", "beta", "alpha", "sandbox", "lab",
    "admin", "administrator", "manage", "manager", "dashboard", "cms",
    "backoffice", "back-office", "intra", "internal", "internal-www",
    "corp", "corporate", "office", "owa", "exchange", "lync", "autodiscover",
    "m", "mobile", "app", "apps", "application", "shop", "store", "boutique",
    "billing", "pay", "payment", "payments", "checkout", "cart", "cdn",
    "static", "assets", "img", "images", "media", "video", "files", "uploads",
    "download", "downloads", "dl", "docs", "documentation", "wiki", "help",
    "support", "status", "stats", "analytics", "monitor", "monitoring",
    "logs", "log", "grafana", "kibana", "jenkins", "ci", "cd", "git",
    "gitlab", "github", "bitbucket", "svn", "cvs", "repo", "repos",
    "db", "database", "mysql", "pgsql", "mongo", "redis", "elastic",
    "elasticsearch", "solr", "search", "kafka", "rabbit", "mq",
    "docker", "k8s", "kubernetes", "rancher", "registry", "harbor",
    "jenkins-ci", "build", "builds", "nightly", "release", "releases",
    "blog", "news", "forum", "community", "chat", "irc", "discord",
    "calendar", "mail2", "owa2", "mx", "ns1", "ns2", "ns3", "dns",
    "ns", "nameserver", "db1", "db2", "web1", "web2", "app1", "app2",
    "old", "legacy", "new", "v1", "v2", "v3", "mobile-api", "gateway",
    "auth", "sso", "login", "signin", "account", "accounts", "my",
    "myaccount", "secure", "secure2", "ssl", "pki", "certs", "ca",
]

_LOGIN_PATHS = ["/login", "/login.php", "/signin", "/sign-in", "/auth/login",
                "/auth/signin", "/account/login", "/user/login",
                "/wp-login.php", "/administrator", "/admin/login",
                "/panel", "/console", "/cms/login", "/portal/login"]
_ADMIN_PATHS = ["/admin", "/administrator", "/manage", "/dashboard",
                "/wp-admin", "/panel", "/console"]
_API_PATHS = ["/api", "/api/v1", "/v1", "/graphql", "/swagger", "/api-docs",
              "/swagger-ui.html", "/actuator", "/actuator/health", "/health",
              "/.well-known/security.txt", "/.git/config", "/.env"]

_SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                     "X-Frame-Options", "X-Content-Type-Options",
                     "Referrer-Policy", "Permissions-Policy"]

# CNAME -> vulnerable service fingerprints (subdomain takeover)
_TAKEOVER_CNAMES = [
    ("github.io", "GitHub Pages", r"404|There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", r"No such app|No app found"),
    ("amazonaws.com", "AWS S3", r"NoSuchBucket|The specified bucket does not exist"),
    ("azurewebsites.net", "Azure App Service", r"404 Web Site does not exist"),
    ("cloudapp.net", "Azure", r"404 Web Site does not exist"),
    ("myshopify.com", "Shopify", r"Sorry, this shop is currently unavailable"),
    ("fastly.net", "Fastly", r"domain not found"),
    ("ghost.io", "Ghost", r"Domain not found"),
    ("pantheonsite.io", "Pantheon", r"The gods are wise|404 error"),
    ("wordpress.com", "WordPress.com", r"blog doesn't exist|Do you want to register"),
    ("tumblr.com", "Tumblr", r"There's nothing here|Whatever you were looking for"),
    ("cargocollective.com", "Cargo", r"If you're moving your domain"),
    ("helpscoutdocs.com", "Help Scout", r"domain is not configured"),
    ("strikingly.com", "Strikingly", r"page not found|Domain not registered"),
    ("tilda.ws", "Tilda", r"Please renew your subscription"),
]


class SubdomainModule(BaseModule):
    """Enumerate subdomains and probe each alive host for low-hanging
    attack surface (login pages, admin panels, missing headers)."""

    name = "subdomains"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery
        parsed = urlparse(target)
        self.domain = parsed.hostname or ""
        self.discovered: List[Dict] = []   # {hostname, ip, http, https, cname}
        self._alive: Dict[str, Dict] = {}  # hostname -> {ip, ...}

    # ------------------------------------------------------------ entry
    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []
        if not self.domain or not _HAS_DNS:
            self.logger.module(self.name, "completed")
            return findings

        hostnames = self._enumerate()
        if not hostnames:
            info_f = Finding(
                title="No subdomains discovered",
                severity=Severity.INFO,
                confidence=90,
                target=self.domain,
                description=(
                    "Certificate Transparency and DNS wordlist checks found "
                    "no additional subdomains for this domain."
                ),
                impact="—",
                recommendation="—",
                module=self.name,
            )
            findings.append(info_f)
            self.logger.module(self.name, "completed")
            return findings

        # dedupe + sort
        hostnames = sorted(set(hostnames))
        findings.append(Finding(
            title=f"Subdomains discovered: {len(hostnames)}",
            severity=Severity.INFO,
            confidence=95,
            target=self.domain,
            description="\n".join(f"  - {h}" for h in hostnames[:60]),
            evidence="\n".join(sorted(set(hostnames))[:100]),
            recommendation=(
                "Review each subdomain for unnecessary exposure; decommission "
                "or restrict forgotten hosts."
            ),
            module=self.name,
        ))

        # probe each alive subdomain
        for host in hostnames:
            try:
                findings.extend(self._probe_host(host))
            except Exception as exc:
                self.logger.logger.debug(f"subdomain probe error {host}: {exc}")

        # persist for other modules / report
        if self.discovery is not None:
            try:
                self.discovery.subdomains = [
                    {"hostname": h, "ip": self._alive.get(h, {}).get("ip", "")}
                    for h in hostnames
                ]
            except Exception:
                pass

        self.logger.module(self.name, "completed")
        return findings

    # -------------------------------------------------------- discovery
    def _enumerate(self) -> List[str]:
        hosts: set = set()
        hosts.add(self.domain)
        hosts.add(f"www.{self.domain}")

        # 1) Certificate Transparency (crt.sh) — the highest value source
        ct = self._ct_logs()
        hosts.update(ct)

        # 2) DNS brute force with common prefixes (rate-limited)
        hosts.update(self._dns_brute())

        self._alive: Dict[str, Dict] = {}
        return [h for h in hosts if self._is_subdomain_of(h, self.domain)]

    def _ct_logs(self) -> List[str]:
        """Query crt.sh for certificates issued for the domain."""
        if not _HAS_REQUESTS:
            return []
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            resp = _requests.get(url, timeout=15,
                                 headers={"User-Agent": "AutoSecAudit/2.0"})
            if resp.status_code != 200:
                return []
            data = resp.json()
            names: set = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and self._is_subdomain_of(name, self.domain):
                        names.add(name.lower())
            return sorted(names)
        except Exception:
            return []

    def _dns_brute(self) -> List[str]:
        found: List[str] = []
        for prefix in _COMMON_PREFIXES:
            host = f"{prefix}.{self.domain}"
            if self._resolve(host):
                found.append(host)
            time.sleep(0.05)  # gentle pacing
        return found

    def _resolve(self, hostname: str) -> bool:
        try:
            answers = _dns_resolver.resolve(hostname, "A", lifetime=2)
            ip = str(answers[0])
            self._alive[hostname] = {"ip": ip}
            return True
        except Exception:
            return False

    @staticmethod
    def _is_subdomain_of(host: str, domain: str) -> bool:
        host = host.lower().rstrip(".")
        domain = domain.lower().rstrip(".")
        return host == domain or host.endswith("." + domain)

    # -------------------------------------------------------- probing
    def _probe_host(self, hostname: str) -> List[Finding]:
        findings: List[Finding] = []
        entry = self._alive.get(hostname, {})
        ip = entry.get("ip", "")
        http_ok = https_ok = None
        server = ""
        techs: List[str] = []

        # try HTTPS first, then HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}/"
            try:
                resp = self.http.get(url, timeout=8)
            except Exception:
                resp = None
            if resp:
                if scheme == "https":
                    https_ok = resp
                else:
                    http_ok = resp
                if not server:
                    server = resp.header("Server") or ""
                body = resp.body or ""
                for tech, pat in (
                    ("WordPress", r"wp-content|wp-includes"),
                    ("Drupal", r"sites/all|drupal\.js"),
                    ("Joomla", r"joomla|com_content"),
                    ("React", r"react|_next"),
                    ("Angular", r"ng-|angular"),
                    ("Vue", r"vue|__nuxt"),
                    ("Laravel", r"laravel"),
                    ("Django", r"django|csrftoken"),
                    ("ASP.NET", r"__VIEWSTATE"),
                    ("PHP", r"X-Powered-By:\s*PHP"),
                    ("Node.js", r"X-Powered-By:\s*Express"),
                    ("GitLab", r"gitlab"),
                    ("Jenkins", r"jenkins"),
                    ("Kibana", r"kibana"),
                    ("Grafana", r"grafana"),
                    ("phpMyAdmin", r"phpmyadmin|pma_username"),
                    ("cPanel", r"cpanel|whm"),
                ):
                    if re.search(pat, body, re.IGNORECASE) and tech not in techs:
                        techs.append(tech)

        if https_ok is None and http_ok is None:
            return findings  # not alive over HTTP(S)

        alive_url = f"https://{hostname}" if https_ok else f"http://{hostname}"
        target_desc = f"{hostname} ({ip})" if ip else hostname
        if server:
            target_desc += f" — server: {server}"

        # record in graph
        if self.discovery is not None:
            try:
                self.discovery.subdomain_hosts = getattr(
                    self.discovery, "subdomain_hosts", [])
                self.discovery.subdomain_hosts.append(
                    {"hostname": hostname, "url": alive_url, "ip": ip,
                     "server": server, "technologies": techs})
            except Exception:
                pass

        info_finding = Finding(
            title=f"Alive subdomain: {hostname}",
            severity=Severity.INFO,
            confidence=95,
            target=hostname,
            endpoint=alive_url,
            description=f"{target_desc}. Technologies: {', '.join(techs) or 'unknown'}",
            impact="Expands the attack surface beyond the root domain.",
            recommendation="Ensure every subdomain is needed, patched and monitored.",
            module=self.name,
        )
        findings.append(info_finding)

        # login page detection — the "find a login" behaviour
        login_hit = None
        for path in _LOGIN_PATHS:
            try:
                resp = self.http.get(alive_url + path, timeout=8)
            except Exception:
                resp = None
            if resp and resp.status == 200 and re.search(
                    r'<form[^>]*(action|method)', resp.body or "", re.IGNORECASE) \
                    and re.search(r'passw|passwd|pwd', resp.body or "",
                                  re.IGNORECASE):
                login_hit = alive_url + path
                break
        if login_hit:
            findings.append(Finding(
                title=f"Login page exposed on subdomain: {hostname}",
                severity=Severity.MEDIUM,
                confidence=85,
                target=hostname,
                endpoint=login_hit,
                description=(
                    f"A login form was found at {login_hit}. This is a "
                    "credential-stuffing / brute-force target; verify it is "
                    "protected by rate limiting, lockout and MFA."
                ),
                reproduction_steps=f"1. Open {login_hit}\n2. Inspect the form",
                impact="Brute force, credential stuffing, account takeover.",
                recommendation="Rate-limit login, enforce lockout, add MFA, monitor failures.",
                module=self.name,
                potential=True,
            ))

        # admin panel exposure
        for path in _ADMIN_PATHS:
            try:
                resp = self.http.get(alive_url + path, timeout=8)
            except Exception:
                resp = None
            if resp and resp.status == 200 and len(resp.body or "") > 200:
                findings.append(Finding(
                    title=f"Admin/management surface on subdomain: {hostname}",
                    severity=Severity.MEDIUM,
                    confidence=70,
                    target=hostname,
                    endpoint=alive_url + path,
                    description=(
                        f"An admin/management page returned 200 at "
                        f"{alive_url + path}. Verify access control."
                    ),
                    impact="Unauthorized administrative access if unprotected.",
                    recommendation="Restrict admin panels by network/VPN + strong auth.",
                    module=self.name,
                    potential=True,
                ))
                break

        # sensitive / api endpoints
        for path in _API_PATHS:
            try:
                resp = self.http.get(alive_url + path, timeout=8)
            except Exception:
                resp = None
            if resp and resp.status in (200, 401, 403):
                if path in ("/.env", "/.git/config"):
                    findings.append(Finding(
                        title=f"Sensitive file reachable on subdomain: {hostname}",
                        severity=Severity.HIGH,
                        confidence=80,
                        target=hostname,
                        endpoint=alive_url + path,
                        description=(
                            f"'{path}' returned HTTP {resp.status} on {hostname}. "
                            "Investigate whether secrets are exposed."
                        ),
                        impact="Secret/credential disclosure.",
                        recommendation="Block access to dotfiles and backup files.",
                        module=self.name,
                        potential=True,
                    ))
                elif "swagger" in path or "api-docs" in path:
                    findings.append(Finding(
                        title=f"API documentation exposed: {hostname}{path}",
                        severity=Severity.LOW,
                        confidence=80,
                        target=hostname,
                        endpoint=alive_url + path,
                        description="API docs (Swagger/OpenAPI) publicly reachable.",
                        impact="Reveals endpoints and data schemas to attackers.",
                        recommendation="Restrict API documentation.",
                        module=self.name,
                    ))
                break  # one hit is enough per subdomain

        # missing security headers on the root
        resp = https_ok or http_ok
        missing = [h for h in _SECURITY_HEADERS
                   if not resp.header(h)]
        if missing:
            findings.append(Finding(
                title=f"Missing security headers on subdomain: {hostname}",
                severity=Severity.LOW,
                confidence=95,
                target=hostname,
                endpoint=alive_url,
                description="Missing: " + ", ".join(missing),
                recommendation="Add the missing security headers.",
                module=self.name,
            ))

        # CNAME takeover fingerprint
        findings.extend(self._check_cname(hostname, alive_url))
        return findings

    def _check_cname(self, hostname: str, alive_url: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            answers = _dns_resolver.resolve(hostname, "CNAME", lifetime=3)
            cnames = [str(r).rstrip(".").lower() for r in answers]
        except Exception:
            return findings
        for cname in cnames:
            for pattern, service, fingerprint in _TAKEOVER_CNAMES:
                if pattern in cname:
                    try:
                        resp = self.http.get(alive_url, timeout=8)
                    except Exception:
                        resp = None
                    if resp and re.search(fingerprint, resp.body or "",
                                          re.IGNORECASE):
                        findings.append(Finding(
                            title=f"Potential subdomain takeover: {service} ({hostname})",
                            severity=Severity.HIGH,
                            confidence=75,
                            target=hostname,
                            endpoint=alive_url,
                            description=(
                                f"'{hostname}' CNAMEs to {cname} ({service}) which "
                                "returns a 'not found' page — the resource may be "
                                "unclaimed and takable."
                            ),
                            impact="Full content control of the subdomain; phishing, cookie theft.",
                            recommendation="Remove dangling DNS records for decommissioned services.",
                            module=self.name,
                            potential=True,
                        ))
        return findings
