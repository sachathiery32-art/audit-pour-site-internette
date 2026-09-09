"""Discovery module package.

Discovers the attack surface for the authorized scope:
- DNS resolution
- HTTP info / redirects / technologies
- robots.txt, sitemap.xml
- public JS files, forms, cookies, URL parameters
- API endpoints visible in JS
- subdomains (only if explicitly listed in allowed_hosts)
- ports/services (only in infrastructure mode, only for in-scope hosts)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity

try:
    import dns.resolver as _dns_resolver
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False


@dataclass
class DiscoveryResult:
    """Aggregate result of the discovery phase."""
    base_url: str = ""
    hostname: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    final_url: str = ""
    redirects: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    pages: List[str] = field(default_factory=list)
    robots_entries: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    cookies: List[Dict] = field(default_factory=list)
    url_params: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    subdomains: List[Dict] = field(default_factory=list)
    subdomain_hosts: List[Dict] = field(default_factory=list)
    server_header: str = ""
    powered_by: str = ""


_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_RE = re.compile(
    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\'](?:[^>]*value=["\']([^"\']*)["\'])?',
    re.IGNORECASE,
)
_API_PATTERNS = [
    re.compile(r'["\']/(api/[a-zA-Z0-9_/\-{}\.]+)["\']'),
    re.compile(r'fetch\(["\`]([^"\`]+)["\`]'),
    re.compile(r'axios\.(?:get|post|put|delete|patch)\(["\`]([^"\`]+)["\`]'),
]
_TECH_SIGNATURES = {
    "jQuery": re.compile(r'jquery', re.IGNORECASE),
    "React": re.compile(r'react|_next', re.IGNORECASE),
    "Vue.js": re.compile(r'vue|__nuxt', re.IGNORECASE),
    "Angular": re.compile(r'angular|ng-', re.IGNORECASE),
    "WordPress": re.compile(r'wp-content|wp-includes', re.IGNORECASE),
    "Drupal": re.compile(r'drupal\.js|sites/all', re.IGNORECASE),
    "Bootstrap": re.compile(r'bootstrap', re.IGNORECASE),
    "PHP": re.compile(r'X-Powered-By:\s*PHP', re.IGNORECASE),
    "ASP.NET": re.compile(r'X-Powered-By:\s*ASP\.NET|__VIEWSTATE', re.IGNORECASE),
    "Express": re.compile(r'X-Powered-By:\s*Express', re.IGNORECASE),
    "Nextcloud": re.compile(r'nc_requesttoken|nextcloud', re.IGNORECASE),
}

_PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch",
}


class DiscoveryModule(BaseModule):
    """Discover the attack surface within the authorized scope."""

    name = "discovery"

    def __init__(self, http, logger, target, config=None,
                 infrastructure_mode: bool = False):
        super().__init__(http, logger, target, config)
        self.result = DiscoveryResult(base_url=target.rstrip("/"))
        self.infrastructure_mode = infrastructure_mode
        self.parsed = urlparse(target)
        self.result.hostname = self.parsed.hostname or ""

    def scan(self) -> List[Finding]:
        """Run discovery. Returns findings (usually empty — this is recon)."""
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        self._resolve_dns()
        self._fetch_root()
        self._fetch_robots()
        self._fetch_sitemap()
        self._discover_links_and_forms()
        self._discover_js_and_api()
        self._collect_cookies()
        if self.infrastructure_mode:
            self._port_scan()

        self.logger.module(self.name, "completed")
        return findings

    def _resolve_dns(self) -> None:
        if not _HAS_DNS or not self.result.hostname:
            return
        try:
            answers = _dns_resolver.resolve(self.result.hostname, "A")
            self.result.ip_addresses = [str(r) for r in answers]
        except Exception:
            pass

    def _fetch_root(self) -> None:
        resp = self.http.get(self.target)
        if not resp:
            return
        self.result.final_url = resp.final_url
        if resp.redirected:
            self.result.redirects.append(resp.final_url)
        self.result.server_header = resp.header("Server")
        self.result.powered_by = resp.header("X-Powered-By")

        body_lower = resp.body.lower()
        for tech, pattern in _TECH_SIGNATURES.items():
            if pattern.search(body_lower) or pattern.search(
                f"server:{resp.header('server')}".lower()
            ):
                if tech not in self.result.technologies:
                    self.result.technologies.append(tech)

        self._extract_params(resp.body)

    def _fetch_robots(self) -> None:
        url = urljoin(self.target, "/robots.txt")
        resp = self.http.get(url)
        if resp and resp.status == 200:
            for line in resp.body.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    self.result.robots_entries.append(line)
                    if line.lower().startswith("sitemap:"):
                        sitemap = line.split(":", 1)[1].strip()
                        if sitemap:
                            self.result.sitemap_urls.append(sitemap)

    def _fetch_sitemap(self) -> None:
        for sitemap in list(self.result.sitemap_urls):
            self._parse_sitemap(sitemap)
        default = urljoin(self.target, "/sitemap.xml")
        if default not in self.result.sitemap_urls:
            self._parse_sitemap(default)

    def _parse_sitemap(self, url: str) -> None:
        resp = self.http.get(url)
        if not resp or resp.status != 200:
            return
        urls = re.findall(r"<loc>([^<]+)</loc>", resp.body)
        for found_url in urls:
            if found_url not in self.result.sitemap_urls:
                self.result.sitemap_urls.append(found_url)

    def _discover_links_and_forms(self) -> None:
        resp = self.http.get(self.target)
        if not resp:
            return
        self._extract_links(resp.body)
        self._extract_forms(resp.body)

    def _extract_links(self, body: str) -> None:
        for match in _LINK_RE.finditer(body):
            href = match.group(1)
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(self.target, href)
            if self._in_scope(absolute) and absolute not in self.result.pages:
                self.result.pages.append(absolute)

    def _extract_forms(self, body: str) -> None:
        for match in _FORM_RE.finditer(body):
            action = urljoin(self.target, match.group(1))
            method = (match.group(2) or "GET").upper()
            if not self._in_scope(action):
                continue
            form = {"action": action, "method": method, "fields": []}
            start = match.start()
            chunk = body[start:start + 2000]
            for field_match in _INPUT_RE.finditer(chunk):
                form["fields"].append({
                    "name": field_match.group(1),
                    "value": field_match.group(2) or "",
                })
            self.result.forms.append(form)

    def _extract_params(self, body: str) -> None:
        if self.parsed.query:
            for param in self.parsed.query.split("&"):
                key = param.split("=")[0]
                if key and key not in self.result.url_params:
                    self.result.url_params.append(key)

    def _discover_js_and_api(self) -> None:
        resp = self.http.get(self.target)
        if not resp:
            return
        for match in _SCRIPT_SRC_RE.finditer(resp.body):
            src = urljoin(self.target, match.group(1))
            if src not in self.result.js_files:
                self.result.js_files.append(src)

        for js_url in list(self.result.js_files[:30]):
            js_resp = self.http.get(js_url)
            if not js_resp:
                continue
            for pattern in _API_PATTERNS:
                for m in pattern.finditer(js_resp.body):
                    endpoint = m.group(1)
                    if endpoint.startswith("http"):
                        if self._in_scope(endpoint) and endpoint not in self.result.api_endpoints:
                            self.result.api_endpoints.append(endpoint)
                    else:
                        absolute = urljoin(self.target, endpoint)
                        if self._in_scope(absolute) and absolute not in self.result.api_endpoints:
                            self.result.api_endpoints.append(absolute)

    def _collect_cookies(self) -> None:
        resp = self.http.get(self.target)
        if not resp:
            return
        cookie_header = resp.header("Set-Cookie")
        if not cookie_header:
            return
        for part in cookie_header.split(","):
            if "=" in part:
                name, value = part.split("=", 1)
                self.result.cookies.append({
                    "name": name.strip(),
                    "value": value.strip(),
                    "secure": "secure" in cookie_header.lower(),
                    "httponly": "httponly" in cookie_header.lower(),
                    "samesite": "samesite" in cookie_header.lower(),
                })

    def _in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        if host == self.result.hostname:
            return True
        if host in (self.config.allowed_hosts if self.config else []):
            return True
        return False

    def _port_scan(self) -> None:
        """Lightweight, polite port check — in-scope hosts only."""
        import socket
        if not self.result.ip_addresses and not self.result.hostname:
            return
        host = self.result.hostname
        common_ports = [21, 22, 25, 80, 443, 3306, 3389, 5432, 6379, 8080, 8443, 9200]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = ""
                    try:
                        sock.settimeout(2)
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                    self.result.open_ports.append({
                        "port": port, "service": _PORT_SERVICES.get(port, "unknown"),
                        "banner": banner,
                    })
                sock.close()
            except Exception:
                pass
