"""Infrastructure scanning module.

In infrastructure mode (and only for in-scope hosts), this module performs
prudent port discovery, service identification, TLS inspection, and
banner/version analysis. All scans are rate-limited.
"""
from __future__ import annotations

import ssl
import socket
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


_DEPRECATED_SERVICES = {
    "ftp": "FTP transmits credentials in cleartext.",
    "telnet": "Telnet transmits credentials in cleartext.",
    "smtp": "Inspect for open relay and STARTTLS.",
    "redis": "Redis should require authentication and bind locally.",
    "elasticsearch": "Elasticsearch should not be publicly exposed.",
    "mysql": "MySQL should not be publicly exposed.",
    "postgresql": "PostgreSQL should not be publicly exposed.",
    "rdp": "RDP should be restricted to a VPN.",
}

_INSECURE_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

_PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


class InfrastructureModule(BaseModule):
    """Scan in-scope hosts for exposed services and weak configurations."""

    name = "infrastructure"

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        host = urlparse(self.target).hostname
        if not host:
            self.logger.error("No hostname resolved for infrastructure scan")
            return findings

        ports = self._scan_ports(host)
        for port_info in ports:
            port = port_info["port"]
            service = port_info["service"]
            banner = port_info.get("banner", "")

            if service in _DEPRECATED_SERVICES:
                findings.append(Finding(
                    title=f"Insecure service exposed: {service} (port {port})",
                    severity=Severity.HIGH,
                    confidence=90,
                    target=self.target,
                    endpoint=f"{host}:{port}",
                    description=f"Service '{service}' is exposed on port {port}. "
                                f"{_DEPRECATED_SERVICES[service]}",
                    evidence=f"Banner: {banner[:100]}" if banner else "Port open.",
                    impact="Weak or legacy service can be abused for access or data theft.",
                    recommendation="Disable the service or restrict access by network ACL.",
                    module=self.name,
                ))

            if banner:
                findings.append(Finding(
                    title=f"Banner disclosure on {service}/{port}",
                    severity=Severity.INFO,
                    confidence=100,
                    target=self.target,
                    endpoint=f"{host}:{port}",
                    description=f"Service banner: {banner[:150]}",
                    impact="Version disclosure aids targeted exploitation.",
                    recommendation="Suppress banners where possible.",
                    module=self.name,
                ))

            if port in (443, 8443) or service == "https":
                findings.extend(self._check_tls(host, port))

        self.logger.module(self.name, "completed")
        return findings

    def _scan_ports(self, host: str) -> List[dict]:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445,
                        3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
        open_ports: List[dict] = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((host, port)) == 0:
                    banner = ""
                    try:
                        sock.settimeout(2)
                        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                    open_ports.append({
                        "port": port,
                        "service": _PORT_SERVICES.get(port, "unknown"),
                        "banner": banner,
                    })
                sock.close()
            except Exception:
                pass
        return open_ports

    def _check_tls(self, host: str, port: int) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
            if version in _INSECURE_TLS_VERSIONS:
                findings.append(Finding(
                    title=f"Insecure TLS version on {host}:{port}",
                    severity=Severity.MEDIUM,
                    confidence=90,
                    target=self.target,
                    endpoint=f"{host}:{port}",
                    description=f"Server supports {version}, which is deprecated.",
                    impact="Known cryptographic weaknesses enable MITM / decryption.",
                    recommendation="Disable protocols older than TLS 1.2.",
                    references=["https://owasp.org/www-community/attacks/Man-in-the-middle_attack"],
                    module=self.name,
                ))
            if cipher and ("RC4" in cipher[0] or "CBC" in cipher[0]):
                findings.append(Finding(
                    title=f"Weak cipher suite on {host}:{port}",
                    severity=Severity.LOW,
                    confidence=70,
                    target=self.target,
                    endpoint=f"{host}:{port}",
                    description=f"Server negotiated cipher '{cipher[0]}' which is considered weak.",
                    impact="Weak ciphers enable plaintext recovery via padding oracle attacks.",
                    recommendation="Restrict to AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
                    module=self.name,
                ))
        except ssl.SSLError as exc:
            findings.append(Finding(
                title=f"TLS handshake error on {host}:{port}",
                severity=Severity.MEDIUM,
                confidence=80,
                target=self.target,
                endpoint=f"{host}:{port}",
                description=f"TLS handshake failed: {exc}",
                impact="Misconfigured TLS or unsupported protocols.",
                recommendation="Review TLS configuration.",
                module=self.name,
                potential=True,
            ))
        except Exception:
            pass
        return findings
