"""File upload vulnerability detection module.

Tests for:
- Directory listing on upload paths
- Dangerous file extensions in listings
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from modules.base import BaseModule
from modules.reporting.models import Finding, Severity


class UploadModule(BaseModule):
    """Detect file upload vulnerabilities and misconfigurations."""

    name = "upload"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    UPLOAD_PATHS = [
        "/upload", "/uploads", "/files/upload", "/api/upload",
        "/attachments", "/media/upload", "/documents", "/docs",
    ]
    DANGEROUS_EXTENSIONS = [".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".py", ".rb", ".sh"]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        client = self.http
        timeout = self.config.timeout if self.config and hasattr(self.config, 'timeout') else 10

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.UPLOAD_PATHS:
            url = base + path
            try:
                resp = client.get(url, timeout=timeout)
                if not resp:
                    continue
                status = resp.status_code if hasattr(resp, 'status_code') else 0
                body = resp.body if hasattr(resp, 'body') else (resp.text if hasattr(resp, 'text') else "")

                if status == 200:
                    dir_listing = re.search(r'(Index of|Directory listing|Parent Directory|<pre>)', body, re.IGNORECASE)
                    if dir_listing:
                        findings.append(Finding(
                            title="Directory Listing on Upload Path",
                            severity=Severity.HIGH,
                            confidence=85,
                            target=target,
                            endpoint=url,
                            description=f"Upload directory {path} has directory listing enabled.",
                            module=self.name,
                            remediation="Disable directory listing.",
                            cwe="CWE-548",
                        ))

                    for ext in self.DANGEROUS_EXTENSIONS:
                        if ext in body.lower():
                            findings.append(Finding(
                                title=f"Potentially Dangerous File Type: {ext}",
                                severity=Severity.HIGH,
                                confidence=70,
                                target=target,
                                endpoint=url,
                                description=f"Found reference to '{ext}' files in upload directory.",
                                module=self.name,
                                remediation="Restrict allowed upload extensions.",
                                cwe="CWE-434",
                            ))
                            break
            except Exception:
                continue

        return findings
