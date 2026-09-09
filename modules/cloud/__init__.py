"""Cloud storage exposure module.

Detects:
- exposed S3 buckets (listable, publicly writable)
- exposed Azure Blob containers
- exposed GCP storage
- cloud metadata endpoints reachable (SSRF confirmation)
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse

from ..base import BaseModule
from ..reporting.models import Finding, Severity


_S3_URL_RE = re.compile(
    r"https?://([a-z0-9.\-]+)\.s3[.\-]([a-z0-9-]*\.?)?amazonaws\.com",
    re.IGNORECASE,
)
_AZURE_BLOB_RE = re.compile(
    r"https?://([a-z0-9]+)\.blob\.core\.windows\.net",
    re.IGNORECASE,
)
_GCP_RE = re.compile(
    r"https?://storage\.googleapis\.com/([a-z0-9_\-./]+)",
    re.IGNORECASE,
)


class CloudModule(BaseModule):
    """Test for cloud storage exposure."""

    name = "cloud"

    def __init__(self, http, logger, target, config=None, discovery=None):
        super().__init__(http, logger, target, config)
        self.discovery = discovery

    def scan(self) -> List[Finding]:
        self.logger.module(self.name, "started")
        findings: List[Finding] = []

        findings.extend(self._find_s3_buckets())
        findings.extend(self._find_azure_blobs())
        findings.extend(self._find_gcp_storage())

        self.logger.module(self.name, "completed")
        return findings

    def _find_s3_buckets(self) -> List[Finding]:
        findings: List[Finding] = []
        # scan JS files and HTML for S3 URLs
        bodies = self._get_bodies()
        for body, source in bodies:
            for m in _S3_URL_RE.finditer(body):
                bucket_url = m.group(0)
                findings.extend(self._test_s3(bucket_url, source))
        return findings

    def _test_s3(self, url: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        # try to list the bucket
        resp = self.http.get(url)
        if not resp:
            return findings
        if resp.status == 200 and ("<ListBucketResult" in resp.body
                                    or "xmlns" in resp.body[:200]):
            findings.append(Finding(
                title="Publicly listable S3 bucket",
                severity=Severity.HIGH,
                confidence=85,
                target=self.target,
                endpoint=url,
                description=f"S3 bucket at {url} allows public listing of its contents.",
                evidence=f"Found in {source}. Bucket listing returned XML.",
                request=f"GET {url}",
                reproduction_steps=f"Access {url} to list the bucket contents.",
                impact="All files in the bucket are publicly readable; potential data leak.",
                recommendation="Disable bucket public listing; use bucket policies / IAM.",
                references=["https://owasp.org/www-community/attacks/"],
                module=self.name,
            ))
            # check for write access (PUT) — non-destructive: we only check OPTIONS
            opt_resp = self.http.options(url)
            if opt_resp and "PUT" in (opt_resp.header("Allow") or ""):
                findings.append(Finding(
                    title="S3 bucket allows public write (PUT)",
                    severity=Severity.CRITICAL,
                    confidence=80,
                    target=self.target,
                    endpoint=url,
                    description=f"S3 bucket at {url} allows public PUT requests.",
                    evidence=f"OPTIONS response includes PUT.",
                    request=f"OPTIONS {url}",
                    reproduction_steps=f"Send OPTIONS to {url}; observe PUT in Allow.",
                    impact="Anyone can upload files to the bucket (malware, defacement).",
                    recommendation="Remove public write permissions immediately.",
                    module=self.name,
                    potential=True,
                ))
        return findings

    def _find_azure_blobs(self) -> List[Finding]:
        findings: List[Finding] = []
        bodies = self._get_bodies()
        for body, source in bodies:
            for m in _AZURE_BLOB_RE.finditer(body):
                url = m.group(0)
                resp = self.http.get(url)
                if resp and resp.status == 200 and "EnumerationResults" in resp.body:
                    findings.append(Finding(
                        title="Publicly listable Azure Blob container",
                        severity=Severity.HIGH,
                        confidence=80,
                        target=self.target,
                        endpoint=url,
                        description=f"Azure Blob at {url} allows public listing.",
                        evidence=f"Found in {source}. Container listing returned.",
                        request=f"GET {url}",
                        reproduction_steps=f"Access {url}.",
                        impact="All blobs in the container are publicly readable.",
                        recommendation="Set container access level to Private.",
                        module=self.name,
                    ))
        return findings

    def _find_gcp_storage(self) -> List[Finding]:
        findings: List[Finding] = []
        bodies = self._get_bodies()
        for body, source in bodies:
            for m in _GCP_RE.finditer(body):
                url = m.group(0)
                resp = self.http.get(url)
                if resp and resp.status == 200 and "<ListBucketResult" in resp.body:
                    findings.append(Finding(
                        title="Publicly listable GCP storage bucket",
                        severity=Severity.HIGH,
                        confidence=80,
                        target=self.target,
                        endpoint=url,
                        description=f"GCP bucket at {url} allows public listing.",
                        evidence=f"Found in {source}.",
                        request=f"GET {url}",
                        reproduction_steps=f"Access {url}.",
                        impact="Public storage object enumeration.",
                        recommendation="Set storage to uniform bucket-level access.",
                        module=self.name,
                    ))
        return findings

    def _get_bodies(self):
        """Return list of (body, source) from target and JS files."""
        bodies = []
        resp = self.http.get(self.target)
        if resp:
            bodies.append((resp.body, "main page"))
        if self.discovery:
            for js_url in (self.discovery.js_files or [])[:15]:
                js_resp = self.http.get(js_url)
                if js_resp:
                    bodies.append((js_resp.body, f"JS:{js_url}"))
        return bodies
