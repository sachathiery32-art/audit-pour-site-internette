"""Tests for the non-destructive DDoS protection assessment module."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import MagicMock

from modules.ddos import DdosProtectionModule, _PROTECTIONS
from modules.http_client import HttpResponse
from modules.reporting.models import Severity


def _resp(status=200, headers=None, body=""):
    return HttpResponse(
        url="https://example.com/", status=status,
        headers=headers or {}, body=body, elapsed=0.1,
        redirected=False, final_url="https://example.com/",
    )


def _make_module(first_response, default=_resp()):
    """Module whose client returns `first_response` once, then `default`."""
    client = MagicMock()
    calls = {"n": 0}

    def get(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return first_response
        return default

    client.get.side_effect = get
    mod = DdosProtectionModule(client, MagicMock(), "https://example.com", None)
    return mod


class TestDdosProtection(unittest.TestCase):

    def test_no_cdn_detected_is_high(self):
        mod = _make_module(_resp(headers={"Server": "nginx"}))
        findings = mod.scan()
        titles = [f.title for f in findings]
        self.assertIn("No CDN/WAF Protection Detected", titles)
        f = next(x for x in findings if x.title == "No CDN/WAF Protection Detected")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_cloudflare_detected(self):
        mod = _make_module(_resp(headers={"cf-ray": "abc123"}))
        findings = mod.scan()
        titles = [f.title for f in findings]
        self.assertTrue(any("Cloudflare" in t for t in titles))

    def test_rate_limiting_detected(self):
        # The initial GET in scan() consumes the first response, so the
        # burst must also see 429s -> make every response 429.
        client = MagicMock()
        client.get.side_effect = lambda *a, **k: _resp(status=429)
        mod = DdosProtectionModule(client, MagicMock(), "https://example.com", None)
        findings = mod.scan()
        self.assertTrue(any("Rate Limiting Present" in f.title for f in findings))

    def test_no_rate_limiting(self):
        mod = _make_module(_resp(status=200))
        findings = mod.scan()
        self.assertTrue(any("No Rate Limiting" in f.title for f in findings))

    def test_protection_signatures_defined(self):
        for name, headers, cookies, markers in _PROTECTIONS:
            self.assertTrue(name)
            self.assertTrue(headers or cookies or markers, name)

    def test_sensitive_endpoints_finding(self):
        client = MagicMock()
        client.get.side_effect = lambda *a, **k: _resp(status=200)
        mod = DdosProtectionModule(client, MagicMock(), "https://example.com", None)
        findings = mod.scan()
        self.assertTrue(any("Sensitive Endpoints" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()
