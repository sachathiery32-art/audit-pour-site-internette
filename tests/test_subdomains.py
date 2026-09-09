"""Tests for the subdomain enumeration + probing module."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import MagicMock, patch

from modules.subdomains import SubdomainModule
from modules.reporting.models import Finding


def _is_subdomain_of(host, domain):
    return SubdomainModule._is_subdomain_of(host, domain)


class TestSubdomainHelpers(unittest.TestCase):

    def test_is_subdomain_of(self):
        self.assertTrue(_is_subdomain_of("www.example.com", "example.com"))
        self.assertTrue(_is_subdomain_of("example.com", "example.com"))
        self.assertTrue(_is_subdomain_of("a.b.example.com", "example.com"))
        self.assertFalse(_is_subdomain_of("example.com.evil.org", "example.com"))
        self.assertFalse(_is_subdomain_of("notexample.com", "example.com"))
        self.assertTrue(_is_subdomain_of("WWW.EXAMPLE.COM.", "example.com"))


class TestSubdomainModule(unittest.TestCase):

    def _mk(self):
        http = MagicMock()
        logger = MagicMock()
        logger.logger = MagicMock()
        logger.module = MagicMock()
        discovery = MagicMock()
        discovery.subdomains = []
        discovery.subdomain_hosts = []
        mod = SubdomainModule(http, logger, "https://example.com",
                              config=MagicMock(), discovery=discovery)
        return mod, http, logger, discovery

    def test_scan_empty_domain(self):
        mod, http, logger, discovery = self._mk()
        mod.domain = ""
        findings = mod.scan()
        self.assertIsInstance(findings, list)

    @patch("modules.subdomains.SubdomainModule._enumerate",
           return_value=["www.example.com", "mail.example.com"])
    @patch("modules.subdomains.SubdomainModule._probe_host",
           return_value=[Finding(
               title="Alive subdomain: www.example.com",
               severity=MagicMock(), confidence=95, target="www.example.com",
               module="subdomains")])
    def test_scan_enumerates_and_probes(self, mock_probe, mock_enum):
        mod, http, logger, discovery = self._mk()
        findings = mod.scan()
        self.assertTrue(any("Subdomains discovered" in f.title for f in findings))
        self.assertTrue(mock_probe.called)
        self.assertTrue(any("Alive subdomain" in f.title for f in findings))

    def test_probe_host_no_response(self):
        mod, http, logger, discovery = self._mk()
        mod._alive = {}
        http.get.return_value = None
        findings = mod._probe_host("www.example.com")
        self.assertEqual(findings, [])

    def test_probe_host_login_detected(self):
        mod, http, logger, discovery = self._mk()
        mod._alive = {"www.example.com": {"ip": "1.2.3.4"}}

        class Resp:
            status = 200
            body = '<form action="/login" method="POST"><input name="password"></form>'
            headers = {"Server": "nginx"}

            def header(self, name):
                return self.headers.get(name)

        http.get.return_value = Resp()
        findings = mod._probe_host("www.example.com")
        titles = [f.title for f in findings]
        self.assertTrue(any("Alive subdomain" in t for t in titles))
        self.assertTrue(any("Login page exposed" in t for t in titles))

    @patch("modules.subdomains._dns_resolver")
    def test_resolve(self, mock_dns):
        mod, http, logger, discovery = self._mk()
        answer = MagicMock()
        answer.__str__.return_value = "9.9.9.9"
        mock_dns.resolve.return_value = [answer]
        self.assertTrue(mod._resolve("www.example.com"))
        self.assertIn("www.example.com", mod._alive)
        self.assertEqual(mod._alive["www.example.com"]["ip"], "9.9.9.9")


if __name__ == "__main__":
    unittest.main()
