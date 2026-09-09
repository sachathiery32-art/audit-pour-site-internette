"""Tests for the post-scan interactive action menu."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import MagicMock, patch

from modules.menu import PostScanMenu, TARGETED_TESTS
from modules.reporting.models import Finding, Severity


def _mk_scanner():
    scanner = MagicMock()
    scanner.cfg.target_url = "https://example.com"
    scanner.cfg.output_dir = "reports"
    scanner.cfg.timeout = 5
    scanner.cfg.interactive_menu = True
    scanner.logger = MagicMock()
    scanner.discovery = None
    scanner.graph = MagicMock()
    scanner.graph.ascii_tree.return_value = "example.com [domain]"
    scanner.http = MagicMock()
    return scanner


class TestPostScanMenu(unittest.TestCase):

    def setUp(self):
        self.scanner = _mk_scanner()
        self.menu = PostScanMenu(self.scanner)

    def test_targeted_tests_defined(self):
        # 16 vulnerability classes must be available
        self.assertEqual(len(TARGETED_TESTS), 16)
        labels = [label for label, _ in TARGETED_TESTS.values()]
        self.assertTrue(any("XSS" in l for l in labels))
        self.assertTrue(any("SQL" in l for l in labels))
        self.assertTrue(any("SSTI" in l for l in labels))
        self.assertTrue(any("SSRF" in l for l in labels))
        self.assertTrue(any("JWT" in l for l in labels))
        self.assertTrue(any("CORS" in l for l in labels))

    def test_findings_details(self):
        f = Finding(title="Reflected XSS", severity=Severity.HIGH,
                    confidence=90, target="x",
                    endpoint="https://example.com/search", parameter="q",
                    description="XSS detected", evidence="marker",
                    recommendation="Escape output")
        self.scanner.findings = [f]
        with patch("builtins.input", side_effect=[""]):
            self.menu._findings_details()  # should not raise

    def test_attack_graph(self):
        with patch("builtins.input", side_effect=[""]):
            self.menu._attack_graph()  # should not raise

    def test_quit_dispatch(self):
        self.menu._dispatch("15")
        self.assertFalse(self.menu.running)
        # 'q' also quits
        self.menu.running = True
        self.menu._dispatch("q")
        self.assertFalse(self.menu.running)

    def test_surface_osint(self):
        f = Finding(title="X", severity=Severity.LOW, confidence=50,
                    target="x", module="m")
        self.scanner.findings = [f]
        self.scanner.discovery = MagicMock()
        self.scanner.discovery.pages = ["https://example.com/a"]
        self.scanner.discovery.api_endpoints = []
        self.scanner.discovery.url_params = ["q"]
        self.scanner.discovery.subdomains = []
        self.scanner.discovery.subdomain_hosts = []
        self.scanner.siteinfo = MagicMock()
        self.scanner.siteinfo.ip_addresses = ["1.2.3.4"]
        self.scanner.siteinfo.emails = ["admin@example.com"]
        self.scanner.siteinfo.mailto_emails = []
        self.scanner.siteinfo.security_contact = ""
        self.scanner.siteinfo.dns_records = {}
        self.scanner.siteinfo.reverse_dns = ""
        self.scanner.siteinfo.city = self.scanner.siteinfo.region = ""
        self.scanner.siteinfo.country = "FR"
        self.scanner.siteinfo.isp = "Some ISP"
        self.scanner.siteinfo.organization = ""
        self.scanner.siteinfo.asn = ""
        self.scanner.siteinfo.registrar = ""
        self.scanner.siteinfo.created = ""
        self.scanner.siteinfo.days_since_created = None
        self.scanner.siteinfo.expires = ""
        self.scanner.siteinfo.nameservers = []
        self.scanner.siteinfo.protections = []
        with patch("builtins.input", side_effect=[""]):
            self.menu._surface_osint()  # should not raise

    def test_dispatch_unknown(self):
        self.menu._dispatch("99")  # should not raise
        self.assertTrue(self.menu.running)

    def test_prompt_url_adds_scheme(self):
        with patch("builtins.input", return_value="example.org"):
            self.assertEqual(self.menu._prompt_url(), "https://example.org")
        with patch("builtins.input", return_value="http://example.org"):
            self.assertEqual(self.menu._prompt_url(), "http://example.org")


if __name__ == "__main__":
    unittest.main()
