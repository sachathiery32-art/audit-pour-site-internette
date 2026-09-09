"""Tests for the siteinfo OSINT module."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import MagicMock, patch

from modules.siteinfo import SiteInfoModule, SiteInfo


class TestSiteInfo(unittest.TestCase):
    def test_to_dict_fields(self):
        info = SiteInfo(domain="example.com", country="France", city="Paris")
        d = info.to_dict()
        self.assertEqual(d["domain"], "example.com")
        self.assertEqual(d["geolocation"]["country"], "France")
        self.assertIn("days_since_created", d)

    def test_scan_returns_findings_and_populates_info(self):
        mock_http = MagicMock()

        # mock the root response (headers/body)
        root_resp = MagicMock()
        root_resp.status = 200
        root_resp.body = "<html><body>Welcome</body></html>"
        root_resp.headers = {"Server": "nginx/1.20"}
        root_resp.url = "https://example.com"
        root_resp.header = lambda n, rv="": {
            "Server": "nginx/1.20", "Set-Cookie": "", "Strict-Transport-Security": "",
        }.get(n, rv)

        mock_http.get.return_value = root_resp

        logger = MagicMock()
        mod = SiteInfoModule(mock_http, logger, "https://example.com")
        findings = mod.scan()

        self.assertIsInstance(findings, list)
        self.assertGreaterEqual(len(findings), 1)
        # should not crash and should record the server header
        self.assertEqual(mod.info.server_header, "nginx/1.20")

    def test_ip_resolution_populates_addresses(self):
        mock_http = MagicMock()
        root_resp = MagicMock()
        root_resp.status = 200
        root_resp.body = "x"
        root_resp.headers = {}
        root_resp.header = lambda n, rv="": rv
        mock_http.get.return_value = root_resp

        logger = MagicMock()
        mod = SiteInfoModule(mock_http, logger, "https://example.com")
        mod._resolve_dns()
        # either DNS or socket fallback populated at least one IP
        self.assertGreaterEqual(len(mod.info.ip_addresses), 1)


if __name__ == "__main__":
    unittest.main()
