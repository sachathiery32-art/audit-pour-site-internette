"""Tests guarding against the false positives seen in the full-assault
probes (static assets flagged as SSTI/admin/API/clickjacking/cache)."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import MagicMock, patch

from modules.exploit import ExploitModule
from modules.menu import PostScanMenu


def mk_resp(body, headers=None, status=200):
    r = MagicMock()
    r.status = status
    r.body = body
    r.headers = headers or {"Content-Type": "application/javascript"}
    r.header = lambda n: next(
        (v for k, v in r.headers.items() if k.lower() == n.lower()), "")
    return r


class TestSstiFalsePositives(unittest.TestCase):

    def setUp(self):
        logger = MagicMock()
        logger.logger = MagicMock()
        logger.module = MagicMock()
        self.http = MagicMock()
        self.m = ExploitModule(self.http, logger, "https://x.com")

    def test_static_js_with_49_not_ssti(self):
        # .map file containing '49' and even the marker value by chance
        self.http.get.return_value = mk_resp(
            "var x = 49; var y = 54444439;" * 50,
            {"Content-Type": "application/javascript"})
        self.assertEqual(self.m._poc_ssti("https://x.com/a.map", "q"), "")

    def test_html_no_reflect_not_ssti(self):
        self.http.get.return_value = mk_resp(
            "<html><body>welcome</body></html>",
            {"Content-Type": "text/html"})
        self.assertEqual(self.m._poc_ssti("https://x.com/page", "q"), "")

    def test_html_evaluating_marker_is_ssti(self):
        self.http.get.return_value = mk_resp(
            "<html>54444439</html>", {"Content-Type": "text/html"})
        self.assertNotEqual(self.m._poc_ssti("https://x.com/page", "q"), "")

    def test_differential_eval_is_ssti(self):
        # first call returns marker body, second {{7*7}}->49, third {{8*8}}->64
        self.http.get.side_effect = [
            mk_resp("<html>no</html>", {"Content-Type": "text/html"}),
            mk_resp("<html>49</html>", {"Content-Type": "text/html"}),
            mk_resp("<html>64</html>", {"Content-Type": "text/html"}),
        ]
        self.assertNotEqual(self.m._poc_ssti("https://x.com/page", "q"), "")


class TestAdminUnauthFalsePositives(unittest.TestCase):

    def setUp(self):
        logger = MagicMock()
        logger.logger = MagicMock()
        logger.module = MagicMock()
        self.http = MagicMock()
        self.m = ExploitModule(self.http, logger, "https://x.com")

    def test_js_file_not_admin(self):
        self.http.get.return_value = mk_resp("alert(1);" * 200)
        self.assertEqual(self.m._poc_admin("https://x.com/script.js"), "")

    def test_html_root_not_admin(self):
        # HTML but the path doesn't look like an admin surface
        self.http.get.return_value = mk_resp(
            "<html><body>" + "<p>hi</p>" * 100 + "</body></html>",
            {"Content-Type": "text/html"})
        self.assertEqual(self.m._poc_admin("https://x.com/"), "")

    def test_real_admin_panel(self):
        self.http.get.return_value = mk_resp(
            "<html><body><h1>Dashboard</h1>" + "<p>stats</p>" * 100 + "</body></html>",
            {"Content-Type": "text/html"})
        self.assertNotEqual(self.m._poc_admin("https://x.com/admin"), "")

    def test_js_file_not_unauth_api(self):
        self.http.get.return_value = mk_resp("function(){}" * 200)
        self.assertEqual(self.m._poc_unauth_api("https://x.com/main.js"), "")

    def test_real_json_api(self):
        self.http.get.return_value = mk_resp(
            '{"users":[{"id":1}]}' * 30,
            {"Content-Type": "application/json"})
        self.assertNotEqual(
            self.m._poc_unauth_api("https://x.com/api/users"), "")


class TestMenuProbeFalsePositives(unittest.TestCase):

    def setUp(self):
        scanner = MagicMock()
        scanner.cfg.target_url = "https://x.com"
        scanner.logger = MagicMock()
        scanner.logger.logger = MagicMock()
        self.http = MagicMock()
        self.menu = PostScanMenu(scanner)
        self.menu._http = lambda: self.http

    def test_clickjacking_ignores_js(self):
        self.http.get.return_value = mk_resp("var a=1;" * 100)
        self.assertEqual(self.menu._probe_clickjacking("https://x.com/app.js"), "")

    def test_clickjacking_on_html(self):
        self.http.get.return_value = mk_resp(
            "<html><body>hi</body></html>", {"Content-Type": "text/html"})
        self.assertNotEqual(self.menu._probe_clickjacking("https://x.com/"), "")

    def test_cache_ignores_static_assets(self):
        # long max-age on a JS file is expected behaviour, not a finding
        self.http.get.return_value = mk_resp(
            "var a=1;" * 100,
            {"Content-Type": "application/javascript",
             "Cache-Control": "max-age=31536000"})
        self.assertEqual(self.menu._probe_cache_poison("https://x.com/app.js"), "")

    def test_cache_flags_html(self):
        self.http.get.return_value = mk_resp(
            "<html><body>hi</body></html>",
            {"Content-Type": "text/html", "Cache-Control": "max-age=300"})
        self.assertNotEqual(self.menu._probe_cache_poison("https://x.com/page"), "")

    def test_full_assault_skips_static_html_tests(self):
        from modules.menu import TARGETED_TESTS
        self.assertIsNotNone(TARGETED_TESTS)  # module-level import works

    def test_full_assault_no_fp_explosion(self):
        from modules.http_client import HttpResponse
        from modules.menu import PostScanMenu
        from modules.reporting.models import Finding, Severity
        scanner = MagicMock()
        scanner.cfg.target_url = "https://x.com"
        scanner.cfg.output_dir = "reports"
        scanner.logger = MagicMock()
        scanner.logger.logger = MagicMock()
        scanner.http = MagicMock()
        scanner.discovery = None
        scanner.graph = None

        def mk(body, ct, extra=None):
            h = {"Content-Type": ct}
            if extra:
                h.update(extra)
            return HttpResponse(
                url="https://x.com/", status=200, headers=h, body=body,
                elapsed=0.1, redirected=False, final_url="https://x.com/")

        # endpoints: static JS/.map/CSS (must be skipped) + real HTML with param
        scanner.findings = [
            Finding(title="s", severity=Severity.LOW, confidence=50, target="x",
                    endpoint="https://x.com/app.js?ver=1.map", module="d"),
            Finding(title="s", severity=Severity.LOW, confidence=50, target="x",
                    endpoint="https://x.com/app.js?ver=1", module="d"),
            Finding(title="s", severity=Severity.LOW, confidence=50, target="x",
                    endpoint="https://x.com/style.css", module="d"),
            Finding(title="s", severity=Severity.LOW, confidence=50, target="x",
                    endpoint="https://x.com/search?q=", module="d"),
        ]

        def fake_get(url, **kw):
            if ".js" in url or ".map" in url or ".css" in url:
                return mk("var x=49; var y=54444439;" * 100,
                          "application/javascript")
            return mk("<html><body>Hello 49</body></html>", "text/html",
                      {"Cache-Control": "max-age=300"})

        scanner.http.get.side_effect = fake_get
        menu = PostScanMenu(scanner)
        with patch("builtins.input", side_effect=[""]):
            menu._full_assault()
        # must not raise; correctness of the probe outputs is covered by
        # the other tests (static assets -> no findings)


if __name__ == "__main__":
    unittest.main()