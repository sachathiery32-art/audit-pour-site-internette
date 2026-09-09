"""Post-scan interactive action menu.

After a scan finishes, the user gets a menu of follow-up attack actions
they can launch from the CLI:

Attack options:
1. Targeted re-test (pick an endpoint + vulnerability class to probe)
2. Controlled exploitation pass (safe PoCs on HIGH/CRITICAL findings)
3. DDoS protection assessment (non-destructive)
4. Controlled credential test (opt-in brute force, capped & rate-limited)
5. Full assault (every safe probe against every discovered endpoint)
6. SSRF canary check (needs a canary URL you control)
7. JWT analysis (read-only)
8. CORS exploit check
9. Clickjacking PoC check

Analysis options:
10. Detailed findings viewer
11. Attack graph viewer
12. Generated reports
13. New scan
14. Quit

Every action stays within the tool's safety policy: no destructive
payloads, no real data modification, brute force is opt-in and capped.
"""
from __future__ import annotations

import os
import sys
import time
from typing import List, Optional
from urllib.parse import urlparse

from modules.ui import (
    info, warn, error, finding as print_finding, prompt, prompt_options,
    _safe_print, _wrap, progress_bar,
)
from modules.reporting.models import Finding, Severity


# Vulnerability classes available for targeted re-tests
TARGETED_TESTS = {
    "1": ("Reflected XSS", "xss"),
    "2": ("SQL Injection", "sqli"),
    "3": ("Template Injection (SSTI)", "ssti"),
    "4": ("Command Injection", "cmdi"),
    "5": ("NoSQL Injection", "nosqli"),
    "6": ("Path Traversal / LFI", "traversal"),
    "7": ("Open Redirect", "redirect"),
    "8": ("Directory Listing", "dirlisting"),
    "9": ("Exposed Sensitive File (.env/.git/backup)", "exposed_file"),
    "10": ("Unauthenticated Admin/API Access", "unauth"),
    "11": ("SSRF Canary Check", "ssrf"),
    "12": ("JWT Analysis", "jwt"),
    "13": ("CORS Misconfiguration", "cors"),
    "14": ("Clickjacking PoC", "clickjacking"),
    "15": ("Host Header Poisoning", "host_header"),
    "16": ("Cache Poisoning Indicators", "cache"),
}

# ASCII art headers shown before each attack action
_ASCII_ART = {
    "target": r"""
      ▄▄▄▄▄▄▄▄▄▄▄
     █           █
     █   ▄   ▄   █
     █   ▀▄▄▄▀   █   TARGET LOCKED
     █     █     █
     █     █     █
     ▀▀▀▀▀▀▀▀▀▀▀""",
    "sword": r"""
        /\
       /  \\
      /    \\
     /  /
     \  \\
      \  \\
       \  \\   EXPLOIT PASS
        \  \\
         \  \\
          \  \\
           \  \\
            \  \\
             \  \\
              \  \\
               \__\\""",
    "shield": """
      ██████████
     ████████████
    ███  ████  ███   DDoS RESILIENCE
    ███  ████  ███   (non-destructive)
    ███  ████  ███
     ████████████
      ██████████""",
    "keys": """
      ╔══════╗
      ║ KEYS ║   CREDENTIAL TEST
      ╚═╤══╤═╝   (capped, opt-in)
        │  │
       ╱    ╲""",
    "eye": """
        ████
      ████████
     ██      ██
     ██  ██  ██   RECON / DISCOVERY
     ██      ██
      ████████
        ████""",
    "skull": """
        ▓▓▓▓
      ▓▓▓▓▓▓▓▓
     ▓▓  ▓▓  ▓▓   FULL ASSAULT
     ▓▓  ▓▓  ▓▓   (safe probes, all vectors)
      ▓▓▓▓▓▓▓▓
        ▓▓▓▓
       ▓▓▓▓▓▓""",
}


class PostScanMenu:
    """Interactive menu offering follow-up attack actions after a scan."""

    def __init__(self, scanner):
        self.scanner = scanner
        self.running = True

    # ------------------------------------------------------------ helpers
    def _scan_title(self) -> str:
        return self.scanner.cfg.target_url

    def _findings(self) -> List[Finding]:
        return self.scanner.findings

    def _http(self):
        return self.scanner.http

    # ------------------------------------------------------------- render
    def render(self) -> None:
        """Render the menu and handle the user's choice."""
        while self.running:
            self._draw_menu()
            choice = input(_wrap("Action: ", "bold")).strip()
            try:
                self._dispatch(choice)
            except KeyboardInterrupt:
                warn("\nBack to menu.")
            except Exception as exc:
                error(f"Action failed: {exc}")

    def _draw_menu(self) -> None:
        target = self._scan_title()
        findings = self._findings()
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)

        _safe_print("")
        _safe_print(_wrap("=" * 62, "cyan"))
        _safe_print(_wrap("        POST-SCAN ACTION MENU", "bright_cyan"))
        _safe_print(_wrap("=" * 62, "cyan"))
        _safe_print(_wrap(f"  Target : {target}", "gray"))
        _safe_print(_wrap(f"  Findings: {len(findings)} total"
                          f"   [CRIT {crit} | HIGH {high} | MED {med}]", "gray"))
        _safe_print(_wrap("-" * 62, "gray"))
        _safe_print(_wrap("  ┌─ ATTACK OPTIONS ────────────────────────────┐", "bright_cyan"))
        _safe_print(_wrap("  │ [1]  Targeted re-test      probe an endpoint │", "bold"))
        _safe_print(_wrap("  │      (XSS/SQLi/SSTI/CMDi/NoSQLi/traversal…)", "gray"))
        _safe_print(_wrap("  │ [2]  Exploit pass          safe PoCs         │", "bold"))
        _safe_print(_wrap("  │ [3]  DDoS assessment       resilience check  │", "bold"))
        _safe_print(_wrap("  │ [4]  Credential test       capped, opt-in    │", "bold"))
        _safe_print(_wrap("  │ [5]  Full assault          all vectors, all  │", "bold"))
        _safe_print(_wrap("  │      endpoints (safe probes)                 │", "gray"))
        _safe_print(_wrap("  │ [6]  SSRF canary           URL-fetch check   │", "bold"))
        _safe_print(_wrap("  │ [7]  JWT analysis          token hardening    │", "bold"))
        _safe_print(_wrap("  │ [8]  CORS exploit check    origin reflection │", "bold"))
        _safe_print(_wrap("  │ [9]  Clickjacking PoC      frame test        │", "bold"))
        _safe_print(_wrap("  └──────────────────────────────────────────────┘", "bright_cyan"))
        _safe_print(_wrap("  ┌─ ANALYSIS / OSINT ───────────────────────────┐", "bright_cyan"))
        _safe_print(_wrap("  │ [10] Surface + OSINT   pages, subdomains,    │", "bold"))
        _safe_print(_wrap("  │      emails, DNS records                     │", "gray"))
        _safe_print(_wrap("  │ [11] Findings details    evidence & fixes    │", "bold"))
        _safe_print(_wrap("  │ [12] Attack graph        visualization      │", "bold"))
        _safe_print(_wrap("  │ [13] Reports             open reports        │", "bold"))
        _safe_print(_wrap("  └──────────────────────────────────────────────┘", "bright_cyan"))
        _safe_print(_wrap("  [14] New scan             restart new target", "bold"))
        _safe_print(_wrap("  [15] Quit", "bold"))
        _safe_print(_wrap("-" * 62, "gray"))
        _safe_print(_wrap("  Enter a number, or 'q' to quit.", "gray"))
        _safe_print("")

    def _dispatch(self, choice: str) -> None:
        if choice in ("q", "Q", "quit", "exit", "15"):
            info("Goodbye.")
            self.running = False
        elif choice == "1":
            self._targeted_test()
        elif choice == "2":
            self._exploit_pass()
        elif choice == "3":
            self._ddos_assessment()
        elif choice == "4":
            self._credential_test()
        elif choice == "5":
            self._full_assault()
        elif choice == "6":
            self._ssrf_test()
        elif choice == "7":
            self._jwt_analysis()
        elif choice == "8":
            self._cors_check()
        elif choice == "9":
            self._clickjacking_check()
        elif choice == "10":
            self._surface_osint()
        elif choice == "11":
            self._findings_details()
        elif choice == "12":
            self._attack_graph()
        elif choice == "13":
            self._reports()
        elif choice == "14":
            self._new_scan()
        else:
            error("Invalid choice.")

    # ------------------------------------------------------ action handlers
    def _targeted_test(self) -> None:
        """Pick an endpoint and a vulnerability class, run a safe probe."""
        findings = self._findings()
        endpoints = []
        for f in findings:
            if f.endpoint and f.endpoint not in endpoints:
                endpoints.append(f.endpoint)
        if not endpoints:
            # fall back to the base URL
            parsed = urlparse(self._scan_title())
            endpoints = [f"{parsed.scheme}://{parsed.netloc}/"]

        _safe_print(_wrap("\n  Select endpoint:", "bold"))
        for i, ep in enumerate(endpoints[:15], 1):
            _safe_print(f"    [{i}] {ep}")
        _safe_print(f"    [{len(endpoints[:15]) + 1}] Enter a custom URL")
        ep_choice = input(_wrap("Endpoint: ", "bold")).strip()
        if ep_choice.isdigit():
            idx = int(ep_choice) - 1
            if 0 <= idx < len(endpoints[:15]):
                url = endpoints[idx]
            else:
                url = self._prompt_url()
        else:
            url = self._prompt_url()

        _safe_print(_wrap("\n  Select vulnerability class:", "bold"))
        for num, (label, _key) in TARGETED_TESTS.items():
            _safe_print(f"    [{num}] {label}")
        test_choice = input(_wrap("Test: ", "bold")).strip()
        if test_choice not in TARGETED_TESTS:
            error("Invalid test.")
            return

        label, test_key = TARGETED_TESTS[test_choice]
        param = input(_wrap("Parameter name (Enter = try auto-discovery): ", "bold")).strip()

        _safe_print(_wrap(f"\n  Running {label} against {url}...", "bright_cyan"))
        result = self._run_safe_probe(url, test_key, param)
        if result:
            info(f"Result: {result}")
        else:
            warn("No vulnerability confirmed with this probe.")
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _prompt_url(self) -> str:
        url = input(_wrap("URL: ", "bold")).strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def _run_safe_probe(self, url: str, test_key: str, param: str) -> str:
        """Run one safe, non-destructive probe. Returns evidence or ''."""
        from modules.exploit import ExploitModule
        mod = ExploitModule(self._http(), self.scanner.logger, url,
                            self.scanner.cfg)
        try:
            if test_key == "xss":
                return mod._poc_xss(url, param or "q")
            if test_key == "sqli":
                return mod._poc_sqli(url, param or "id")
            if test_key == "ssti":
                return mod._poc_ssti(url, param or "name")
            if test_key == "cmdi":
                return mod._poc_cmdi(url, param or "cmd")
            if test_key == "nosqli":
                return mod._poc_nosqli(url, param or "user")
            if test_key == "traversal":
                return mod._poc_traversal(url, param or "file")
            if test_key == "redirect":
                return mod._poc_redirect(url, param or "url")
            if test_key == "dirlisting":
                return mod._poc_dirlisting(url)
            if test_key == "exposed_file":
                return mod._poc_exposed_file(url, param or "env")
            if test_key == "unauth":
                return (mod._poc_admin(url) or mod._poc_unauth_api(url)
                        or mod._poc_git(url))
            if test_key == "host_header":
                return self._probe_host_header(url)
            if test_key == "cache":
                return self._probe_cache_poison(url)
            if test_key == "clickjacking":
                return self._probe_clickjacking(url)
            if test_key == "cors":
                return self._probe_cors(url)
        except Exception as exc:
            error(f"Probe error: {exc}")
        return ""

    # ------------------------------------------- extra safe probes (menu)
    def _probe_host_header(self, url: str) -> str:
        """Send a poisoned Host header and look for absolute-URL reflection."""
        parsed = urlparse(url)
        http = self._http()
        evil = "evil.example"
        headers = {"Host": evil}
        resp = http.get(url, headers=headers)
        if not resp:
            return ""
        body = resp.body or ""
        if evil in body or evil in str(resp.headers):
            return ("Custom Host header reflected in response — potential "
                    "host header poisoning / password-reset poisoning.")
        return ""

    @staticmethod
    def _is_html_resp(resp) -> bool:
        """Only HTML documents can be clicked-jacked or template-injected."""
        if not resp:
            return False
        ct = ""
        for k, v in (resp.headers or {}).items():
            if k.lower() == "content-type":
                ct = v
        ct = ct.lower()
        if ct:
            return "text/html" in ct or "application/xhtml" in ct
        return (resp.body or "")[:200].lstrip().lower().startswith("<!doctype")

    def _probe_cache_poison(self, url: str) -> str:
        """Look for unkeyed header handling that could poison a cache.

        Only flags HTML responses: static assets (.js/.css/images) are
        *supposed* to be cached with long max-age — flagging them as
        cache-poisoning is a false positive."""
        http = self._http()
        evil = "cachepoison.evil"
        headers = {"X-Forwarded-Host": evil}
        resp = http.get(url, headers=headers)
        if not resp or not self._is_html_resp(resp):
            return ""
        body = resp.body or ""
        if evil in body:
            return ("X-Forwarded-Host reflected in response — cache poisoning "
                    "indicator (unkeyed header).")
        cc = ""
        for k, v in (resp.headers or {}).items():
            if k.lower() == "cache-control":
                cc = v
        if cc and "no-store" not in cc.lower() and "private" not in cc.lower():
            return (f"HTML response is cacheable (Cache-Control: {cc}) — review "
                    "cache-key composition for poisoning potential.")
        return ""

    def _probe_clickjacking(self, url: str) -> str:
        """Check frame protection headers (HTML pages only)."""
        http = self._http()
        resp = http.get(url)
        if not resp or not self._is_html_resp(resp):
            return ""
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            return ("No X-Frame-Options / CSP frame-ancestors — page can be "
                    "embedded in an iframe (clickjacking).")
        return ""

    def _probe_cors(self, url: str) -> str:
        """Check whether an arbitrary Origin is reflected with credentials."""
        http = self._http()
        evil = "https://evil.example"
        resp = http.get(url, headers={"Origin": evil})
        if not resp:
            return ""
        acao = ""
        acac = ""
        for k, v in (resp.headers or {}).items():
            lk = k.lower()
            if lk == "access-control-allow-origin":
                acao = v
            elif lk == "access-control-allow-credentials":
                acac = v
        if evil in acao:
            return (f"Arbitrary Origin '{evil}' reflected in "
                    "Access-Control-Allow-Origin — CORS misconfiguration.")
        if acao == "*" and acac.lower() == "true":
            return "CORS wildcard + credentials — dangerous configuration."
        return ""

    def _show_ascii(self, key: str) -> None:
        art = _ASCII_ART.get(key)
        if art:
            _safe_print(_wrap(art, "red"))
            _safe_print("")

    def _exploit_pass(self) -> None:
        """Run the controlled exploitation pass on HIGH/CRITICAL findings."""
        self._show_ascii("sword")
        from modules.exploit import ExploitModule
        findings = [f for f in self._findings()
                    if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        if not findings:
            warn("No HIGH/CRITICAL findings to exploit-confirm.")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return

        info(f"Running controlled exploit pass on {len(findings)} finding(s)...")
        mod = ExploitModule(
            self._http(), self.scanner.logger, self._scan_title(),
            self.scanner.cfg,
            discovery=self.scanner.discovery, findings=self._findings(),
            brute_force=False,
        )
        new = mod.scan()
        confirmed = [f for f in self._findings()
                     if f.confidence >= 95 and "[CONFIRMED]" in f.evidence]
        info(f"Confirmed: {len(confirmed)} finding(s) with safe PoCs")
        for f in confirmed:
            print_finding(f.severity.value, f.title)
        self.scanner.findings.extend(new)
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _ddos_assessment(self) -> None:
        """Run the non-destructive DDoS protection assessment."""
        self._show_ascii("shield")
        from modules.ddos import DdosProtectionModule
        info("Running DDoS protection assessment (non-destructive)...")
        mod = DdosProtectionModule(self._http(), self.scanner.logger,
                                   self._scan_title(), self.scanner.cfg)
        findings = mod.scan()
        for f in findings:
            print_finding(f.severity.value, f.title)
        self.scanner.findings.extend(findings)
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _credential_test(self) -> None:
        """Controlled credential test — opt-in, capped, rate-limited."""
        self._show_ascii("keys")
        info("Credential test requires --brute-force and explicit authorization.")
        confirm = input(_wrap("Type YES to run a capped credential test: ", "bold")).strip()
        if confirm.upper() != "YES":
            warn("Aborted.")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return

        from modules.exploit import ExploitModule
        info("Running controlled credential test (capped, rate-limited)...")
        mod = ExploitModule(
            self._http(), self.scanner.logger, self._scan_title(),
            self.scanner.cfg,
            discovery=self.scanner.discovery, findings=self._findings(),
            brute_force=True,
        )
        new = mod.scan()
        self.scanner.findings.extend(new)
        input(_wrap("\nPress Enter to continue...", "gray"))

    # ------------------------------------------------ new attack actions
    def _full_assault(self) -> None:
        """Run every safe probe against every discovered endpoint."""
        self._show_ascii("skull")
        endpoints = []
        for f in self._findings():
            if f.endpoint and f.endpoint not in endpoints:
                endpoints.append(f.endpoint)
        if not endpoints:
            parsed = urlparse(self._scan_title())
            endpoints = [f"{parsed.scheme}://{parsed.netloc}/"]
        endpoints = endpoints[:12]
        # HTML-context tests must not run against static assets
        # (.js/.css/.map/images) — that produces false positives.
        html_classes = {"ssti", "clickjacking", "cache", "unauth",
                        "host_header", "cors", "dirlisting"}
        param_classes = {"xss", "sqli", "cmdi", "nosqli", "traversal",
                         "redirect"}
        classes = ["xss", "sqli", "ssti", "cmdi", "nosqli",
                   "traversal", "redirect", "dirlisting",
                   "exposed_file", "unauth", "cors", "clickjacking",
                   "host_header", "cache"]
        info(f"Full assault: {len(endpoints)} endpoint(s) x {len(classes)} vectors")
        confirmed = []
        total = len(endpoints) * len(classes)
        done = 0
        for url in endpoints:
            path = urlparse(url).path.lower()
            is_static = path.endswith((".js", ".css", ".map", ".png",
                                       ".jpg", ".jpeg", ".gif", ".svg",
                                       ".webp", ".ico", ".woff", ".woff2",
                                       ".ttf", ".pdf", ".zip", ".gz",
                                       ".json", ".min.js", ".min.css"))
            for test_key in classes:
                done += 1
                # skip HTML-context tests on static assets
                if is_static and test_key in html_classes:
                    continue
                # skip parameter-injection tests if the URL has no params
                if test_key in param_classes and "?" not in url:
                    continue
                # extract the *real* first parameter from the URL so the
                # probe targets an existing input instead of inventing one
                param = ""
                if "?" in url:
                    q = urlparse(url).query
                    if q:
                        param = q.split("&")[0].split("=")[0]
                progress_bar(done / total * 100)
                try:
                    result = self._run_safe_probe(url, test_key, param)
                except Exception as exc:
                    result = ""
                    self.scanner.logger.logger.debug(f"assault probe error: {exc}")
                if result:
                    confirmed.append((url, test_key, result))
        _safe_print("")
        if confirmed:
            info(f"{len(confirmed)} confirmation(s) from full assault:")
            for url, key, result in confirmed:
                print_finding("MEDIUM", f"{key.upper()} @ {url}")
                _safe_print(_wrap(f"      {result[:160]}", "gray"))
        else:
            warn("No vulnerability confirmed by the full assault probes.")
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _ssrf_test(self) -> None:
        """SSRF canary check: send a marker to an attacker-controlled URL
        parameter and see whether the server fetches it."""
        self._show_ascii("target")
        info("SSRF canary check (non-destructive).")
        canary = input(_wrap(
            "Canary URL you control (e.g. https://your-server/ssrf?tag=1): ", "bold"
        )).strip()
        if not canary:
            warn("No canary URL — cannot confirm SSRF.")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return
        param = input(_wrap(
            "Parameter to test (Enter = try common ones: url, redirect, next): ", "bold"
        )).strip() or "url"
        parsed = urlparse(self._scan_title())
        base = f"{parsed.scheme}://{parsed.netloc}/"
        resp = self._http().get(base, params={param: canary})
        if not resp:
            error("No response from target.")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return
        body_lower = (resp.body or "").lower()
        if canary.lower() in body_lower or "error" in body_lower:
            warn("Server may have processed the canary URL — check your server logs.")
            info("If your canary received a hit, the parameter is SSRF-capable.")
        else:
            warn("No immediate reflection. Check canary logs for outbound fetches.")
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _jwt_analysis(self) -> None:
        """Inspect JWT handling: algorithm confusion, weak secret,
        missing exp — all checks are read-only."""
        self._show_ascii("keys")
        from modules.jwt import JwtModule
        info("Running JWT analysis (read-only)...")
        try:
            mod = JwtModule(self._http(), self.scanner.logger,
                            self._scan_title(), self.scanner.cfg)
            findings = mod.scan()
            for f in findings:
                print_finding(f.severity.value, f.title)
            self.scanner.findings.extend(findings)
        except Exception as exc:
            error(f"JWT module error: {exc}")
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _cors_check(self) -> None:
        """CORS misconfiguration check: arbitrary origin reflection."""
        self._show_ascii("target")
        from modules.cors import CORSModule
        info("Running CORS check...")
        try:
            mod = CORSModule(self._http(), self.scanner.logger,
                             self._scan_title(), self.scanner.cfg)
            findings = mod.scan()
            for f in findings:
                print_finding(f.severity.value, f.title)
            self.scanner.findings.extend(findings)
        except Exception as exc:
            error(f"CORS module error: {exc}")
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _clickjacking_check(self) -> None:
        """Clickjacking check: X-Frame-Options / CSP frame-ancestors."""
        self._show_ascii("shield")
        info("Running clickjacking check...")
        target = self._scan_title()
        resp = self._http().get(target)
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")
        frame_ancestors = "frame-ancestors" in csp.lower()
        if not xfo and not frame_ancestors:
            warn("No X-Frame-Options nor CSP frame-ancestors — page is framable.")
            info("A clickjacking PoC would load this page in an invisible iframe.")
        elif xfo and xfo.upper() == "SAMEORIGIN":
            info("X-Frame-Options: SAMEORIGIN present.")
        else:
            info(f"Protection present: XFO={xfo} frame-ancestors={frame_ancestors}")
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _surface_osint(self) -> None:
        """Show the full discovered surface + OSINT: all pages, subdomains,
        related URLs, emails and DNS records."""
        self._show_ascii("eye")
        disc = self.scanner.discovery
        site = getattr(self.scanner, "siteinfo", None)
        _safe_print(_wrap("\n  FULL SURFACE + OSINT", "bright_cyan"))
        _safe_print(_wrap("  " + "-" * 56, "gray"))

        # --- OSINT ---
        if site is not None and site:
            _safe_print(_wrap("  [OSINT] HOSTING & DOMAIN", "bold"))
            rows = [
                ("IP", ", ".join(site.ip_addresses)),
                ("Reverse DNS", site.reverse_dns),
                ("Geo", ", ".join(x for x in (site.city, site.region, site.country) if x)),
                ("ISP/Org", site.isp or site.organization),
                ("ASN", site.asn),
                ("Registrar", site.registrar),
                ("Created", site.created),
                ("Age", f"{site.days_since_created} days" if site.days_since_created is not None else ""),
                ("Expires", site.expires),
                ("Nameservers", ", ".join(site.nameservers)),
                ("Protections", ", ".join(site.protections)),
            ]
            for k, v in rows:
                if v:
                    _safe_print(_wrap(f"    {k:13s}: {v}", "gray"))
            # emails
            emails = list(dict.fromkeys(
                list(site.emails) + list(getattr(site, "mailto_emails", []))
                + ([site.security_contact] if site.security_contact else [])))
            if emails:
                _safe_print(_wrap("    Emails        :", "bold"))
                for e in emails[:15]:
                    _safe_print(_wrap(f"      ✉ {e}", "cyan"))
            # DNS records
            dns = getattr(site, "dns_records", {}) or {}
            for key, label in (("spf", "SPF"), ("dkim", "DKIM"),
                               ("dmarc", "DMARC"), ("mx", "MX"),
                               ("caa", "CAA")):
                vals = dns.get(key) or []
                if vals:
                    _safe_print(_wrap(f"    {label:13s}: " + " ; ".join(vals[:3]), "gray"))
        else:
            _safe_print(_wrap("  [OSINT] No siteinfo collected.", "gray"))

        # --- pages ---
        if disc is not None and (disc.pages or disc.api_endpoints):
            _safe_print(_wrap("\n  [SURFACE] ALL DISCOVERED PAGES", "bold"))
            pages = (disc.pages or [])
            apis = (disc.api_endpoints or [])
            for p in (pages + apis)[:60]:
                _safe_print(_wrap(f"    ▸ {p}", "cyan"))
            if len(pages + apis) > 60:
                _safe_print(_wrap(f"    … {len(pages) + len(apis) - 60} more in the report", "gray"))
            if disc.url_params:
                _safe_print(_wrap(f"\n    Parameters: {', '.join(disc.url_params[:40])}", "gray"))

        # --- subdomains ---
        subdomains = getattr(disc, "subdomains", []) if disc else []
        sub_hosts = getattr(disc, "subdomain_hosts", []) if disc else []
        if subdomains or sub_hosts:
            _safe_print(_wrap("\n  [SURFACE] SUBDOMAINS", "bold"))
            for sub in subdomains[:40]:
                host = sub.get("hostname", "") if isinstance(sub, dict) else str(sub)
                if host:
                    _safe_print(_wrap(f"    ▸ {host}", "cyan"))
            if sub_hosts:
                _safe_print(_wrap("\n    Alive:", "bold"))
                for sh in sub_hosts[:20]:
                    _safe_print(_wrap(
                        f"    ✓ {sh.get('hostname','')}  {sh.get('url','')}"
                        f"  [server: {sh.get('server','') or '?'}]", "gray"))
        else:
            _safe_print(_wrap("\n  [SURFACE] No subdomains discovered.", "gray"))

        _safe_print("")
        input(_wrap("Press Enter to continue...", "gray"))

    def _findings_details(self) -> None:
        """Show full finding details."""
        findings = sorted(self._findings(),
                          key=lambda f: f.severity.weight, reverse=True)
        if not findings:
            warn("No findings yet.")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return
        for f in findings:
            _safe_print("")
            _safe_print(_wrap(f"  [{f.severity.value}] {f.title}", "bold"))
            _safe_print(_wrap(f"    Endpoint : {f.endpoint or '(root)'}", "gray"))
            if f.parameter:
                _safe_print(_wrap(f"    Parameter: {f.parameter}", "gray"))
            _safe_print(_wrap(f"    Confidence: {f.confidence}%  Status: {f.status}", "gray"))
            if f.description:
                _safe_print(_wrap(f"    {f.description}", "cyan"))
            if f.evidence:
                _safe_print(_wrap(f"    Evidence: {f.evidence[:200]}", "gray"))
            if f.recommendation:
                _safe_print(_wrap(f"    Fix: {f.recommendation}", "green"))
        _safe_print("")
        input(_wrap("Press Enter to continue...", "gray"))

    def _attack_graph(self) -> None:
        """Show the attack graph as ASCII."""
        graph = self.scanner.graph
        if not graph:
            warn("No attack graph available.")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return
        _safe_print(_wrap("\n  ATTACK GRAPH", "bright_cyan"))
        _safe_print(_wrap("  " + "-" * 40, "gray"))
        _safe_print(graph.ascii_tree())
        _safe_print("")
        input(_wrap("Press Enter to continue...", "gray"))

    def _reports(self) -> None:
        """List generated reports and offer to open one."""
        out_dir = self.scanner.cfg.output_dir
        if not os.path.isdir(out_dir):
            warn(f"No reports directory ({out_dir}).")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return
        reports = sorted(
            [f for f in os.listdir(out_dir)
             if f.endswith((".html", ".json", ".md"))]
        )
        if not reports:
            warn("No reports generated yet.")
            input(_wrap("\nPress Enter to continue...", "gray"))
            return
        _safe_print(_wrap("\n  REPORTS:", "bold"))
        for i, r in enumerate(reports, 1):
            _safe_print(f"    [{i}] {r}")
        choice = input(_wrap("Open (number, or Enter to skip): ", "bold")).strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(reports):
                path = os.path.join(out_dir, reports[idx])
                info(f"Opening {path}")
                self._open_file(path)
        input(_wrap("\nPress Enter to continue...", "gray"))

    def _open_file(self, path: str) -> None:
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # noqa
            elif sys.platform == "darwin":
                os.system(f"open {path}")
            else:
                os.system(f"xdg-open {path}")
        except Exception:
            info(f"Report at: {os.path.abspath(path)}")

    def _new_scan(self) -> None:
        """Restart with a new target."""
        target = input(_wrap("New target URL / IP: ", "bold")).strip()
        if not target:
            warn("No target. Returning to menu.")
            return
        self.running = False
        self.scanner.cfg.target_url = target
        info(f"Starting new scan against {target}...")
        self.scanner.run()
