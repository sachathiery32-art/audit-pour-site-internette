#!/usr/bin/env python
"""AutoSecAudit — main entry point.

Orchestrates the full scan workflow:
1. confirm authorization
2. load config
3. resolve target & scope
4. run discovery
5. run detection modules (per mode)
6. validate & score findings
7. generate reports
8. log everything (without secrets)
"""
from __future__ import annotations

import os
import sys
import time
import signal
import threading
from datetime import datetime
from typing import List
from urllib.parse import urlparse

# allow running both as `python autosecaudit.py` and `python -m autosecaudit`
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from config import load_config, resolve_modules_for_mode, ScanConfig
from modules.http_client import HttpClient
from modules.logger import ScanLogger
from modules.ui import (
    print_banner, info, warn, error, finding as print_finding,
    progress_bar, prompt, prompt_options, Dashboard,
    animate_scan_start, animate_discovery, animate_testing,
    animate_exploitation, animate_report, print_scan_complete,
    module_start, module_done,
)
from modules.reporting.models import Finding, Severity
from modules.reporting import ReportGenerator
from modules.discovery import DiscoveryModule
from modules.headers import HeadersTlsModule
from modules.injection import InjectionModule
from modules.access_control import AccessControlModule
from modules.auth import AuthSessionModule
from modules.api import ApiModule
from modules.files import FilesModule
from modules.infrastructure import InfrastructureModule
from modules.cve import CveModule
# --- Red-team adaptive & advanced modules ---
from modules.adaptive import plan_adaptive_modules, red_team_summary
from modules.ssrf import SsrfModule
from modules.xxe import XxeModule
from modules.redirect import OpenRedirectModule
from modules.graphql import GraphQLModule
from modules.websocket import WebSocketModule
from modules.jwt import JwtModule
from modules.cloud import CloudModule
from modules.waf import WafModule
from modules.deps import DepsModule
from modules.business_logic import BusinessLogicModule
from modules.param_mining import ParamMiningModule
from modules.takeover import TakeoverModule
from modules.subdomains import SubdomainModule
from modules.siteinfo import SiteInfoModule
from modules.exploit import ExploitModule
from modules.csrf import CSRFModule
from modules.cors import CORSModule
from modules.cookies import CookieModule
from modules.clickjacking import ClickjackingModule
from modules.host_header import HostHeaderModule
from modules.cache import CacheModule
from modules.deserialization import DeserializationModule
from modules.prototype_pollution import PrototypePollutionModule
from modules.race_condition import RaceConditionModule
from modules.rate_limiting import RateLimitModule
from modules.info_disclosure import InfoDisclosureModule
from modules.secrets_exposure import SecretsExposureModule
from modules.http_smuggling import HTTPSmugglingModule
from modules.upload import UploadModule
from modules.oauth import OAuthModule
from modules.saml import SAMModule
from modules.http_methods import HTTPMethodsModule
from modules.mass_assignment import MassAssignmentModule
from modules.ddos import DdosProtectionModule


# (module_key, class, requires_discovery, is_infra_only)
MODULE_REGISTRY = [
    ("discovery", DiscoveryModule, False, False),
    ("headers", HeadersTlsModule, False, False),
    ("tls", HeadersTlsModule, False, False),  # covered by headers module
    ("xss", None, True, False),  # handled by injection
    ("sqli", None, True, False),
    ("nosqli", None, True, False),
    ("command_injection", None, True, False),
    ("ldap_injection", None, True, False),
    ("ssti", None, True, False),
    ("xpath_injection", None, True, False),
    ("path_traversal", None, True, False),
    ("csrf", None, True, False),  # handled by auth module
    ("access_control", AccessControlModule, True, False),
    ("api", ApiModule, True, False),
    ("files", FilesModule, True, False),
    ("infrastructure", InfrastructureModule, False, True),
    ("cve", CveModule, True, False),
]


class Scanner:
    """Orchestrates the scan workflow."""

    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.http = HttpClient(
            timeout=cfg.timeout,
            rate_limit=cfg.rate_limit,
            retries=cfg.retries,
            cache=cfg.cache,
        )
        self.logger = ScanLogger()
        self.findings: List[Finding] = []
        self.discovery = None
        self.siteinfo = None
        self.brute_force_enabled = False
        self.graph = None
        self.events = None
        self.rules = None
        self.queue = None
        self.chains = []
        self._stop = False
        self.dashboard = Dashboard()

    def confirm_authorization(self) -> bool:
        """Refuse to scan without explicit user confirmation."""
        if not self.cfg.confirm_authorization:
            return True
        print()
        warn("AUTHORIZED TEST ONLY")
        print()
        print("I confirm that I have explicit permission to test this target.")
        answer = prompt("Type YES to continue:")
        if answer.upper() != "YES":
            error("Authorization not confirmed. Aborting.")
            return False
        info("Authorization confirmed.")
        return True

    def validate_scope(self) -> bool:
        """Ensure the target is reachable and in-scope."""
        if not self.cfg.target_url:
            error("No target URL set.")
            return False
        if self.cfg.authorized_only and not self._is_explicitly_in_scope():
            warn("Target not in explicit allowed_hosts list.")
            warn("Proceeding requires your explicit authorization (already confirmed).")
        return True

    def _is_explicitly_in_scope(self) -> bool:
        host = urlparse(self.cfg.target_url).hostname or ""
        return host in self.cfg.allowed_hosts if self.cfg.allowed_hosts else True

    def run(self) -> None:
        """Run the adaptive attack-engine scan."""
        from modules.engine.graph import AttackGraph, classify_parameter
        from modules.engine.events import EventBus
        from modules.engine.rules import RulesEngine
        from modules.engine.queue import AttackQueue
        from modules.engine.chains import build_chains

        self.logger.start(self.cfg.target_url, self.cfg.mode)
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        start_time = time.monotonic()

        signal.signal(signal.SIGINT, self._handle_sigint)

        # Initialize dashboard
        self.dashboard.set_target(self.cfg.target_url, self.cfg.mode)

        info(f"Target accepted: {self.cfg.target_url}")
        info(f"Mode: {self.cfg.mode}")
        info(f"Scope validated")

        modules = resolve_modules_for_mode(self.cfg)

        # --- attack knowledge graph + event bus + rules ---
        host = urlparse(self.cfg.target_url).hostname or self.cfg.target_url
        self.graph = AttackGraph(root=host)
        self.events = EventBus()
        self.rules = RulesEngine(self.graph, self.events)
        self.queue = AttackQueue()

        # ---------- Phase 1: discovery + site OSINT ----------
        animate_discovery()
        if modules.get("discovery"):
            module_start("discovery")
            info("Starting discovery...")
            infra_mode = modules.get("infrastructure", False)
            disc = DiscoveryModule(
                self.http, self.logger, self.cfg.target_url,
                self.cfg, infrastructure_mode=bool(infra_mode),
            )
            disc.scan()
            self.discovery = disc.result
            module_done("discovery")
            info(f"Technologies discovered: {len(self.discovery.technologies)}")
            info(f"Endpoints discovered: {len(self.discovery.pages) + len(self.discovery.api_endpoints)}")
            info(f"Parameters discovered: {len(self.discovery.url_params)}")
            # Update dashboard
            self.dashboard.set_surface(
                endpoints=len(self.discovery.pages) + len(self.discovery.api_endpoints),
                parameters=len(self.discovery.url_params),
                techs=self.discovery.technologies,
            )
            # build the graph + events
            self.graph.ingest_discovery(self.discovery)
            self.events.publish_discovery_events(self.discovery)

            # --- red-team adaptive analysis ---
            adaptive = plan_adaptive_modules(self.discovery)
            if adaptive:
                info("Red-team adaptive engine: analyzing discovery...")
                summary = red_team_summary(self.discovery, adaptive)
                for line in summary.splitlines():
                    self.logger.logger.info(line)
                    info(f"  {line}")
                for mod_key in adaptive:
                    modules[mod_key] = True

        if modules.get("siteinfo"):
            module_start("siteinfo")
            info("Gathering site OSINT (hosting, geolocation, domain age)...")
            mod = SiteInfoModule(self.http, self.logger, self.cfg.target_url, self.cfg)
            self.siteinfo = mod.info
            self.findings.extend(mod.scan())
            module_done("siteinfo")
            if self.siteinfo:
                info(f"Hosting: {self.siteinfo.isp or 'unknown'}")
                info(f"Location: {self.siteinfo.city or '?'}, {self.siteinfo.country or '?'}")
                info(f"Domain age: {self.siteinfo.days_since_created or '?'} days")

        if self._stop:
            self._finish(start_time, started_at)
            return

        # ---------- Phase 2: build the prioritized attack queue ----------
        animate_testing()
        self._build_queue(modules)

        # apply rules + parameter-class implications
        for mod_key, mult in self.rules.action_to_modules(
                self.rules.evaluate()).items():
            self.queue.add(mod_key, relevance=mult,
                           impact=self.rules.impact_for(mod_key))
        for mod_key, mult in self.rules.implications_from_parameters().items():
            self.queue.boost(mod_key, mult)

        # Update dashboard queue
        self.dashboard.update_queue(self.queue.sorted())
        info("\n" + self.queue.render())

        # ---------- Phase 3: learning loop ----------
        max_iterations = 3
        for iteration in range(1, max_iterations + 1):
            if self._stop:
                break
            info(f"\n=== Learning iteration {iteration}/{max_iterations} ===")
            ran_any = False
            changed = False
            ran_groups: set = set()
            self.dashboard.set_iteration(iteration, max_iterations)
            self.dashboard.render_dashboard()
            for item in self.queue.sorted():
                if self._stop:
                    break
                key = item["module"]
                if key in ("discovery", "siteinfo", "exploit"):
                    continue
                # group module keys that share one runner (injection, headers/tls)
                if key in self._INJECTION_KEYS:
                    group = "injection"
                elif key in ("headers", "tls"):
                    group = "headers"
                elif key == "csrf":
                    group = "auth_session"
                else:
                    group = key
                if group in ran_groups:
                    continue
                if item.get("ran") and not item.get("rerun"):
                    continue
                item["rerun"] = False
                findings_before = len(self.findings)
                module_start(key)
                self.dashboard.module_started(key)
                self._run_module(key, modules)
                new_findings = len(self.findings) - findings_before
                module_done(key, new_findings)
                self.dashboard.module_finished(key)
                # Add findings to dashboard and print immediately
                for f in self.findings[findings_before:]:
                    self.dashboard.add_finding(f)
                    print_finding(f.severity.value, f.title)
                    if f.endpoint:
                        info(f"    Endpoint: {f.endpoint}")
                ran_groups.add(group)
                # mark every queue item in the same group as run
                for other in self.queue._items.values():
                    ok = other["module"]
                    other_group = ("injection" if ok in self._INJECTION_KEYS
                                   else "headers" if ok in ("headers", "tls")
                                   else "auth_session" if ok == "csrf" else ok)
                    if other_group == group:
                        other["ran"] = True
                item["ran"] = True
                ran_any = True
                if new_findings:
                    changed = True
                    for f in self.findings[findings_before:]:
                        self.graph.add_finding_node(f)
                        self.events.finding_event(f)

            # stop conditions
            if self._check_stop_conditions():
                warn("SCAN PAUSED — target returned an abnormal error rate.")
                warn("No further tests executed.")
                break

            # re-evaluate rules: new discoveries -> only *new* tests are added;
            # modules already executed this scan are never re-run (avoids loops)
            new_added = False
            for mod_key, mult in self.rules.action_to_modules(
                    self.rules.evaluate()).items():
                if mod_key in ("discovery", "siteinfo", "exploit"):
                    continue
                if mod_key not in self.queue.keys():
                    self.queue.add(mod_key, relevance=mult,
                                   impact=self.rules.impact_for(mod_key))
                    new_added = True

            if not changed and not new_added:
                break  # attack surface is stable

        # ---------- Phase 4: auto-exploitation pass ----------
        if modules.get("exploit"):
            info("\nAuto-exploitation: confirming findings with safe PoCs...")
            mod = ExploitModule(
                self.http, self.logger, self.cfg.target_url, self.cfg,
                discovery=self.discovery, findings=self.findings,
                brute_force=self.brute_force_enabled,
            )
            self.findings.extend(mod.scan())

        # ---------- attack chains ----------
        self.chains = build_chains(self.findings)
        if self.chains:
            info(f"\nIdentified {len(self.chains)} logical attack path(s):")
            for c in self.chains:
                info(f"  {c.overall_risk.value} risk path: " +
                     " -> ".join(f.title for f in c.findings[:4]))

        progress_bar(100)
        self._finish(start_time, started_at)

    # ------------------------------------------------------------------ engine helpers
    _INJECTION_KEYS = ("xss", "sqli", "nosqli", "command_injection",
                       "ldap_injection", "ssti", "xpath_injection",
                       "path_traversal")

    def _run_module(self, key: str, modules: dict) -> None:
        """Instantiate and run one detection module by key."""
        target = self.cfg.target_url
        if key in ("headers", "tls"):
            self.findings.extend(HeadersTlsModule(
                self.http, self.logger, target, self.cfg).scan())
        elif key in self._INJECTION_KEYS:
            self.findings.extend(InjectionModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "access_control":
            self.findings.extend(AccessControlModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key in ("csrf", "auth_session"):
            self.findings.extend(AuthSessionModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "api":
            self.findings.extend(ApiModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "files":
            self.findings.extend(FilesModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "infrastructure":
            self.findings.extend(InfrastructureModule(
                self.http, self.logger, target, self.cfg).scan())
        elif key == "cve":
            self.findings.extend(CveModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "waf":
            self.findings.extend(WafModule(
                self.http, self.logger, target, self.cfg).scan())
        elif key == "deps":
            self.findings.extend(DepsModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "ssrf":
            self.findings.extend(SsrfModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "xxe":
            self.findings.extend(XxeModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "redirect":
            self.findings.extend(OpenRedirectModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "graphql":
            self.findings.extend(GraphQLModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "websocket":
            self.findings.extend(WebSocketModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "jwt":
            self.findings.extend(JwtModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "cloud":
            self.findings.extend(CloudModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "business_logic":
            self.findings.extend(BusinessLogicModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "param_mining":
            self.findings.extend(ParamMiningModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "takeover":
            self.findings.extend(TakeoverModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "subdomains":
            self.findings.extend(SubdomainModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "csrf":
            self.findings.extend(CSRFModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "cors":
            self.findings.extend(CORSModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "cookies":
            self.findings.extend(CookieModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "clickjacking":
            self.findings.extend(ClickjackingModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "host_header":
            self.findings.extend(HostHeaderModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "cache":
            self.findings.extend(CacheModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "deserialization":
            self.findings.extend(DeserializationModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "prototype_pollution":
            self.findings.extend(PrototypePollutionModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "race_condition":
            self.findings.extend(RaceConditionModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "rate_limiting":
            self.findings.extend(RateLimitModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "info_disclosure":
            self.findings.extend(InfoDisclosureModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "secrets_exposure":
            self.findings.extend(SecretsExposureModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "http_smuggling":
            self.findings.extend(HTTPSmugglingModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "upload":
            self.findings.extend(UploadModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "oauth":
            self.findings.extend(OAuthModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "saml":
            self.findings.extend(SAMModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "http_methods":
            self.findings.extend(HTTPMethodsModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "mass_assignment":
            self.findings.extend(MassAssignmentModule(
                self.http, self.logger, target, self.cfg,
                discovery=self.discovery).scan())
        elif key == "ddos_protection":
            self.findings.extend(DdosProtectionModule(
                self.http, self.logger, target, self.cfg).scan())

    def _count_params(self, cls_name: str) -> int:
        from modules.engine.graph import classify_parameter
        return sum(1 for n in self.graph.nodes.values()
                   if n["type"] == "parameter"
                   and classify_parameter(n["label"]) == cls_name)

    def _surface_for(self, key: str) -> float:
        """How much attack surface the graph gives this module (0-1)."""
        g = self.graph
        base = 0.25
        if key in ("access_control", "api"):
            return min(1.0, base + (g.count_type("api") + self._count_params("id")) / 3.0)
        if key in ("ssrf", "redirect"):
            return min(1.0, base + self._count_params("url") / 2.0)
        if key in ("xss", "sqli"):
            return min(1.0, base + (self._count_params("search") + g.count_type("endpoint")) / 4.0)
        if key == "ssti":
            return min(1.0, base + self._count_params("template"))
        if key in ("auth_session", "jwt"):
            return min(1.0, base + (g.count_type("cookie") + self._count_params("auth")) / 2.0)
        if key == "deps":
            return min(1.0, base + g.count_type("file") / 4.0)
        if key == "business_logic":
            return min(1.0, base + self._count_params("numeric") / 2.0)
        if key == "graphql":
            return min(1.0, base + sum(
                1 for n in g.nodes.values()
                if n["type"] == "api" and "graphql" in n["label"].lower()))
        if key == "cloud":
            return min(1.0, base + sum(
                1 for t in g.tech_names()
                if any(c in t.lower() for c in ("aws", "azure", "gcp", "s3"))))
        if key == "files":
            return 0.8
        if key == "headers" or key == "tls" or key == "waf":
            return 0.9
        if key == "cve":
            return min(1.0, base + g.count_type("technology") / 3.0)
        if key == "takeover":
            return 0.4
        if key == "websocket":
            return min(1.0, base + g.count_type("file") / 6.0)
        if key == "csrf":
            return min(1.0, base + (g.count_type("cookie") + self._count_params("auth")) / 2.0)
        if key == "cors":
            return 0.7
        if key == "cookies":
            return min(1.0, base + g.count_type("cookie") / 3.0)
        if key == "clickjacking":
            return 0.6
        if key == "host_header":
            return 0.5
        if key == "cache":
            return 0.5
        if key == "deserialization":
            return min(1.0, base + self._count_params("auth") / 3.0)
        if key == "prototype_pollution":
            return min(1.0, base + g.count_type("file") / 5.0)
        if key == "race_condition":
            return min(1.0, base + self._count_params("numeric") / 3.0)
        if key == "rate_limiting":
            return 0.7
        if key == "info_disclosure":
            return 0.8
        if key == "secrets_exposure":
            return min(1.0, base + g.count_type("file") / 4.0)
        if key == "upload":
            return 0.4
        if key == "oauth":
            return 0.5
        if key == "saml":
            return 0.4
        if key == "http_methods":
            return 0.4
        if key == "mass_assignment":
            return min(1.0, base + g.count_type("api") / 3.0)
        if key == "ddos_protection":
            return 0.9  # always relevant — availability check
        return base

    def _build_queue(self, modules: dict) -> None:
        """Populate the attack queue from the enabled module map."""
        for key, enabled in modules.items():
            if not enabled or key in ("discovery", "siteinfo", "exploit"):
                continue
            surf = self._surface_for(key)
            impact = self.rules.impact_for(key)
            self.queue.add(key, relevance=0.5, surface=surf,
                           confidence=0.6, impact=impact,
                           exploitability=0.6)

    def _check_stop_conditions(self) -> bool:
        """Return True if the scan should pause (safety)."""
        reqs = self.http.requests_count
        fails = self.http.failures_count
        if reqs >= 10 and fails / max(reqs, 1) > 0.5:
            self.logger.logger.warning(
                f"stop-condition: error rate {fails}/{reqs}")
            return True
        return False

    def _handle_sigint(self, signum, frame) -> None:
        warn("\nCTRL+C received — stopping after current module...")
        self._stop = True

    def _finish(self, start_time: float, started_at: str) -> None:
        duration = time.monotonic() - start_time
        finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # deduplicate findings by (title, endpoint, parameter)
        seen = set()
        unique: List[Finding] = []
        for f in self.findings:
            key = (f.title, f.endpoint, f.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        # Final dashboard render
        self.dashboard.render_dashboard()

        # print findings summary with validation status
        print()
        info("FINAL FINDINGS SUMMARY")
        info("-" * 40)
        for f in sorted(self.findings, key=lambda x: x.severity.weight, reverse=True):
            status = f.status
            color = {"CONFIRMED": "green", "VALIDATED": "green",
                     "DETECTED": "yellow", "POTENTIAL": "gray"}.get(status, "gray")
            from modules.ui import _wrap as _w
            sev = f.severity.value.upper()
            print(f"  {_w(sev.ljust(8), '')} {_w(f.title, 'bold')}  "
                  f"{_w(f'[{status}]', color)}  conf={f.confidence}%")

        if self.graph:
            info(f"Attack graph: {self.graph.node_count} nodes")

        # generate reports
        gen = ReportGenerator(self.cfg.output_dir)
        report_paths = []
        if self.cfg.formats_html:
            path = gen.generate_html(
                self.cfg.target_url, self.cfg.mode, duration,
                self.findings, self.discovery, self.siteinfo, started_at, finished_at,
                graph=self.graph, chains=self.chains,
            )
            report_paths.append(path)
        if self.cfg.formats_json:
            path = gen.generate_json(
                self.cfg.target_url, self.cfg.mode, duration,
                self.findings, self.discovery, self.siteinfo, started_at, finished_at,
                graph=self.graph, chains=self.chains,
            )
            report_paths.append(path)
        if self.cfg.formats_markdown:
            path = gen.generate_markdown(
                self.cfg.target_url, self.cfg.mode, duration,
                self.findings, self.discovery, self.siteinfo, started_at, finished_at,
                graph=self.graph, chains=self.chains,
            )
            report_paths.append(path)

        # Print final summary with reports
        print_scan_complete(len(self.findings), duration, report_paths)
        info(f"Log: {self.logger.log_path}")

        # interactive post-scan menu (only when stdin is a real terminal)
        if self.cfg.interactive_menu and sys.stdin.isatty():
            try:
                from modules.menu import PostScanMenu
                PostScanMenu(self).render()
            except (KeyboardInterrupt, EOFError):
                info("Menu closed.")
            except Exception as exc:
                warn(f"Menu unavailable: {exc}")

        self.http.close()


def interactive_select_mode() -> str:
    """Show the CLI mode menu and return the chosen mode."""
    modes = ["quick", "standard", "deep", "infrastructure", "full"]
    labels = [
        "Quick        — fastest, safest checks only",
        "Standard     — balanced web checks",
        "Deep         — thorough, all injection vectors",
        "Infrastructure — ports & services on in-scope hosts",
        "Full Audit   — every module",
    ]
    chosen = prompt_options("Scan mode:", labels)
    # map label back to mode key
    return modes[labels.index(chosen)]


def _print_help() -> None:
    print("""Usage: py autosecaudit.py [URL] [OPTIONS]

Options:
  URL              Target URL or IP (e.g. https://example.com)
  --mode MODE      Scan mode: quick, standard, deep, infrastructure, full
  --yes            Skip the interactive authorization prompt (use with caution)
  --exploit        Auto-exploit: confirm each HIGH/CRITICAL finding with a safe PoC
  --brute-force    ALSO run a controlled, rate-limited password test on login forms
                   (requires --exploit; capped at 100 attempts; authorized use only)
  --no-menu        Skip the interactive post-scan action menu (non-TTY friendly)
  --help, -h       Show this help message

Examples:
  py autosecaudit.py                         interactive mode
  py autosecaudit.py https://example.com      target given, pick mode interactively
  py autosecaudit.py https://example.com --mode standard --yes
  py autosecaudit.py https://example.com --mode deep --exploit --yes
  py autosecaudit.py https://example.com --mode deep --exploit --brute-force --yes
  run.bat                                     double-click on Windows

Note: You MUST have explicit permission to test any target.
""")


def main(argv: list | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    print_banner()

    # help flag
    if "--help" in argv or "-h" in argv:
        _print_help()
        return 0

    cfg = load_config()

    # parse flags
    skip_auth = "--yes" in argv
    exploit_enabled = "--exploit" in argv
    brute_force_enabled = "--brute-force" in argv
    # post-scan interactive menu (default on for TTY; disable with --no-menu)
    cfg.interactive_menu = "--no-menu" not in argv
    argv_pos = [a for a in argv if not a.startswith("-")]  # positional args

    # allow CLI args: autosecaudit.py <target> [--mode X] [--yes]
    if argv_pos:
        cfg.target_url = argv_pos[0]
    if "--mode" in argv:
        idx = argv.index("--mode")
        if idx + 1 < len(argv):
            cfg.mode = argv[idx + 1].lower()

    # interactive target entry if not provided
    if not cfg.target_url:
        print()
        target = prompt("Target URL / IP :")
        if not target:
            error("No target provided. Exiting.")
            return 1
        cfg.target_url = target

    # interactive mode selection if running interactively
    if "--mode" not in argv:
        print()
        cfg.mode = interactive_select_mode()

    scanner = Scanner(cfg)

    # enable siteinfo / exploit via flags (config flags can only disable)
    if exploit_enabled or brute_force_enabled:
        cfg.modules["exploit"] = True
        cfg.modules["siteinfo"] = True
        if brute_force_enabled:
            cfg.brute_force = True
            scanner.brute_force_enabled = True

    # authorization check
    if skip_auth:
        info("Authorization flag --yes provided. Proceeding.")
        warn("You confirmed you have explicit permission to test this target.")
        if brute_force_enabled:
            warn("BRUTE FORCE enabled — only for systems you own or are authorized to test.")
    else:
        if not scanner.confirm_authorization():
            return 1
        if brute_force_enabled:
            warn("BRUTE FORCE enabled — only for systems you own or are authorized to test.")
    if not scanner.validate_scope():
        return 1

    try:
        scanner.run()
    except Exception as exc:
        error(f"Scan failed: {exc}")
        scanner.logger.error(str(exc))
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
