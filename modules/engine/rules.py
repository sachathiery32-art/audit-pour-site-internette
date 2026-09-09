"""Adaptive rules engine.

Evaluates declarative rules (config/rules.yaml) against the attack
graph and the event history, producing *actions* that the scanner turns
into enabled modules / queue entries / priority boosts.

New rules can be added to rules.yaml without touching scanner code.
"""
from __future__ import annotations

import os
from typing import Dict, List

import yaml

from modules.engine.graph import AttackGraph, classify_parameter, implications_for_class
from modules.engine.events import EventBus

_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config", "rules.yaml",
)

# Module keys -> base impact (used by the prioritizer)
MODULE_IMPACT = {
    "xss": 0.8, "sqli": 1.0, "nosqli": 0.9, "command_injection": 1.0,
    "ssti": 1.0, "ldap_injection": 0.8, "xpath_injection": 0.6,
    "path_traversal": 0.9, "ssrf": 0.9, "xxe": 0.9, "redirect": 0.5,
    "graphql": 0.7, "websocket": 0.6, "jwt": 0.8, "cloud": 0.7,
    "deps": 0.5, "business_logic": 0.7, "param_mining": 0.4,
    "takeover": 0.8, "subdomains": 0.7, "access_control": 0.95, "api": 0.8, "csrf": 0.6,
    "auth_session": 0.7, "files": 0.7, "headers": 0.3, "tls": 0.2,
    "cve": 0.8, "infrastructure": 0.6, "waf": 0.2, "siteinfo": 0.1,
    "exploit": 0.5, "discovery": 0.1,
    # --- New modules ---
    "cors": 0.6, "cookies": 0.5, "clickjacking": 0.4,
    "host_header": 0.7, "cache": 0.5, "deserialization": 0.9,
    "prototype_pollution": 0.7, "race_condition": 0.6, "rate_limiting": 0.5,
    "info_disclosure": 0.4, "secrets_exposure": 0.9, "http_smuggling": 0.9,
    "upload": 0.8, "oauth": 0.7, "saml": 0.6, "http_methods": 0.3,
    "mass_assignment": 0.8,
    "ddos_protection": 0.6,
}


class RulesEngine:
    """Loads rules.yaml and evaluates conditions against the graph."""

    def __init__(self, graph: AttackGraph, events: EventBus,
                 path: str | None = None):
        self.graph = graph
        self.events = events
        self.path = path or _RULES_PATH
        self.rules: List[dict] = self._load()

    def _load(self) -> List[dict]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return data.get("rules", []) or []
        except Exception:
            return []

    # ------------------------------------------------------ evaluation
    def evaluate(self) -> Dict[str, float]:
        """Return {action: priority_multiplier} for all matching rules.

        Actions are strings like 'enable_ssrf' / 'prioritize_bola'.
        The returned map lets the queue adjust module priority.
        """
        actions: Dict[str, float] = {}
        for rule in self.rules:
            cond = rule.get("condition", {})
            if not self._matches(cond):
                continue
            for action in rule.get("actions", []):
                actions[action] = max(actions.get(action, 0.0), 1.0)
        return actions

    def _matches(self, cond: Dict) -> bool:
        """Evaluate a single condition dict (AND semantics)."""
        for key, value in cond.items():
            if not self._match_condition(key, value):
                return False
        return True

    def _match_condition(self, key: str, value) -> bool:
        if key == "technology":
            return self._match_technology(value)
        if key == "api_detected":
            return self.graph.has_type("api") if value else not self.graph.has_type("api")
        if key == "authentication_detected":
            return self._auth_detected() if value else not self._auth_detected()
        if key == "endpoint_parameter_type":
            # value like "url" -> any parameter of that class
            return any(classify_parameter(n["label"]) == value
                       for n in self.graph.nodes.values()
                       if n["type"] == "parameter")
        if key == "has_parameter":
            return self.graph.has_type("parameter")
        if key == "has_cookie":
            return self.graph.has_type("cookie")
        if key == "has_js_files":
            return self.graph.has_type("file")
        if key == "has_forms":
            return self.graph.count_type("endpoint") > 0 or self.graph.has_type("api")
        if key == "service":
            return any(n.get("attrs", {}).get("service") == value
                       for n in self.graph.nodes.values())
        if key == "event":
            return self.events.has_event(value)
        # default: unknown condition -> ignore (fail-open for safety)
        return True

    def _match_technology(self, value) -> bool:
        if isinstance(value, str):
            value = [value]
        techs = [t.lower() for t in self.graph.tech_names()]
        return any(str(v).lower() in " ".join(techs) for v in value)

    def _auth_detected(self) -> bool:
        if self.graph.has_type("cookie"):
            return True
        for n in self.graph.nodes.values():
            if n["type"] == "endpoint" and any(
                    w in n["label"].lower() for w in ("login", "auth", "signin")):
                return True
        return False

    # ------------------------------------------------------- helpers
    def action_to_modules(self, actions: Dict[str, float]) -> Dict[str, float]:
        """Map rule actions to module keys with multipliers."""
        result: Dict[str, float] = {}
        for action, mult in actions.items():
            if action.startswith("enable_"):
                mod = action[len("enable_"):]
                result[mod] = max(result.get(mod, 1.0), mult)
            elif action.startswith("prioritize_"):
                mod = action[len("prioritize_"):]
                result[mod] = max(result.get(mod, 1.0), mult * 1.5)
        return result

    def implications_from_parameters(self) -> Dict[str, float]:
        """Map parameter classes in the graph to module boosts."""
        boosts: Dict[str, float] = {}
        for n in self.graph.nodes.values():
            if n["type"] != "parameter":
                continue
            cls = classify_parameter(n["label"])
            for mod in implications_for_class(cls):
                boosts[mod] = max(boosts.get(mod, 0.0), 0.9)
        return boosts

    def impact_for(self, module_key: str) -> float:
        return MODULE_IMPACT.get(module_key, 0.5)
