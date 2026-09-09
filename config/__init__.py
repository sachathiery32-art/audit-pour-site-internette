"""Configuration loader for AutoSecAudit.

Reads ``config.yaml`` and exposes a normalized :class:`ScanConfig` object.
Unsafe options (destructive, brute force, data modification) are forced to
``False`` unless explicitly set in the YAML — they can never be toggled on
accidentally from the CLI.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

import yaml


DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config.yaml",
)


@dataclass
class ScanConfig:
    """Normalized runtime configuration object."""

    target_url: str = ""
    allowed_hosts: List[str] = field(default_factory=list)
    auth_username: str = ""
    auth_password: str = ""
    auth_cookie: str = ""

    mode: str = "standard"
    threads: int = 5
    timeout: int = 10
    rate_limit: int = 2
    retries: int = 2
    cache: bool = True
    resume: bool = False

    modules: Dict[str, bool] = field(default_factory=dict)

    authorized_only: bool = True
    destructive_tests: bool = False
    brute_force: bool = False
    data_modification: bool = False
    confirm_authorization: bool = True

    output_dir: str = "reports"
    formats_html: bool = True
    formats_json: bool = True
    formats_markdown: bool = True
    interactive_menu: bool = True

    raw: Dict[str, Any] = field(default_factory=dict)


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_config(path: str | None = None) -> ScanConfig:
    """Load configuration from YAML and return a :class:`ScanConfig`."""
    config_path = path or DEFAULT_CONFIG_PATH
    if not os.path.exists(config_path):
        return ScanConfig()

    with open(config_path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    cfg = ScanConfig(raw=dict(data))

    target = data.get("target", {}) or {}
    auth = target.get("auth", {}) or {}
    cfg.target_url = str(target.get("url", "")).strip()
    cfg.allowed_hosts = [str(h).strip() for h in (target.get("allowed_hosts") or [])]
    cfg.auth_username = str(auth.get("username", "")).strip()
    cfg.auth_password = str(auth.get("password", "")).strip()
    cfg.auth_cookie = str(auth.get("cookie", "")).strip()

    scan = data.get("scan", {}) or {}
    cfg.mode = str(scan.get("mode", "standard")).strip().lower()
    cfg.threads = max(1, _coerce_int(scan.get("threads"), 5))
    cfg.timeout = max(1, _coerce_int(scan.get("timeout"), 10))
    cfg.rate_limit = max(1, _coerce_int(scan.get("rate_limit"), 2))
    cfg.retries = max(0, _coerce_int(scan.get("retries"), 2))
    cfg.cache = _coerce_bool(scan.get("cache"), True)
    cfg.resume = _coerce_bool(scan.get("resume"), False)

    cfg.modules = {k: _coerce_bool(v, False) for k, v in (data.get("modules") or {}).items()}

    safety = data.get("safety", {}) or {}
    cfg.authorized_only = _coerce_bool(safety.get("authorized_only"), True)
    cfg.destructive_tests = _coerce_bool(safety.get("destructive_tests"), False)
    cfg.brute_force = _coerce_bool(safety.get("brute_force"), False)
    cfg.data_modification = _coerce_bool(safety.get("data_modification"), False)
    cfg.confirm_authorization = _coerce_bool(safety.get("confirm_authorization"), True)

    reporting = data.get("reporting", {}) or {}
    cfg.output_dir = str(reporting.get("output_dir", "reports"))
    fmts = reporting.get("formats", {}) or {}
    cfg.formats_html = _coerce_bool(fmts.get("html"), True)
    cfg.formats_json = _coerce_bool(fmts.get("json"), True)
    cfg.formats_markdown = _coerce_bool(fmts.get("markdown"), True)

    return cfg


def resolve_modules_for_mode(cfg: ScanConfig) -> Dict[str, bool]:
    """Return the effective module map after applying the scan mode.

    Modes never enable destructive options — they only widen which
    detection modules run.
    """
    mode_presets: Dict[str, Dict[str, bool]] = {
        "quick": {
            "discovery": True, "headers": True, "tls": True,
            "xss": False, "sqli": False, "nosqli": False,
            "command_injection": False, "ldap_injection": False,
            "ssti": False, "xpath_injection": False, "path_traversal": False,
            "csrf": True, "access_control": False, "api": False,
            "files": True, "infrastructure": False, "cve": False,
            "waf": True, "deps": False, "ssrf": False, "xxe": False,
            "redirect": False, "graphql": False, "websocket": False,
            "jwt": False, "cloud": False, "business_logic": False,
            "param_mining": False, "takeover": False, "subdomains": False,
            "siteinfo": True, "exploit": False,
            "cors": True, "cookies": True, "clickjacking": True,
            "host_header": False, "cache": False, "deserialization": False,
            "prototype_pollution": False, "race_condition": False,
            "rate_limiting": False, "info_disclosure": True, "secrets_exposure": False,
            "http_smuggling": False, "upload": False, "oauth": False, "saml": False,
            "http_methods": False, "mass_assignment": False,
            "ddos_protection": True,
        },
        "standard": {
            "discovery": True, "headers": True, "tls": True,
            "xss": True, "sqli": True, "nosqli": False,
            "command_injection": False, "ldap_injection": False,
            "ssti": False, "xpath_injection": False, "path_traversal": True,
            "csrf": True, "access_control": True, "api": True,
            "files": True, "infrastructure": False, "cve": True,
            "waf": True, "deps": True, "ssrf": False, "xxe": False,
            "redirect": False, "graphql": False, "websocket": False,
            "jwt": False, "cloud": False, "business_logic": False,
            "param_mining": False, "takeover": False, "subdomains": True,
            "siteinfo": True, "exploit": False,
            "cors": True, "cookies": True, "clickjacking": True,
            "host_header": True, "cache": True, "deserialization": False,
            "prototype_pollution": False, "race_condition": False,
            "rate_limiting": True, "info_disclosure": True, "secrets_exposure": True,
            "http_smuggling": False, "upload": True, "oauth": False, "saml": False,
            "http_methods": True, "mass_assignment": False,
            "ddos_protection": True,
        },
        "deep": {
            "discovery": True, "headers": True, "tls": True,
            "xss": True, "sqli": True, "nosqli": True,
            "command_injection": True, "ldap_injection": True,
            "ssti": True, "xpath_injection": True, "path_traversal": True,
            "csrf": True, "access_control": True, "api": True,
            "files": True, "infrastructure": False, "cve": True,
            "waf": True, "deps": True, "ssrf": True, "xxe": True,
            "redirect": True, "graphql": True, "websocket": True,
            "jwt": True, "cloud": True, "business_logic": True,
            "param_mining": True, "takeover": True, "subdomains": True,
            "siteinfo": True, "exploit": False,
            "cors": True, "cookies": True, "clickjacking": True,
            "host_header": True, "cache": True, "deserialization": True,
            "prototype_pollution": True, "race_condition": True,
            "rate_limiting": True, "info_disclosure": True, "secrets_exposure": True,
            "http_smuggling": False, "upload": True, "oauth": True, "saml": True,
            "http_methods": True, "mass_assignment": True,
            "ddos_protection": True,
        },
        "web": {
            "discovery": True, "headers": True, "tls": True,
            "xss": True, "sqli": True, "nosqli": True,
            "command_injection": False, "ldap_injection": False,
            "ssti": True, "xpath_injection": True, "path_traversal": True,
            "csrf": True, "access_control": True, "api": False,
            "files": True, "infrastructure": False, "cve": True,
            "waf": True, "deps": True, "ssrf": True, "xxe": False,
            "redirect": True, "graphql": False, "websocket": True,
            "jwt": True, "cloud": True, "business_logic": True,
            "param_mining": True, "takeover": True, "subdomains": True,
            "siteinfo": True, "exploit": False,
            "ddos_protection": True,
        },
        "api": {
            "discovery": True, "headers": True, "tls": True,
            "xss": False, "sqli": False, "nosqli": True,
            "command_injection": False, "ldap_injection": False,
            "ssti": False, "xpath_injection": False, "path_traversal": False,
            "csrf": True, "access_control": True, "api": True,
            "files": False, "infrastructure": False, "cve": True,
            "waf": True, "deps": False, "ssrf": True, "xxe": False,
            "redirect": False, "graphql": True, "websocket": False,
            "jwt": True, "cloud": False, "business_logic": False,
            "param_mining": True, "takeover": False, "subdomains": True,
            "ddos_protection": True,
        },
        "infrastructure": {
            "discovery": True, "headers": False, "tls": True,
            "xss": False, "sqli": False, "nosqli": False,
            "command_injection": False, "ldap_injection": False,
            "ssti": False, "xpath_injection": False, "path_traversal": False,
            "csrf": False, "access_control": False, "api": False,
            "files": False, "infrastructure": True, "cve": True,
            "waf": False, "deps": False, "ssrf": False, "xxe": False,
            "redirect": False, "graphql": False, "websocket": False,
            "jwt": False, "cloud": False, "business_logic": False,
            "param_mining": False, "takeover": True, "subdomains": True,
            "siteinfo": True, "exploit": False,
            "ddos_protection": True,
        },
        "full": {
            "discovery": True, "headers": True, "tls": True,
            "xss": True, "sqli": True, "nosqli": True,
            "command_injection": True, "ldap_injection": True,
            "ssti": True, "xpath_injection": True, "path_traversal": True,
            "csrf": True, "access_control": True, "api": True,
            "files": True, "infrastructure": True, "cve": True,
            "waf": True, "deps": True, "ssrf": True, "xxe": True,
            "redirect": True, "graphql": True, "websocket": True,
            "jwt": True, "cloud": True, "business_logic": True,
            "param_mining": True, "takeover": True, "subdomains": True,
            "siteinfo": True, "exploit": False,
            "cors": True, "cookies": True, "clickjacking": True,
            "host_header": True, "cache": True, "deserialization": True,
            "prototype_pollution": True, "race_condition": True,
            "rate_limiting": True, "info_disclosure": True, "secrets_exposure": True,
            "http_smuggling": True, "upload": True, "oauth": True, "saml": True,
            "http_methods": True, "mass_assignment": True,
            "ddos_protection": True,
        },
    }
    preset = mode_presets.get(cfg.mode, mode_presets["standard"])
    effective = dict(preset)
    # Config flags only *disable* preset-enabled modules (never enable
    # destructive ones) — safer default behavior.
    for key, value in cfg.modules.items():
        if key in effective and value is False:
            effective[key] = False
        elif key in effective and value is True and key not in (
            "command_injection", "ldap_injection",
        ):
            # config can re-enable non-destructive modules suppressed by mode
            effective[key] = True
    return effective
