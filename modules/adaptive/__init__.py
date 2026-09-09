"""Red-team adaptive engine.

Behaves like a red-team operator: after discovery, it inspects what was
found (technologies, forms, API endpoints, cookies, ports) and decides
which *additional* modules to launch.  For example:

  - If forms are found            -> injection, CSRF, business logic
  - If API endpoints are found     -> SSRF, GraphQL, JWT, BOLA
  - If JS files are found         -> dependency analysis, secret mining
  - If cookies with session IDs   -> JWT analysis, session fixation
  - If redirect parameters found  -> open redirect testing
  - If a WAF is detected          -> lower request rate, add evasion notes
  - If cloud signatures found     -> S3/bucket exposure
  - If WebSocket headers seen     -> WebSocket testing
  - If XML / SOAP content type    -> XXE testing

This is *additive*: it only enables modules that the static mode preset
left off, and never enables destructive options.
"""
from __future__ import annotations

from typing import Dict, List


# Keywords in discovered data that trigger a module.
_TRIGGERS: Dict[str, Dict[str, object]] = {
    # module_key -> {trigger_field -> list of patterns that enable it}
    "ssrf": {
        "url_params": ["url", "redirect", "next", "dest", "target", "rurl",
                       "return", "callback", "proxy", "fetch", "uri", "path"],
        "api_endpoints": ["/api/fetch", "/api/proxy", "/api/url", "/fetch",
                          "/proxy", "/load", "/import"],
    },
    "xxe": {
        "forms": ["xml", "soap"],
        "technologies": ["soap", "xml", "rest"],
    },
    "redirect": {
        "url_params": ["url", "redirect", "next", "dest", "target", "rurl",
                       "return", "goto", "continue", "to"],
    },
    "graphql": {
        "api_endpoints": ["/graphql", "/graphql.php", "/api/graphql"],
        "technologies": ["graphql", "apollo", "hasura"],
    },
    "websocket": {
        "technologies": ["websocket", "socket.io", "ws://"],
    },
    "jwt": {
        "cookies": ["jwt", "token", "bearer", "auth"],
        "url_params": ["token", "jwt"],
        "technologies": ["jwt", "auth0", "oauth"],
    },
    "cloud": {
        "technologies": ["aws", "s3", "azure", "gcp", "cloudfront",
                         "digitalocean"],
    },
    "deps": {
        "js_files": ["any"],  # any JS files at all trigger dependency analysis
    },
    "business_logic": {
        "forms": ["any"],
        "url_params": ["quantity", "amount", "price", "discount", "coupon",
                       "qty", "count", "step"],
    },
    "param_mining": {
        "forms": ["any"],
        "api_endpoints": ["any"],
    },
    "takeover": {
        "technologies": ["github pages", "heroku", "s3", "azure", "netlify",
                         "vercel", "fastly"],
    },
}


def plan_adaptive_modules(discovery) -> List[str]:
    """Given a :class:`DiscoveryResult`, return a list of module keys that
    should be *additionally* enabled based on what was discovered.

    This emulates a red-team operator choosing the next move based on
    the target's actual surface.
    """
    if discovery is None:
        return []

    enabled: List[str] = []

    for module_key, trigger_fields in _TRIGGERS.items():
        for field, patterns in trigger_fields.items():
            data: List[str] = []
            if field == "technologies":
                data = [t.lower() for t in (discovery.technologies or [])]
            elif field == "url_params":
                data = [p.lower() for p in (discovery.url_params or [])]
            elif field == "api_endpoints":
                data = [e.lower() for e in (discovery.api_endpoints or [])]
            elif field == "forms":
                data = [f.get("action", "").lower() + " " +
                        " ".join(f.get("name", "") for f in
                                 (discovery.forms or []))
                        for f in (discovery.forms or [])]
                # simplify: just collect all form actions+fields joined
                data = []
                for form in (discovery.forms or []):
                    data.append(form.get("action", "").lower())
                    for fld in form.get("fields", []):
                        data.append(fld.get("name", "").lower())
            elif field == "cookies":
                data = [c.get("name", "").lower() for c in (discovery.cookies or [])]
            elif field == "js_files":
                data = [j.lower() for j in (discovery.js_files or [])]

            for pattern in patterns:
                if pattern == "any":
                    if data:
                        enabled.append(module_key)
                        break
                else:
                    if any(pattern in item for item in data):
                        enabled.append(module_key)
                        break

    return list(set(enabled))


def red_team_summary(discovery, adaptive_modules: List[str]) -> str:
    """Return a human-readable summary of the red-team decision process."""
    lines = ["Red-team adaptive analysis:"]
    if not adaptive_modules:
        lines.append("  No additional modules triggered by discovery.")
        return "\n".join(lines)

    for mod in sorted(adaptive_modules):
        reason = _module_reason(mod, discovery)
        lines.append(f"  [+] Enabling {mod}: {reason}")

    return "\n".join(lines)


def _module_reason(mod: str, discovery) -> str:
    reasons = {
        "ssrf": "URL/redirect-like parameters found — testing SSRF.",
        "xxe": "XML/SOAP indicators found — testing XXE.",
        "redirect": "Redirect parameters found — testing open redirect.",
        "graphql": "GraphQL endpoint or technology detected.",
        "websocket": "WebSocket indicators found.",
        "jwt": "JWT/token-related cookies or parameters found.",
        "cloud": "Cloud technology signatures detected.",
        "deps": "JavaScript files found — analyzing dependencies.",
        "business_logic": "Forms with quantity/price fields — testing logic.",
        "param_mining": "Forms/APIs found — mining hidden parameters.",
        "takeover": "Subdomain-takeover-vulnerable host detected.",
    }
    return reasons.get(mod, "Discovery triggered this module.")
