"""Reporting module: HTML, JSON, and Markdown report generation."""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import List, Optional

from .models import Finding, Severity, compute_overall_score, findings_by_severity
from ..scan_state import ScanState


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>AutoSecAudit Report - {target}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #0f1419; color: #c9d1d9; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px; }}
  h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #7ee787; margin-top: 40px; }}
  h3 {{ color: #d2a8ff; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
  .card .num {{ font-size: 2.5em; font-weight: bold; }}
  .card .label {{ color: #8b949e; font-size: 0.9em; text-transform: uppercase; }}
  .critical .num {{ color: #f85149; }}
  .high .num {{ color: #f85149; }}
  .medium .num {{ color: #d29922; }}
  .low .num {{ color: #58a6ff; }}
  .info .num {{ color: #8b949e; }}
  .score {{ font-size: 3em; font-weight: bold; text-align: center; margin: 20px; }}
  .finding {{ background: #161b22; border: 1px solid #30363d; border-left: 4px solid #30363d; border-radius: 6px; padding: 20px; margin: 15px 0; }}
  .finding.critical {{ border-left-color: #f85149; }}
  .finding.high {{ border-left-color: #f85149; }}
  .finding.medium {{ border-left-color: #d29922; }}
  .finding.low {{ border-left-color: #58a6ff; }}
  .finding.info {{ border-left-color: #8b949e; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; margin-right: 8px; }}
  .badge.critical {{ background: #f85149; color: #fff; }}
  .badge.high {{ background: #f85149; color: #fff; }}
  .badge.medium {{ background: #d29922; color: #fff; }}
  .badge.low {{ background: #1f6feb; color: #fff; }}
  .badge.info {{ background: #6e7681; color: #fff; }}
  .badge.potential {{ background: #30363d; color: #c9d1d9; border: 1px solid #8b949e; }}
  pre {{ background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 12px; overflow-x: auto; color: #e6edf3; }}
  code {{ color: #e6edf3; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
  th {{ background: #21262d; color: #58a6ff; }}
  .bar-chart {{ margin: 20px 0; }}
  .bar {{ display: flex; align-items: center; margin: 8px 0; }}
  .bar .name {{ width: 100px; }}
  .bar .track {{ flex: 1; background: #21262d; border-radius: 4px; overflow: hidden; height: 24px; }}
  .bar .fill {{ height: 100%; }}
  .timestamp {{ color: #8b949e; font-size: 0.9em; }}
  .disclaimer {{ background: #1c2128; border: 1px solid #d29922; border-radius: 6px; padding: 15px; margin: 20px 0; color: #d2a8ff; }}
</style>
</head>
<body>
<div class=\"container\">
  <h1>AutoSecAudit Report</h1>
  <p class=\"timestamp\">Generated: {generated}</p>
  <p><strong>Target:</strong> {target}</p>
  <p><strong>Mode:</strong> {mode}</p>
  <p><strong>Duration:</strong> {duration:.1f}s</p>

  <div class=\"disclaimer\">
    <strong>Authorized testing only.</strong> This report was produced by a tool
    intended exclusively for systems you own or are explicitly authorized to test.
  </div>

  <h2>Executive Summary</h2>
  <div class=\"score\" style=\"color: {score_color};\">{score}/100</div>
  <p style=\"text-align:center; color:#8b949e;\">Risk score (higher = worse posture)</p>

  <div class=\"summary\">
    <div class=\"card critical\"><div class=\"num\">{critical}</div><div class=\"label\">Critical</div></div>
    <div class=\"card high\"><div class=\"num\">{high}</div><div class=\"label\">High</div></div>
    <div class=\"card medium\"><div class=\"num\">{medium}</div><div class=\"label\">Medium</div></div>
    <div class=\"card low\"><div class=\"num\">{low}</div><div class=\"label\">Low</div></div>
  </div>

  <h2>Findings by Severity</h2>
  <div class=\"bar-chart\">
    {bars}
  </div>

  <h2>Site Information (OSINT)</h2>
  <table>
    <tr><th>Attribute</th><th>Value</th></tr>
    <tr><td>IP address</td><td>{site_ip}</td></tr>
    <tr><td>Reverse DNS</td><td>{site_rdns}</td></tr>
    <tr><td>Geolocation</td><td>{site_geo}</td></tr>
    <tr><td>ISP / Organization</td><td>{site_isp}</td></tr>
    <tr><td>ASN</td><td>{site_asn}</td></tr>
    <tr><td>Registrar</td><td>{site_registrar}</td></tr>
    <tr><td>Domain created</td><td>{site_created}</td></tr>
    <tr><td>Domain age</td><td>{site_age}</td></tr>
    <tr><td>Domain expires</td><td>{site_expires}</td></tr>
    <tr><td>Nameservers</td><td>{site_ns}</td></tr>
    <tr><td>Emails</td><td>{site_emails}</td></tr>
    <tr><td>DNS records (SPF/DKIM/DMARC/MX)</td><td>{site_dns}</td></tr>
    <tr><td>First archived</td><td>{site_first}</td></tr>
    <tr><td>Server header</td><td>{site_server}</td></tr>
    <tr><td>Protections</td><td>{site_protections}</td></tr>
  </table>

  <h2>Detected Technologies</h2>
  <p>{technologies}</p>

  <h2>Discovered Surface</h2>
  <table>
    <tr><th>Surface</th><th>Count</th></tr>
    <tr><td>Pages</td><td>{pages}</td></tr>
    <tr><td>API endpoints</td><td>{apis}</td></tr>
    <tr><td>JS files</td><td>{js}</td></tr>
    <tr><td>Forms</td><td>{forms}</td></tr>
    <tr><td>Open ports</td><td>{ports}</td></tr>
    <tr><td>URL parameters</td><td>{params_count}</td></tr>
    <tr><td>Subdomains</td><td>{subdomains_count}</td></tr>
  </table>
  {pages_html}
  {apis_html}
  {subdomains_html}

  <h2>Attack Graph</h2>
  <p class="timestamp">Nodes: {graph_nodes} | Edges: {graph_edges}</p>
  <pre style="max-height:400px; overflow:auto;">{attack_graph_html}</pre>

  <h2>Attack Paths</h2>
  {attack_paths_html}

  <h2>Findings ({count})</h2>
  {findings_html}

  <h2>Timeline</h2>
  <p class=\"timestamp\">Scan started: {started}</p>
  <p class=\"timestamp\">Scan finished: {finished}</p>
</div>
</body>
</html>"""

_FINDING_HTML = """
<div class=\"finding {sev_lower}\" id=\"finding-{idx}\">
  <h3><span class=\"badge {sev_lower}\">{severity}</span>{title} <span class=\"badge {status_lower}\">{status}</span></h3>
  {potential_badge}
  <p><strong>Confidence:</strong> {confidence}% | <strong>Module:</strong> {module}
     | <strong>Validation:</strong> LEVEL {level} ({level_label})</p>
  <p><strong>Endpoint:</strong> {endpoint}</p>
  {parameter}
  <p><strong>Description:</strong> {description}</p>
  <p><strong>Impact:</strong> {impact}</p>
  {exploitability}
  <p><strong>Evidence:</strong></p>
  <pre>{evidence}</pre>
  <p><strong>Request:</strong></p>
  <pre>{request}</pre>
  <p><strong>Response indicators:</strong> {response_indicators}</p>
  <p><strong>Reproduction steps:</strong></p>
  <pre>{reproduction_steps}</pre>
  <p><strong>Recommendation:</strong> {recommendation}</p>
  {references}
</div>
"""

_EXPLOIT_HTML = """
  <p><strong>Exploitability analysis</strong></p>
  <table>
    <tr><td><strong>Entry point</strong></td><td>{entry_point}</td></tr>
    <tr><td><strong>Attack surface</strong></td><td>{attack_surface}</td></tr>
    <tr><td><strong>Preconditions</strong></td><td>{preconditions}</td></tr>
    <tr><td><strong>Required privileges</strong></td><td>{required_privileges}</td></tr>
    <tr><td><strong>User interaction</strong></td><td>{user_interaction}</td></tr>
    <tr><td><strong>Attack complexity</strong></td><td>{attack_complexity}</td></tr>
    <tr><td><strong>Affected component</strong></td><td>{affected_component}</td></tr>
    <tr><td><strong>Validation status</strong></td><td>{validation_status}</td></tr>
  </table>
"""


class ReportGenerator:
    """Generate HTML, JSON, and Markdown reports.

    Report files are named '<sanitized_url>_scan_<N>.<ext>' where N is
    a per-target counter that increments on every scan.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._state = ScanState(output_dir)
        self._basename: Optional[str] = None

    def _get_basename(self, target: str) -> str:
        if self._basename is None:
            self._basename = self._state.get_basename(target)
        return self._basename

    def _base_path(self, ext: str, target: str = "") -> str:
        if target:
            name = self._get_basename(target)
        else:
            name = f"report_{self.timestamp}"
        return os.path.join(self.output_dir, f"{name}.{ext}")

    def _site_rows(self, siteinfo) -> dict:
        """Build the siteinfo placeholder values for templates."""
        if not siteinfo:
            return {
                "site_ip": "N/A", "site_rdns": "N/A", "site_geo": "N/A",
                "site_isp": "N/A", "site_asn": "N/A", "site_registrar": "N/A",
                "site_created": "N/A", "site_age": "N/A",
                "site_expires": "N/A", "site_ns": "N/A",
                "site_emails": "N/A", "site_dns": "N/A", "site_first": "N/A",
                "site_server": "N/A", "site_protections": "N/A",
            }
        geo = ", ".join(x for x in (siteinfo.city, siteinfo.region, siteinfo.country) if x)
        all_emails = list(dict.fromkeys(
            list(siteinfo.emails) + list(getattr(siteinfo, "mailto_emails", []))
            + ([siteinfo.security_contact] if siteinfo.security_contact else [])))
        dns = getattr(siteinfo, "dns_records", {}) or {}
        dns_summary = "; ".join(
            f"{k.upper()}: {v[0][:80]}" for k, v in dns.items()
            if v and k in ("spf", "dkim", "dmarc", "mx"))
        return {
            "site_ip": ", ".join(siteinfo.ip_addresses) or "N/A",
            "site_rdns": getattr(siteinfo, "reverse_dns", "") or "N/A",
            "site_geo": geo or "N/A",
            "site_isp": (siteinfo.isp or siteinfo.organization or "N/A"),
            "site_asn": siteinfo.asn or "N/A",
            "site_registrar": siteinfo.registrar or "N/A",
            "site_created": siteinfo.created or "N/A",
            "site_age": (f"{siteinfo.days_since_created} days" if siteinfo.days_since_created is not None else "N/A"),
            "site_expires": siteinfo.expires or "N/A",
            "site_ns": ", ".join(siteinfo.nameservers[:4] or dns.get("ns", [])) or "N/A",
            "site_emails": ", ".join(all_emails[:6]) or "N/A",
            "site_dns": dns_summary or "N/A",
            "site_first": siteinfo.first_snapshot or "N/A",
            "site_server": siteinfo.server_header or "N/A",
            "site_protections": ", ".join(siteinfo.protections) or "None detected",
        }

    def generate_html(self, target: str, mode: str, duration: float,
                      findings: List[Finding], discovery=None, siteinfo=None,
                      started: str = "", finished: str = "",
                      graph=None, chains=None) -> str:
        counts = findings_by_severity(findings)
        score = compute_overall_score(findings)
        score_color = "#7ee787" if score < 30 else "#d29922" if score < 60 else "#f85149"
        max_count = max(counts.values()) if counts else 1
        bars = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = counts.get(sev, 0)
            pct = int((cnt / max_count) * 100) if max_count else 0
            color = {"CRITICAL": "#f85149", "HIGH": "#f85149",
                     "MEDIUM": "#d29922", "LOW": "#58a6ff", "INFO": "#8b949e"}[sev]
            bars.append(
                f'<div class="bar"><div class="name">{sev}</div>'
                f'<div class="track"><div class="fill" style="width:{pct}%;background:{color}"></div></div>'
                f'<div style="margin-left:10px">{cnt}</div></div>'
            )

        from modules.reporting.models import validation_level_label
        findings_html = []
        for idx, f in enumerate(findings):
            potential = '<span class="badge potential">POTENTIAL</span>' if f.potential else ''
            param_html = f'<p><strong>Parameter:</strong> {f.parameter}</p>' if f.parameter else ''
            refs = '<p><strong>References:</strong><br>' + '<br>'.join(
                f'<a href="{r}" style="color:#58a6ff">{r}</a>' for r in f.references
            ) + '</p>' if f.references else ''
            exploit_html = ""
            if f.entry_point or f.attack_surface or f.preconditions or \
               f.required_privileges or f.attack_complexity != "MEDIUM":
                exploit_html = _EXPLOIT_HTML.format(
                    entry_point=f.entry_point or 'N/A',
                    attack_surface=f.attack_surface or 'N/A',
                    preconditions=f.preconditions or 'N/A',
                    required_privileges=f.required_privileges or 'N/A',
                    user_interaction=f.user_interaction or 'NONE',
                    attack_complexity=f.attack_complexity or 'MEDIUM',
                    affected_component=f.affected_component or 'N/A',
                    validation_status=f.status,
                )
            findings_html.append(_FINDING_HTML.format(
                idx=idx,
                sev_lower=f.severity.value.lower(),
                severity=f.severity.value,
                title=f.title,
                status=f.status,
                status_lower=f.status.lower(),
                potential_badge=potential,
                confidence=f.confidence,
                module=f.module,
                level=f.validation_level,
                level_label=validation_level_label(f.validation_level),
                endpoint=f.endpoint,
                parameter=param_html,
                description=f.description,
                impact=f.impact,
                exploitability=exploit_html,
                evidence=f.evidence[:1000] or 'N/A',
                request=f.request or 'N/A',
                response_indicators=f.response_indicators or 'N/A',
                reproduction_steps=f.reproduction_steps or 'N/A',
                recommendation=f.recommendation,
                references=refs,
            ))

        tech = ', '.join(discovery.technologies) if discovery and discovery.technologies else 'None detected'
        pages = len(discovery.pages) if discovery else 0
        apis = len(discovery.api_endpoints) if discovery else 0
        js = len(discovery.js_files) if discovery else 0
        forms = len(discovery.forms) if discovery else 0
        ports = len(discovery.open_ports) if discovery else 0
        subdomains = (getattr(discovery, "subdomains", None) or []) if discovery else []
        sub_hosts = (getattr(discovery, "subdomain_hosts", None) or []) if discovery else []
        subdomains_count = len(subdomains)
        params_count = len(discovery.url_params) if discovery else 0
        all_pages = ((discovery.pages or []) + (discovery.api_endpoints or [])) if discovery else []
        if all_pages:
            page_lis = "".join(
                f"<li><code>{p}</code></li>" for p in all_pages[:150])
            pages_html = (
                f"<h3>All Discovered Pages ({len(all_pages)})</h3>"
                f"<ul style='max-height:300px; overflow:auto; columns:2;'>{page_lis}</ul>")
        else:
            pages_html = ""
        apis_list = (discovery.api_endpoints or []) if discovery else []
        if apis_list:
            apis_html = (
                f"<h3>API Endpoints ({len(apis_list)})</h3>"
                f"<ul>{"".join(f'<li><code>{e}</code></li>' for e in apis_list[:80])}</ul>")
        else:
            apis_html = ""
        if sub_hosts:
            sub_rows = "".join(
                f"<tr><td>{sh.get('hostname','')}</td><td>{sh.get('url','')}</td>"
                f"<td>{sh.get('ip','')}</td><td>{sh.get('server','')}</td></tr>"
                for sh in sub_hosts[:40])
            subdomains_html = (
                "<h3>Alive Subdomains</h3>"
                "<table><tr><th>Host</th><th>URL</th><th>IP</th><th>Server</th></tr>"
                f"{sub_rows}</table>")
        elif subdomains:
            sub_list = "<br>".join(
                (s.get('hostname','') if isinstance(s, dict) else str(s))
                for s in subdomains[:60])
            subdomains_html = f"<h3>Discovered Subdomains</h3><p>{sub_list}</p>"
        else:
            subdomains_html = ""

        site = self._site_rows(siteinfo)
        graph_html = graph.ascii_tree() if graph else "(no graph)"
        graph_nodes = graph.node_count if graph else 0
        graph_edges = len(graph.edges) if graph else 0
        paths_html = ""
        if chains:
            for ci, chain in enumerate(chains, 1):
                steps = [
                    f"<li><strong>{f.severity.value}</strong> {f.title} "
                    f"[{'VALIDATED' if not f.potential else 'HYPOTHESIS'}] "
                    f"(<a href='#finding-{idx}' style='color:#58a6ff'>details</a>)</li>"
                    for idx, f in enumerate(findings) if any(
                        f2.title == f.title and f2.endpoint == f.endpoint
                        for f2 in chain.findings)
                ]
                # simpler: list chain steps directly
                steps = []
                for f in chain.findings:
                    fidx = next((i for i, x in enumerate(findings)
                                 if x.title == f.title and x.endpoint == f.endpoint), 0)
                    steps.append(
                        f"<li><strong>{f.severity.value}</strong> {f.title} "
                        f"[{'VALIDATED' if not f.potential else 'HYPOTHESIS'}] "
                        f"(<a href='#finding-{fidx}' style='color:#58a6ff'>details</a>)</li>")
                paths_html += (
                    f"<div class='finding high'><h3>Attack Path #{ci} "
                    f"<span class='badge high'>{chain.overall_risk.value}</span></h3>"
                    f"<ol>{''.join(steps)}</ol>"
                    f"<p class='timestamp'>Logical risk chain — validated and hypothetical "
                    f"steps are labeled. Not a proven exploit.</p></div>")
        else:
            paths_html = "<p>No attack paths identified.</p>"

        html = _HTML_TEMPLATE.format(
            target=target, mode=mode, duration=duration,
            generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            score=score, score_color=score_color,
            critical=counts.get("CRITICAL", 0),
            high=counts.get("HIGH", 0),
            medium=counts.get("MEDIUM", 0),
            low=counts.get("LOW", 0),
            bars="\n".join(bars),
            technologies=tech, pages=pages, apis=apis, js=js, forms=forms, ports=ports,
            params_count=params_count,
            pages_html=pages_html, apis_html=apis_html,
            subdomains_count=subdomains_count, subdomains_html=subdomains_html,
            count=len(findings),
            findings_html="\n".join(findings_html) if findings_html else "<p>No findings.</p>",
            started=started or "N/A", finished=finished or "N/A",
            attack_graph_html=graph_html,
            graph_nodes=graph_nodes, graph_edges=graph_edges,
            attack_paths_html=paths_html,
            **site,
        )

        path = self._base_path("html", target)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def generate_json(self, target: str, mode: str, duration: float,
                      findings: List[Finding], discovery=None, siteinfo=None,
                      started: str = "", finished: str = "",
                      graph=None, chains=None) -> str:
        score = compute_overall_score(findings)
        data = {
            "tool": "AutoSecAudit",
            "generated": datetime.now().isoformat(),
            "target": target,
            "mode": mode,
            "duration_seconds": round(duration, 2),
            "started": started,
            "finished": finished,
            "risk_score": score,
            "findings_count": len(findings),
            "findings_by_severity": findings_by_severity(findings),
            "findings": [f.to_dict() for f in findings],
            "siteinfo": siteinfo.to_dict() if siteinfo else {},
            "attack_graph": graph.to_dict() if graph else {},
            "attack_paths": [c.to_dict() for c in chains] if chains else [],
            "discovery": {
                "technologies": discovery.technologies if discovery else [],
                "pages": discovery.pages if discovery else [],
                "api_endpoints": discovery.api_endpoints if discovery else [],
                "js_files": discovery.js_files if discovery else [],
                "url_params": discovery.url_params if discovery else [],
                "cookies": discovery.cookies if discovery else [],
                "forms": discovery.forms if discovery else [],
                "open_ports": discovery.open_ports if discovery else [],
                "ip_addresses": discovery.ip_addresses if discovery else [],
                "subdomains": getattr(discovery, "subdomains", []) if discovery else [],
                "subdomain_hosts": getattr(discovery, "subdomain_hosts", []) if discovery else [],
            },
        }
        path = self._base_path("json", target)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return path

    def generate_markdown(self, target: str, mode: str, duration: float,
                          findings: List[Finding], discovery=None, siteinfo=None,
                          started: str = "", finished: str = "",
                          graph=None, chains=None) -> str:
        counts = findings_by_severity(findings)
        score = compute_overall_score(findings)
        lines = [
            f"# AutoSecAudit Report",
            f"",
            f"**Target:** {target}  ",
            f"**Mode:** {mode}  ",
            f"**Duration:** {duration:.1f}s  ",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"",
            f"> **Authorized testing only.** This report was produced by a tool intended "
            f"exclusively for systems you own or are explicitly authorized to test.",
            f"",
            f"## Executive Summary",
            f"",
            f"**Risk score:** {score}/100",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| CRITICAL | {counts.get('CRITICAL', 0)} |",
            f"| HIGH | {counts.get('HIGH', 0)} |",
            f"| MEDIUM | {counts.get('MEDIUM', 0)} |",
            f"| LOW | {counts.get('LOW', 0)} |",
            f"| INFO | {counts.get('INFO', 0)} |",
            f"",
        ]
        if siteinfo:
            s = siteinfo
            geo = ", ".join(x for x in (s.city, s.region, s.country) if x)
            lines.append("## Site Information (OSINT)")
            lines.append("")
            rows = [
                ("IP address", ", ".join(s.ip_addresses)),
                ("Reverse DNS", s.reverse_dns),
                ("Geolocation", geo),
                ("ISP / Organization", s.isp or s.organization),
                ("ASN", s.asn),
                ("Registrar", s.registrar),
                ("Domain created", s.created),
                ("Domain age", f"{s.days_since_created} days" if s.days_since_created is not None else ""),
                ("Domain expires", s.expires),
                ("Nameservers", ", ".join(s.nameservers or getattr(s, 'dns_records', {}).get('ns', []))),
                ("Emails (WHOIS/RDAP)", ", ".join(s.emails)),
                ("Emails (mailto links)", ", ".join(getattr(s, 'mailto_emails', []))),
                ("Security contact", s.security_contact),
                ("First archived", s.first_snapshot),
                ("Server header", s.server_header),
                ("Protections", ", ".join(s.protections)),
            ]
            for k, v in rows:
                if v:
                    lines.append(f"- **{k}:** {v}")
            # DNS records section (SPF / DKIM / DMARC / MX / CAA)
            dns = getattr(s, "dns_records", {}) or {}
            for key, label in (("spf", "SPF"), ("dkim", "DKIM"),
                               ("dmarc", "DMARC"), ("mx", "MX"),
                               ("caa", "CAA"), ("txt", "TXT (other)")):
                vals = dns.get(key) or []
                if vals:
                    lines.append(f"- **{label}:** " + " ; ".join(vals[:5]))
            lines.append("")

        if discovery:
            lines.append(f"## Technologies Detected")
            lines.append("")
            if discovery.technologies:
                for tech in discovery.technologies:
                    lines.append(f"- {tech}")
            else:
                lines.append("- None detected")
            lines.append("")
            lines.append(f"## Discovered Surface")
            lines.append("")
            lines.append(f"- Pages: {len(discovery.pages)}")
            lines.append(f"- API endpoints: {len(discovery.api_endpoints)}")
            lines.append(f"- JS files: {len(discovery.js_files)}")
            lines.append(f"- Forms: {len(discovery.forms)}")
            lines.append(f"- Open ports: {len(discovery.open_ports)}")
            lines.append(f"- URL parameters: {len(discovery.url_params)}")
            lines.append(f"- Cookies: {len(discovery.cookies)}")
            subdomains = getattr(discovery, "subdomains", [])
            sub_hosts = getattr(discovery, "subdomain_hosts", [])
            lines.append(f"- Subdomains discovered: {len(subdomains)}")
            lines.append(f"- Alive subdomains: {len(sub_hosts)}")
            # full page list (every discovered page, not just a count)
            pages = discovery.pages or []
            if pages:
                lines.append("")
                lines.append("### All Discovered Pages")
                for p in pages[:150]:
                    lines.append(f"- {p}")
                if len(pages) > 150:
                    lines.append(f"- … and {len(pages) - 150} more")
            # API endpoints list
            if discovery.api_endpoints:
                lines.append("")
                lines.append("### API Endpoints")
                for e in discovery.api_endpoints[:100]:
                    lines.append(f"- {e}")
            # URL parameters list
            if discovery.url_params:
                lines.append("")
                lines.append("### URL Parameters")
                lines.append(", ".join(discovery.url_params[:80]))
            if subdomains:
                lines.append("")
                lines.append("### Subdomains")
                for sub in subdomains[:60]:
                    host = sub.get("hostname", "") if isinstance(sub, dict) else str(sub)
                    if host:
                        lines.append(f"- {host}")
            if sub_hosts:
                lines.append("")
                lines.append("### Alive Subdomain Details")
                for sh in sub_hosts[:40]:
                    host = sh.get("hostname", "")
                    url = sh.get("url", "")
                    ip = sh.get("ip", "")
                    server = sh.get("server", "")
                    techs = ", ".join(sh.get("technologies", []) or [])
                    lines.append(
                        f"- **{host}** {url} (IP {ip}, server {server or 'unknown'}"
                        + (f", tech: {techs})" if techs else ")"))
            lines.append("")

        # attack graph + paths
        if graph:
            from modules.reporting.models import validation_level_label
            lines.append("## Attack Graph")
            lines.append("")
            lines.append(f"Nodes: {graph.node_count} | Edges: {len(graph.edges)}")
            lines.append("")
            lines.append("```")
            lines.append(graph.ascii_tree())
            lines.append("```")
            lines.append("")
        if chains:
            lines.append("## Attack Paths")
            lines.append("")
            for ci, chain in enumerate(chains, 1):
                lines.append(f"### Attack Path #{ci} — overall risk: **{chain.overall_risk.value}**")
                lines.append("")
                lines.append(chain.render_ascii())
                lines.append("")
                lines.append("> Logical risk chain: validated and hypothetical steps are labeled. "
                             "Not a proven exploit.")
                lines.append("")

        lines.append(f"## Findings ({len(findings)})")
        lines.append("")
        for i, f in enumerate(findings, 1):
            potential = " *(potential)*" if f.potential else ""
            lines.append(f"### {i}. [{f.severity.value}] {f.title}{potential} — **{f.status}**")
            lines.append("")
            lines.append(f"- **Confidence:** {f.confidence}%")
            lines.append(f"- **Validation:** LEVEL {f.validation_level} ({validation_level_label(f.validation_level)})")
            lines.append(f"- **Module:** {f.module}")
            lines.append(f"- **Endpoint:** `{f.endpoint}`")
            if f.parameter:
                lines.append(f"- **Parameter:** `{f.parameter}`")
            lines.append(f"- **Description:** {f.description}")
            lines.append(f"- **Impact:** {f.impact}")
            if f.entry_point or f.attack_complexity != "MEDIUM":
                lines.append("")
                lines.append("  **Exploitability analysis:**")
                lines.append(f"  - Entry point: `{f.entry_point or 'N/A'}`")
                lines.append(f"  - Required privileges: {f.required_privileges or 'N/A'}")
                lines.append(f"  - User interaction: {f.user_interaction or 'NONE'}")
                lines.append(f"  - Attack complexity: {f.attack_complexity or 'MEDIUM'}")
                lines.append(f"  - Validation status: {f.status}")
            lines.append(f"- **Evidence:**")
            lines.append(f"  ```")
            lines.append(f"  {f.evidence[:500]}")
            lines.append(f"  ```")
            if f.request:
                lines.append(f"- **Request:** `{f.request}`")
            lines.append(f"- **Response indicators:** {f.response_indicators or 'N/A'}")
            lines.append(f"- **Reproduction steps:**")
            lines.append(f"  ```")
            lines.append(f"  {f.reproduction_steps}")
            lines.append(f"  ```")
            lines.append(f"- **Recommendation:** {f.recommendation}")
            if f.references:
                lines.append(f"- **References:**")
                for r in f.references:
                    lines.append(f"  - {r}")
            lines.append("")

        lines.append("## Timeline")
        lines.append("")
        lines.append(f"- Scan started: {started or 'N/A'}")
        lines.append(f"- Scan finished: {finished or 'N/A'}")

        path = self._base_path("md", target)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path
