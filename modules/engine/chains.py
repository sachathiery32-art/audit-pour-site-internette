"""Attack chain builder.

Identifies logical chains of findings (e.g. public endpoint -> weak auth
-> IDOR -> sensitive data) based on shared endpoints, parameters, and
severity ordering. Chains are *logical risk models*, not proven
exploits — each link is tagged VALIDATED or HYPOTHESIS.
"""
from __future__ import annotations

from typing import Dict, List

from modules.reporting.models import Finding, Severity


# Severity ordering used to orient a chain (entry -> impact)
_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
          Severity.CRITICAL]


def _severity_rank(sev: Severity) -> int:
    try:
        return _ORDER.index(sev)
    except ValueError:
        return 2


def _endpoint_key(f: Finding) -> str:
    ep = f.endpoint or f.target
    # normalize: strip query string
    return ep.split("?")[0]


class AttackChain:
    """A logical sequence of findings forming an attack path."""

    def __init__(self, findings: List[Finding]):
        self.findings = findings

    @property
    def overall_risk(self) -> Severity:
        return max((f.severity for f in self.findings),
                   key=_severity_rank) if self.findings else Severity.INFO

    def to_dict(self) -> Dict:
        return {
            "overall_risk": self.overall_risk.value,
            "steps": [{
                "title": f.title,
                "severity": f.severity.value,
                "endpoint": f.endpoint,
                "status": "VALIDATED" if not f.potential else "HYPOTHESIS",
                "confidence": f.confidence,
            } for f in self.findings],
        }

    def render_ascii(self) -> str:
        lines = [f"Attack Path (overall risk: {self.overall_risk.value})"]
        for i, f in enumerate(self.findings):
            status = "VALIDATED" if not f.potential else "HYPOTHESIS"
            lines.append(f"  {f.severity.value:8s} {f.title}  [{status}]")
            if i < len(self.findings) - 1:
                lines.append("       |")
                lines.append("       v")
        return "\n".join(lines)


def build_chains(findings: List[Finding], max_chains: int = 5) -> List[AttackChain]:
    """Group findings that share endpoints into logical attack chains.

    Rules:
    - INFO findings are excluded.
    - duplicate titles on the same endpoint are merged.
    - a chain requires at least 2 *distinct* findings.
    """
    if not findings:
        return []

    by_endpoint: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.severity == Severity.INFO:
            continue
        by_endpoint.setdefault(_endpoint_key(f), []).append(f)

    chains: List[AttackChain] = []
    seen_chain_ids: set = set()

    for group in by_endpoint.values():
        # merge duplicates by title
        merged: Dict[str, Finding] = {}
        for f in group:
            if f.title not in merged or _severity_rank(f.severity) > _severity_rank(
                    merged[f.title].severity):
                merged[f.title] = f
        distinct = list(merged.values())
        if len(distinct) < 2:
            continue  # a chain needs at least two distinct weaknesses
        ordered = sorted(distinct, key=lambda f: _severity_rank(f.severity))
        # safety net: never put two findings with the same title in one chain
        if len({f.title for f in ordered}) != len(ordered):
            continue
        chain_id = "|".join(f.title for f in ordered)
        if chain_id in seen_chain_ids:
            continue
        seen_chain_ids.add(chain_id)
        chains.append(AttackChain(ordered))

    chains.sort(key=lambda c: _severity_rank(c.overall_risk), reverse=True)
    return chains[:max_chains]
