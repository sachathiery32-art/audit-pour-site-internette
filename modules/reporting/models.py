"""Finding data model and severity scoring.

A :class:`Finding` represents a single confirmed or suspected vulnerability.
Severity and confidence are scored deterministically; CVSS is optional.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHT[self]


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


VALIDATION_LEVELS = {
    0: "Fingerprint only",
    1: "Suspicious behavior",
    2: "Strong evidence",
    3: "Safe validation",
    4: "Confirmed in test environment",
}


def validation_level_label(level: int) -> str:
    return VALIDATION_LEVELS.get(level, "Unknown")


@dataclass
class Finding:
    """A single security finding."""

    title: str
    severity: Severity
    confidence: int  # 0-100
    target: str
    endpoint: str = ""
    parameter: str = ""
    description: str = ""
    evidence: str = ""
    request: str = ""
    response_indicators: str = ""
    reproduction_steps: str = ""
    impact: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    cvss: Optional[float] = None
    cwe: str = ""
    module: str = ""
    potential: bool = False
    validation_level: int = 2  # 0-4, see VALIDATION_LEVELS
    # --- exploitability analysis ---
    entry_point: str = ""
    attack_surface: str = ""
    preconditions: str = ""
    required_privileges: str = ""
    user_interaction: str = "NONE"
    attack_complexity: str = "MEDIUM"  # LOW / MEDIUM / HIGH
    affected_component: str = ""
    validation_status: str = "DETECTED"  # DETECTED/POTENTIAL/VALIDATED/CONFIRMED
    attack_path: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        """Normalized validation status derived from flags."""
        if self.validation_status in ("DETECTED", "POTENTIAL", "VALIDATED", "CONFIRMED"):
            return self.validation_status
        if not self.potential and self.validation_level >= 3:
            return "VALIDATED"
        if self.potential:
            return "POTENTIAL"
        if self.validation_level >= 2:
            return "DETECTED"
        return "POTENTIAL"

    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": self.evidence,
            "request": self.request,
            "response_indicators": self.response_indicators,
            "reproduction_steps": self.reproduction_steps,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "references": self.references,
            "cve": self.cve,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "module": self.module,
            "potential": self.potential,
            "validation_level": self.validation_level,
            "validation_status": self.status,
            "exploitability": {
                "entry_point": self.entry_point,
                "attack_surface": self.attack_surface,
                "preconditions": self.preconditions,
                "required_privileges": self.required_privileges,
                "user_interaction": self.user_interaction,
                "attack_complexity": self.attack_complexity,
                "affected_component": self.affected_component,
            },
            "attack_path": self.attack_path,
        }


def severity_from_cvss(cvss: float) -> Severity:
    """Map a CVSS v3.x base score to a :class:`Severity`."""
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss >= 0.1:
        return Severity.LOW
    return Severity.INFO


def compute_overall_score(findings: List[Finding]) -> float:
    """Return a 0-100 risk score from the list of findings.

    100 = no findings (perfect posture). Each finding *reduces* the score
    by an amount weighted by severity and attenuated by confidence.
    A single CRITICAL at full confidence lowers the score to ~30; a single
    INFO finding barely affects it.
    """
    if not findings:
        return 100.0
    # penalty per finding, attenuated by confidence (low-confidence = less penalty)
    # max penalty per finding is its severity weight as a fraction of 4 (the max weight)
    penalty = 0.0
    for f in findings:
        # INFO findings carry negligible penalty
        if f.severity == Severity.INFO:
            continue
        confidence_factor = max(0.25, f.confidence / 100.0)
        # CRITICAL (weight 4) -> 40 point penalty at full confidence
        penalty += f.severity.weight * 10.0 * confidence_factor
    score = 100.0 - penalty
    return round(max(0.0, min(100.0, score)), 1)


def findings_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
