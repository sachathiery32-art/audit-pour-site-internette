"""Tests for the finding models and scoring."""
import unittest

from modules.reporting.models import (
    Finding, Severity, compute_overall_score,
    findings_by_severity, severity_from_cvss,
)


class TestSeverity(unittest.TestCase):
    def test_severity_weights(self):
        self.assertGreater(Severity.CRITICAL.weight, Severity.HIGH.weight)
        self.assertGreater(Severity.HIGH.weight, Severity.MEDIUM.weight)
        self.assertGreater(Severity.MEDIUM.weight, Severity.LOW.weight)
        self.assertGreater(Severity.LOW.weight, Severity.INFO.weight)

    def test_severity_from_cvss(self):
        self.assertEqual(severity_from_cvss(9.5), Severity.CRITICAL)
        self.assertEqual(severity_from_cvss(7.0), Severity.HIGH)
        self.assertEqual(severity_from_cvss(4.0), Severity.MEDIUM)
        self.assertEqual(severity_from_cvss(1.0), Severity.LOW)
        self.assertEqual(severity_from_cvss(0.0), Severity.INFO)


class TestScoring(unittest.TestCase):
    def test_empty_findings_perfect_score(self):
        self.assertEqual(compute_overall_score([]), 100.0)

    def test_critical_finding_lowers_score(self):
        f = Finding(
            title="RCE", severity=Severity.CRITICAL, confidence=100,
            target="https://example.com", module="test",
        )
        score = compute_overall_score([f])
        self.assertLess(score, 100.0)

    def test_low_confidence_counts_less(self):
        # low-confidence findings produce a higher (better) score because
        # they carry less certainty and therefore less penalty.
        high_conf = Finding(
            title="RCE", severity=Severity.CRITICAL, confidence=100,
            target="x", module="t",
        )
        low_conf = Finding(
            title="RCE", severity=Severity.CRITICAL, confidence=25,
            target="x", module="t",
        )
        s1 = compute_overall_score([high_conf])  # more penalty -> lower score
        s2 = compute_overall_score([low_conf])   # less penalty -> higher score
        self.assertLess(s1, s2)

    def test_findings_by_severity(self):
        findings = [
            Finding(title="a", severity=Severity.HIGH, confidence=90, target="x", module="t"),
            Finding(title="b", severity=Severity.HIGH, confidence=90, target="x", module="t"),
            Finding(title="c", severity=Severity.LOW, confidence=90, target="x", module="t"),
        ]
        counts = findings_by_severity(findings)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["CRITICAL"], 0)

    def test_to_dict(self):
        f = Finding(
            title="test", severity=Severity.MEDIUM, confidence=50,
            target="https://example.com", endpoint="/test", module="mod",
        )
        d = f.to_dict()
        self.assertEqual(d["severity"], "MEDIUM")
        self.assertEqual(d["confidence"], 50)
        self.assertEqual(d["endpoint"], "/test")


if __name__ == "__main__":
    unittest.main()
