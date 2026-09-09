"""Tests for the adaptive attack engine (graph, events, queue, chains, rules)."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from modules.engine.graph import AttackGraph, classify_parameter, implications_for_class
from modules.engine.events import EventBus
from modules.engine.queue import AttackQueue
from modules.engine.chains import build_chains, AttackChain
from modules.engine.rules import RulesEngine
from modules.reporting.models import Finding, Severity


class TestAttackGraph(unittest.TestCase):
    def test_add_node_and_edge(self):
        g = AttackGraph(root="example.com")
        self.assertTrue(g.add_node("example.com", "domain"))
        self.assertFalse(g.add_node("example.com", "domain"))  # duplicate
        g.add_node("tech:react", "technology", label="React")
        g.add_edge("example.com", "tech:react", "uses")
        self.assertEqual(g.node_count, 2)
        self.assertEqual(g.neighbors("example.com"), ["tech:react"])

    def test_ingest_discovery_changes_graph(self):
        g = AttackGraph(root="example.com")

        class D:
            hostname = "example.com"
            technologies = ["React", "jQuery"]
            pages = ["https://example.com/"]
            api_endpoints = ["https://example.com/api/users"]
            url_params = ["q", "id"]
            cookies = [{"name": "session"}]
            js_files = ["/app.js"]
            open_ports = [{"port": 443, "service": "https"}]
            ip_addresses = ["1.2.3.4"]

        self.assertTrue(g.ingest_discovery(D()))
        self.assertTrue(g.has_type("technology"))
        self.assertTrue(g.has_type("api"))
        self.assertTrue(g.has_type("parameter"))
        self.assertTrue(g.has_type("port"))

    def test_ascii_tree_ascii_safe(self):
        g = AttackGraph(root="example.com")
        g.add_node("example.com", "domain")
        g.add_node("api:1", "api", label="/api")
        g.add_edge("example.com", "api:1", "calls")
        tree = g.ascii_tree()
        self.assertIn("example.com", tree)
        self.assertIn("/api", tree)


class TestParameterClassifier(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(classify_parameter("redirect"), "url")
        self.assertEqual(classify_parameter("next"), "url")
        self.assertEqual(classify_parameter("file"), "file")
        self.assertEqual(classify_parameter("user_id"), "id")
        self.assertEqual(classify_parameter("q"), "search")
        self.assertEqual(classify_parameter("template"), "template")
        self.assertEqual(classify_parameter("quantity"), "numeric")
        self.assertEqual(classify_parameter("unknownparam"), "generic")

    def test_implications(self):
        self.assertIn("ssrf", implications_for_class("url"))
        self.assertIn("path_traversal", implications_for_class("file"))
        self.assertIn("ssti", implications_for_class("template"))


class TestEventBus(unittest.TestCase):
    def test_publish_subscribe(self):
        eb = EventBus()
        received = []
        eb.subscribe("DISCOVERY_NEW_API", lambda e: received.append(e))
        eb.publish("DISCOVERY_NEW_API", endpoint="/api/x")
        self.assertEqual(len(received), 1)
        self.assertTrue(eb.has_event("DISCOVERY_NEW_API"))
        self.assertEqual(eb.events_of("DISCOVERY_NEW_API")[0]["endpoint"], "/api/x")


class TestAttackQueue(unittest.TestCase):
    def test_priority_order(self):
        q = AttackQueue()
        q.add("ssrf", relevance=0.9, surface=0.8, confidence=0.8,
              impact=0.9, exploitability=0.8)
        q.add("xss", relevance=0.3, surface=0.2, confidence=0.6,
              impact=0.8, exploitability=0.6)
        items = q.sorted()
        self.assertEqual(items[0]["module"], "ssrf")
        self.assertGreater(items[0]["priority"], items[1]["priority"])

    def test_boost_and_demote(self):
        q = AttackQueue()
        q.add("bola", relevance=0.5, surface=0.5)
        before = q.score("bola")
        q.boost("bola", 1.0)
        boosted = q.score("bola")
        self.assertGreater(boosted, before)
        q.demote("bola")
        q.demote("bola")
        self.assertLess(q.score("bola"), boosted)

    def test_disable(self):
        q = AttackQueue()
        q.add("x", relevance=1.0, surface=1.0, impact=1.0)
        q.disable("x")
        self.assertEqual(q.sorted(), [])


class TestAttackChains(unittest.TestCase):
    def _mk(self, title, sev, endpoint, potential=False):
        return Finding(title=title, severity=sev, confidence=90, target="x",
                       endpoint=endpoint, module="t", potential=potential)

    def test_chain_requires_two_distinct(self):
        f = self._mk("Same issue", Severity.HIGH, "/api/x")
        self.assertEqual(build_chains([f, f]), [])

    def test_chain_builds_path(self):
        f1 = self._mk("Weak auth", Severity.LOW, "/login")
        f2 = self._mk("IDOR", Severity.HIGH, "/login")
        chains = build_chains([f1, f2])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].overall_risk, Severity.HIGH)
        self.assertIn("Weak auth", chains[0].render_ascii())

    def test_chain_excludes_info(self):
        f1 = self._mk("Info thing", Severity.INFO, "/x")
        f2 = self._mk("Real bug", Severity.HIGH, "/x")
        self.assertEqual(build_chains([f1, f2]), [])


class TestRulesEngine(unittest.TestCase):
    def test_rules_file_parses(self):
        g = AttackGraph(root="x")
        eb = EventBus()
        r = RulesEngine(g, eb)
        self.assertGreaterEqual(len(r.rules), 1)  # rules.yaml loaded

    def test_action_mapping(self):
        g = AttackGraph(root="x")
        eb = EventBus()
        r = RulesEngine(g, eb)
        actions = {"enable_ssrf": 1.0, "prioritize_api": 1.0}
        mods = r.action_to_modules(actions)
        self.assertIn("ssrf", mods)
        self.assertIn("api", mods)
        self.assertGreater(mods["api"], mods["ssrf"])  # prioritize boosts more


if __name__ == "__main__":
    unittest.main()
