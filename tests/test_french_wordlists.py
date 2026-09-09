"""Tests for the French-first wordlist generator."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "wordlists"))

import unittest

import generate_french as gf


class TestFrenchHelpers(unittest.TestCase):

    def test_french_surnames_curated(self):
        self.assertIn("Martin", gf._FR_LASTNAMES)
        self.assertIn("Dupont", gf._FR_LASTNAMES)
        self.assertIn("Rivière", gf._FR_LASTNAMES)
        self.assertGreater(len(gf._FR_LASTNAMES), 100)

    def test_french_like_shapes(self):
        # accepts short accent-bearing names, rejects long foreign ones
        self.assertTrue(gf._french_like("Marie"))
        self.assertTrue(gf._french_like("Riviere"))  # no accents, short
        self.assertFalse(gf._french_like("Fjellbirkeland"))
        self.assertFalse(gf._french_like("AdrianCristianEduard"))

    def test_names_from_french_wordlist(self):
        words = ["nicolas", "nicolas", "thomas", "thomas", "julien", "julien",
                 "camille", "camille", "password", "azerty", "maison",
                 "bonjour"]
        names = gf.names_from_french_wordlist(words)
        self.assertIn("nicolas", names)
        self.assertIn("julien", names)
        # non-name stop words excluded
        self.assertNotIn("password", names)
        self.assertNotIn("azerty", names)

    def test_name_date_patterns_contains_at_and_year(self):
        pats = gf.name_date_patterns("Jean", "Dupont", "1990", "90", "19900501")
        rejoined = "|".join(pats)
        self.assertIn("1990", rejoined)
        self.assertIn("jean", rejoined.lower())
        self.assertIn("@", rejoined)

    def test_quality_filter_rejects_junk(self):
        self.assertFalse(gf._quality("0000001@1"))
        self.assertFalse(gf._quality("Aaaa2000"))
        self.assertTrue(gf._quality("Alexandre1992"))


class TestFrenchGenerator(unittest.TestCase):

    def test_master_contains_french_words_and_combos(self):
        # bounded sample for CI speed: rely on build_french_master quickly
        built = gf.build_french_master(seed=1, max_names=100,
                                       max_combos_tier=500)
        tiers = built["tiers"]
        self.assertTrue(tiers["top"] or tiers["good"] or tiers["full"])
        # real leak list should load from disk
        real = built["real"]
        self.assertGreater(len(real), 0)


if __name__ == "__main__":
    unittest.main()