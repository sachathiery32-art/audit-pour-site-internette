"""Tests for wordlist generation and brute-force loading."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from wordlists import generate_wordlists as gen
from wordlists.names_data import FIRST_NAMES, LAST_NAMES, NATIONALITIES


class TestNameData(unittest.TestCase):
    def test_nationalities_present(self):
        self.assertGreaterEqual(len(NATIONALITIES), 8)
        for nat in NATIONALITIES:
            self.assertIn(nat, FIRST_NAMES)
            self.assertIn(nat, LAST_NAMES)
            self.assertGreaterEqual(len(FIRST_NAMES[nat]), 30)
            self.assertGreaterEqual(len(LAST_NAMES[nat]), 30)

    def test_no_empty_names(self):
        for nat in NATIONALITIES:
            for name in FIRST_NAMES[nat] + LAST_NAMES[nat]:
                self.assertTrue(name.strip(), f"empty name in {nat}")


class TestPatterns(unittest.TestCase):
    def test_name_password_patterns(self):
        pats = gen.name_password_patterns("Marie", "Dupont")
        self.assertIn("marie", pats)
        self.assertIn("Marie123", pats)
        self.assertIn("dupont", pats)
        self.assertIn("mariedupont", pats)
        self.assertTrue(any("marie" in p and "dupont" in p for p in pats))

    def test_name_date_patterns(self):
        pats = gen.name_date_patterns("Marie", "Dupont", 1990, "05", "14")
        self.assertIn("marie1990", pats)
        self.assertIn("Marie1990", pats)
        self.assertIn("dupont1990", pats)
        self.assertIn("mariedupont19900514", pats)
        # modern-ish year must appear as 2-digit too
        self.assertTrue(any("90" in p and "marie" in p.lower() for p in pats))

    def test_date_variants(self):
        v = gen.date_variants(1989, "07", "03")
        self.assertIn("1989", v)
        self.assertIn("89", v)
        self.assertIn("19890703", v)
        self.assertIn("890703", v)

    def test_quality_filter(self):
        self.assertFalse(gen._quality_filter("00"))          # too short
        self.assertFalse(gen._quality_filter("12345"))       # pure short digits
        self.assertFalse(gen._quality_filter("aaaa"))        # repeated char
        self.assertTrue(gen._quality_filter("Marie1989"))    # good
        self.assertTrue(gen._quality_filter("dupont123"))    # good


class TestGenerator(unittest.TestCase):
    def test_build_personal_wordlist_has_combos(self):
        # deterministic seed for stable test
        wl = gen.build_personal_wordlist(count=500, seed=42)
        self.assertGreaterEqual(len(wl), 300)
        joined = "\n".join(wl).lower()
        # must include name+year combos (the whole point)
        self.assertRegex(joined, r"[a-z]+(19|20)[0-9]{2}")
        # must include leet variants
        self.assertTrue(any(any(c in p for c in "01234")
                            and p.replace("0", "o") != p
                            for p in wl))

    def test_build_all_names(self):
        firsts, lasts = gen.build_all_names()
        self.assertGreaterEqual(len(firsts), 300)
        self.assertGreaterEqual(len(lasts), 300)


class TestWordlistFiles(unittest.TestCase):
    def test_generated_files_exist_and_nonempty(self):
        wl_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "wordlists")
        for fname in ("first_names.txt", "last_names.txt", "dates.txt",
                      "personal_top.txt", "personal_good.txt",
                      "personal_passwords.txt", "common_passwords.txt",
                      "common_usernames.txt"):
            path = os.path.join(wl_dir, fname)
            self.assertTrue(os.path.exists(path), f"missing {fname}")
            with open(path, encoding="utf-8") as fh:
                entries = [ln for ln in fh
                           if ln.strip() and not ln.startswith("#")]
            self.assertGreater(len(entries), 0, f"empty {fname}")

    def test_common_passwords_contains_top(self):
        wl_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "wordlists")
        with open(os.path.join(wl_dir, "common_passwords.txt"),
                  encoding="utf-8") as fh:
            content = fh.read()
        for pw in ("123456", "password", "password123", "admin123"):
            self.assertIn(pw, content)


if __name__ == "__main__":
    unittest.main()
