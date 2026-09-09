#!/usr/bin/env python
"""Generate real-world brute-force wordlists, French-first.

Sources (curated copies in wordlists/data/):
- n0kovo real name lists: first_names_male/female_2021, last_names_2021
  (62k + 80k first names, 297k last names, international)
- French leaked-password lists: top-5000 / top-20000 / Pwdb-150
- French vocabulary: lang-french-full.txt, moby-french.txt
- Our own curated common_passwords.txt + names_data.py

Generation strategy (ordered by attack value):
1. Real French password lists merged (base layer)
2. Real names -> classic patterns: Name123, Prénom.Nom, initials
3. Name + year / full birth date  (prenom1992, NOM1987, prenom.nom1992)
4. Capitalized + leet + separators (. _ - @) variants
5. Email-style candidates: prenom.nom@domain, p.nom@domain
6. Mixed combos: Pàssw0rd style, majority French words

Outputs:
    wordlists/french_real_passwords.txt  (real French leaked passwords)
    wordlists/french_combos.txt          (names + dates + @ generations)
    wordlists/french_master.txt          (merged, deduped master list)
"""
from __future__ import annotations

import os
import random
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

random.seed()

# ------------------------------------------------------------------ paths
# Curated data lives in wordlists/data/ (extracted from the SecLists and
# Probable-Wordlists clones, which are no longer needed on disk).
DATA = os.path.join(_HERE, "data")
NAMES_DIR = os.path.join(DATA, "names")
PW_DIR = os.path.join(DATA, "passwords")

_FR_LISTS = [
    os.path.join(PW_DIR, "French_Pwdb_common-password-list-top-150.txt"),
    os.path.join(PW_DIR, "French-common-password-list-top-5000.txt"),
    os.path.join(PW_DIR, "French-common-password-list-top-20000.txt"),
]
_NAME_FILES = {
    "first_male": os.path.join(NAMES_DIR, "first_names_male_2021.txt"),
    "first_female": os.path.join(NAMES_DIR, "first_names_female_2021.txt"),
    "last": os.path.join(NAMES_DIR, "last_names_2021.txt"),
}


def _read_lines(path: str, limit: int | None = None) -> list:
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                out.append(line)
                if limit and len(out) >= limit:
                    break
    except Exception:
        pass
    return out


def load_real_data() -> dict:
    """Load French words + n0kovo names into a handy dict."""
    french = []
    for p in _FR_LISTS:
        french.extend(_read_lines(p))
    french = list(dict.fromkeys(french))

    male = _read_lines(_NAME_FILES["first_male"])
    female = _read_lines(_NAME_FILES["first_female"])
    lasts = _read_lines(_NAME_FILES["last"])

    return {"french": french, "male": male, "female": female,
            "lasts": lasts}


# ------------------------------------------------------------------ years
def _years() -> list:
    out = []
    for y in range(1940, 2012):
        out.append(str(y))
        out.append(str(y)[-2:])
    # hot recent years heavy-weighted for the *common* tier
    out += [str(y) for y in range(1975, 2006) for _ in range(3)]
    return out


def _full_dates() -> list:
    out = []
    for y in range(1950, 2006):
        out.append(f"{y}0101")
    # realistic month/day combos
    months = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
    days = ["01", "05", "10", "12", "15", "16", "17", "18", "20", "21", "22", "23", "24", "25", "28"]
    for y in (range(1960, 2006)):
        yy = str(y)
        y2 = yy[-2:]
        for m in months[:6]:
            for d in days[:8]:
                out.append(yy + m + d)
                out.append(y2 + m + d)
                out.append(d + m + y2)
                out.append(m + y2)
    return list(dict.fromkeys(out))


# ------------------------------------------------------------------ helpers
def _norm(name: str) -> str:
    return name.lower().replace(" ", "").replace("'", "").replace("-", "")


def _cap(name: str) -> str:
    return name[:1].upper() + name[1:]


def _leet(name: str) -> str:
    table = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7",
             "b": "8", "g": "9"}
    return "".join(table.get(c, c) for c in name.lower())


_SPECIALS = ["@", ".", "_", "-"]


# ------------------------------------------------------------------ combos
def french_word_variants(word: str) -> list:
    """Password variants of a single French word."""
    w = word.lower()
    out = {w}
    c = _cap(w)
    out.add(c)
    for suf in ("1", "12", "123", "1234", "!", "!!", "1!", "123!", "69", "96",
                "07", "00", "99", "42", "77", "2000", "2010", "2020", "2024",
                "azerty", "du59", "du62", "du75", "du13", "du69"):
        out.add(w + suf)
        out.add(c + suf)
    out.add(_leet(w))
    out.add(_leet(w) + "123")
    out.add(c + "@" + "1")
    out.add(w + "@" + "1")
    out.add(_cap(w + "s"))
    return list(out)


def name_date_patterns(first: str, last: str, y: str, y2: str,
                       fulldate: str) -> list:
    """Name + birth-date / year combos, with @ and capitals.

    Compact: skips obviously-weak names and keeps each pair's highest
    value candidates so the total stays manageable.
    """
    first = first.strip()
    last = last.strip()
    f = _norm(first)
    l = _norm(last)
    if len(f) < 3 or len(l) < 3 or len(set(f)) < 2 or len(set(l)) < 2:
        return []
    # capitalized without spaces (Jean Pierre -> Jeanpierre)
    fc = _cap(first).replace(" ", "").replace("'", "").replace("-", "")
    lc = _cap(last).replace(" ", "").replace("'", "").replace("-", "")
    fi = first[0].lower()
    FIi = first[0].upper()

    out = set()
    # first/name + year
    out.update([f + y, fc + y, l + y, lc + y,
                f + y2, fc + y2, l + y2, lc + y2])
    # full birth date + name (top value)
    out.update([f + fulldate, fc + fulldate, l + fulldate, lc + fulldate])
    # separators + year (just the strong ones)
    out.update([f + "." + l + y, fc + "." + lc + y, f + "_" + l + y,
                fc + lc + y, lc + fc + y, fc + lc + fulldate])
    # name.name@year + email style
    out.add(f + "." + l + "@" + y)
    out.add(fc + "." + lc + "@" + y)
    out.add(fc + lc + "@" + y)
    out.add(f + "." + l + "@gmail.com")
    out.add(f + "." + l + "@orange.fr")
    out.add(f + "." + l + "@free.fr")
    # initial variants + leet
    out.update([fi + l + y, FIi + lc + y, fi + "." + l + y, FIi + "." + lc + y,
                _leet(f) + y, _leet(l + y), _leet(f + l) + y])
    # modern flair
    out.update([fc + "@" + y, fc + "!" + y, fc + lc + "@" + y,
                fc + lc + "!" + y])
    return list(out)


def email_style(first: str, last: str, year: str) -> list:
    f = _norm(first)
    l = _norm(last)
    fc = _cap(first)
    lc = _cap(last)
    fi = first[0].lower()
    FIi = first[0].upper()
    out = set()
    for dom in ("gmail.com", "orange.fr", "free.fr", "hotmail.fr", "sfr.fr",
                "laposte.net", "wanadoo.fr", "yahoo.fr"):
        for combo in (f + "." + l, f + l, fi + "." + l, FIi + l,
                      fi + l, l + "." + f, fc + "." + lc, f + "_" + l):
            out.add(combo + "@" + dom)
            out.add(combo + year + "@" + dom)
    return list(out)


# ------------------------------------------------------------------ french names
# Real French surnames (curated — deterministic and reliable).
_FR_LASTNAMES = """
Martin Bernard Dubois Thomas Robert Richard Petit Durand Leroy Moreau
Simon Laurent Lefebvre Michel Garcia David Bertrand Roux Vincent Fournier
Morel Girard André Lefèvre Mercier Dupont Lambert Bonnet François Martinez
Legrand Garnier Faure Rousseau Blanc Muller Henry Roussel Nicolas Perrin
Morin Mathieu Clément Gauthier Dumont Rousseau Lefèvre Chevalier
Renard Aubert Vasseur Boyer Klein Roger Berard Roy Jourdan Clement Noel
Gautier Masson Marchal Dufour Deschamps Guerin Meunier Blanchard Camus
Brun Charpentier Menard Denis Caron Mallet Benoit Fabre Schmitt Leroux
Colin Vidal Carpentier Lemoine Rivière Delattre Delmas Dupuis Fauconnier
Gaillard Barbier Arnaud Marchand Lefort Regnier Picard Henry
Chauvin Lemaire Dijoux Gros Barre Torre Ruiz Fontaine Aubert
Brunet Rattier Guillot Raynaud Legros Carré Grimaud Chretien
Gregoire Delaunay Paquet Delcourt Blandin Roche Desrosiers
Boulanger Fleury Chatelain Rocher Pichon Tessier Perrot Davy
""".split()

_ACCENTS = "àâçéèêëîïôùûüÿœ"


def _french_score(name: str) -> int:
    """Heuristic for FIRST names: penalize long / foreign-looking ones."""
    n = name.lower().strip()
    score = 0
    if any(c in n for c in _ACCENTS):
        score += 1
    if len(n) <= 9:
        score += 1  # typical French first-name length
    if len(n) > 11:
        score -= 2
    if re.search(r"(zh|wz|xq|qj|xj|sch|ck|ph|thw|aa|uu|yy|kz|qz|wj)", n):
        score -= 4
    return score


def _french_like(name: str, threshold: int = 0) -> bool:
    # short names (3-9) that aren't obviously foreign pass;
    # long/exotic ones are rejected
    return 3 <= len(name) <= 9 and _french_score(name) >= threshold


def names_from_french_wordlist(french_words: list) -> list:
    """Extract real French given/family names embedded in the leak lists.

    The French top-20000 contains hundreds of first names used as
    passwords (nicolas, thomas, julien, camille...). Words that appear
    often and look like names become our French name corpus.
    """
    from collections import Counter
    counts = Counter()
    for w in french_words:
        w = w.strip().lower()
        if not re.fullmatch(r"[a-zàâçéèêëîïôùûüÿ'-]{3,20}", w):
            continue
        if w in ("password", "azerty", "bonjour", "motdepasse", "coucou",
                 "jetaime", "princesse", "maison", "chocolat", "secret",
                 "papillon", "voiture", "nounours", "louloute", "mamour",
                 "amour", "france", "soleil", "chouchou", "caramel"):
            continue
        # must look like a name: capitalize-able, no French stop words
        counts[w] += 1
    # keep words seen >= 2 times (strong signal) or top-frequency
    common = [w for w, c in counts.items() if c >= 2]
    ranked = sorted(common, key=lambda w: (-counts[w], w))
    return ranked


# ------------------------------------------------------------------ ranks
def _quality(c: str) -> bool:
    """Strict plausibility filter."""
    if len(c) < 4 or len(c) > 40:
        return False
    if len(set(c)) == 1:
        return False
    # repeated digits-only runs of 6+ are junk (0000001@1)
    if re.fullmatch(r"[0-9]{6,}.*", c):
        return False
    # names that are 1-2 repeated letters (Aaaa2000)
    if re.match(r"^([a-z])\1{2,}[0-9@!._\-]*$", c.lower()):
        return False
    # must contain at least one letter
    if not re.search(r"[a-zA-Z]", c):
        return False
    return True


def _build_name_re(firsts: list, lasts: list):
    """One compiled regex matching any real name token (C-speed search)."""
    tokens = list(dict.fromkeys(
        t for t in ({_norm(t) for t in firsts} | {_norm(t) for t in lasts})
        if 4 <= len(t) <= 14))
    if not tokens:
        return re.compile(r"(?!x)x")
    # longest-first for alternation correctness
    tokens.sort(key=len, reverse=True)
    return re.compile("|".join(re.escape(t) for t in tokens))


def _is_leet(low: str) -> bool:
    name_part = re.sub(r"(19|20)[0-9]{2}$", "", low)
    return any(ch in name_part for ch in "01234")


def rank_candidates(flat: set, firsts: list, lasts: list,
                    priority_tokens: set | None = None) -> dict:
    """Split into top / good / full by plausibility.

    Tier assignment:
    - top   : real name + 4-digit year, non-leet, ASCII letters first.
              Candidates containing a priority token (extracted FR first
              name) get promoted to the top of the top tier.
    - good  : real name + short pattern, non-leet
    - full  : everything else plausible

    Sort key: longest real-name match wins (Alexandre1992 before Bent96).
    """
    name_re = _build_name_re(firsts, lasts)
    prio_re = None
    if priority_tokens:
        pt = list(dict.fromkeys(
            t for t in priority_tokens if 4 <= len(t) <= 14))
        if pt:
            pt.sort(key=len, reverse=True)
            prio_re = re.compile("|".join(re.escape(t) for t in pt))
    # longest token length per candidate for ranking
    tokens = list(dict.fromkeys(
        t for t in ({_norm(x) for x in firsts} | {_norm(x) for x in lasts})
        if 4 <= len(t) <= 20))
    tokens.sort(key=len, reverse=True)
    token_re = re.compile("|".join(re.escape(t) for t in tokens))

    top, good, full = [], [], []
    for c in flat:
        if not _quality(c):
            continue
        low = c.lower()
        m = token_re.search(low)
        has_real = bool(m)
        name_len = len(m.group(0)) if m else 0
        is_prio = bool(prio_re and prio_re.search(low))
        if has_real and re.search(r"(19|20)[0-9]{2}$", c) and not _is_leet(low):
            top.append((0 if is_prio else 1, -name_len, c))
        elif has_real and len(c) <= 16 and not _is_leet(low):
            good.append((0 if is_prio else 1, -name_len, c))
        else:
            full.append((0 if is_prio else 1, -name_len, c))

    def _sort_key(item):
        prio, name_len, c = item
        low = c.lower()
        return (prio, len(c), name_len, 0 if re.match(r"^[a-z]", low) else 1, c)

    def _clean(tups):
        ordered = [c for _, _, c in sorted(tups, key=_sort_key)]
        # deterministic interleave for diversity: quality order preserved,
        # but consecutive same-prefix entries (Alain1940..Alain1965) get
        # spread out so the first N lines sample many different names.
        rng = random.Random(7)
        bucketed: dict = {}
        for c in ordered:
            key = _norm(re.sub(r"[0-9!@._\\-].*$", "", c))
            bucketed.setdefault(key, []).append(c)
        names = sorted(bucketed.keys())
        # round-robin across buckets until everything is consumed
        merged = []
        while bucketed:
            for key in list(bucketed):
                merged.append(bucketed[key].pop(0))
                if not bucketed[key]:
                    del bucketed[key]
        return merged

    return {"top": _clean(top), "good": _clean(good), "full": _clean(full)}


# ------------------------------------------------------------------ main
def build_french_master(seed: int = 42, max_names: int = 2000,
                        max_combos_tier: int = 12000) -> dict:
    """Build the merged lists. Returns tiers + master."""
    data = load_real_data()
    french = data["french"]
    male = data["male"] or []
    female = data["female"] or []
    lasts = data["lasts"] or []

    # --- real French names extracted from the leaked FR passwords ---
    fr_name_tokens = names_from_french_wordlist(french)
    fr_names = [n for n in fr_name_tokens if _french_like(n)] or fr_name_tokens
    # keep plausible name lengths only (single names, 3-12 chars)
    fr_names = [n for n in fr_names if 3 <= len(n) <= 12]
    male = [n for n in male if 3 <= len(n) <= 12]
    female = [n for n in female if 3 <= len(n) <= 12]
    lasts = [n for n in lasts if 3 <= len(n) <= 14]

    # --- French-first subsets of the real n0kovo names (fallback pool) ---
    # surnames: exclude Nordic/Germanic endings that leak through
    _NORTH_E = re.compile(r"(sen|sson|dottir|berg|land|gaard|gaard|qvist|strom|ström|rud|lund|holm|stad|borg|foss|vik|heim)$", re.IGNORECASE)
    rng = random.Random(seed)
    fr_male = [n for n in male if _french_like(n)]
    fr_female = [n for n in female if _french_like(n)]
    # surnames: strong French score only (>=4) + reject Nordic/Germanic,
    # + reject obvious foreign multisyllable artifacts (won't help FR targets)
    fr_last = [n for n in lasts
               if 4 <= len(n) <= 12
               and _french_score(n) >= 4
               and not _NORTH_E.search(n)]
    if len(fr_last) < 300:
        fr_last = [n for n in lasts if _french_like(n) and not _NORTH_E.search(n)]
    sample_male = rng.sample(fr_male, min(max_names, len(fr_male)))
    sample_female = rng.sample(fr_female, min(max_names, len(fr_female)))
    sample_last = rng.sample(fr_last, min(max_names, len(fr_last)))

    # firsts = extracted FR names (best signal) FIRST, n0kovo as fallback
    first_pool = list(fr_names) + sample_male + sample_female
    if not first_pool:
        first_pool = sample_male + sample_female
    # last names = curated real French surnames + n0kovo FR-ish leftovers
    last_pool = list(_FR_LASTNAMES) + [n for n in fr_names if len(n) >= 5]
    if len(last_pool) < 200:
        last_pool += sample_last
    last_pool = list(dict.fromkeys(last_pool))
    firsts = first_pool
    # Pool split: FR-extracted names get ~2/3 of the generation budget
    n_fr_first = len(fr_names)
    fr_first_pool = list(fr_names)
    n0k_first_pool = sample_male + sample_female
    # real FR first-name tokens for ranking priority
    fr_first_tokens = set(fr_names)

    years = _years()
    fulldates = _full_dates()
    flat: set = set()

    # tier 1: French word variants from the *real* list (limited, clean)
    for w in french[:800]:
        if re.match(r"^[0-9]{3,}$", w):
            continue  # skip pure digits, noise already in common list
        if re.match(r"^([a-z])\1{2,}$", w.lower()):
            continue  # single repeated letter
        flat.update(french_word_variants(w))

    # tier 2: name + date / @ generations
    # 2/3 of the budget uses the real French extracted names,
    # 1/3 samples the n0kovo French-like pool for breadth.
    for i in range(max_combos_tier):
        if n_fr_first and i % 3 != 2:
            first = rng.choice(fr_first_pool)
        else:
            first = rng.choice(n0k_first_pool) if n0k_first_pool else rng.choice(firsts)
        last = rng.choice(last_pool)
        y = rng.choice(years)
        y2 = y[-2:]
        fd = rng.choice(fulldates)
        flat.update(name_date_patterns(first, last, y, y2, fd))
        if rng.random() < 0.2:
            flat.update(email_style(first, last, y))

    tiers = rank_candidates(flat, firsts, last_pool,
                            priority_tokens=fr_first_tokens)
    real = list(dict.fromkeys(french))
    master = list(dict.fromkeys(real + tiers["full"]))
    return {"real": real, "tiers": tiers, "master": master, "names": firsts,
            "last_names": last_pool}


def main() -> None:
    out_dir = _HERE
    data = load_real_data()
    print(f"Loaded {len(data['french'])} French passwords "
          f"({len(data['male'])} male names, {len(data['female'])} female names, "
          f"{len(data['lasts'])} last names)")

    built = build_french_master()
    tiers = built["tiers"]

    with open(os.path.join(out_dir, "french_real_passwords.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# Real French leaked passwords (curated from language-specific lists)\n")
        fh.write("\n".join(built["real"]) + "\n")

    with open(os.path.join(out_dir, "french_top.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# French tier-1 candidates: real name + year, non-leet\n")
        fh.write("\n".join(tiers["top"][:10000]) + "\n")

    with open(os.path.join(out_dir, "french_good.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# French tier-2 candidates: real name patterns\n")
        fh.write("\n".join(tiers["good"][:30000]) + "\n")

    with open(os.path.join(out_dir, "french_combos.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# Generated French name+date+@ combinations (full tier)\n")
        fh.write("\n".join(tiers["full"]) + "\n")

    with open(os.path.join(out_dir, "french_master.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# French master wordlist: real + generated (authorized testing only)\n")
        fh.write("\n".join(built["master"]) + "\n")

    # also refresh the personal_* name lists from the real n0kovo data
    with open(os.path.join(out_dir, "names_real.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(sorted(set(built["names"]))) + "\n")
    with open(os.path.join(out_dir, "last_names_real.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(sorted(set(built["last_names"]))) + "\n")

    print(f"french_real_passwords.txt: {len(built['real'])}")
    print(f"french_top.txt           : {len(tiers['top'][:10000])}")
    print(f"french_good.txt          : {len(tiers['good'][:30000])}")
    print(f"french_combos.txt        : {len(tiers['full'])}")
    print(f"french_master.txt        : {len(built['master'])}")

    # sample check
    sample = [c for c in tiers["top"]
              if any(t in c.lower() for t in ("@",))][:5]
    print("email-style top sample:", sample)
    print("top sample:", tiers["top"][:6])


if __name__ == "__main__":
    main()