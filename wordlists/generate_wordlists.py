#!/usr/bin/env python
"""Generate personalized password wordlists.

Combines first names, last names, and realistic birth dates (1940-2010,
weighted toward recent decades) into password patterns that people
actually use: Name+year, name.year, firstname123, surname+date, leet
variants, capitalized forms, and birth-date-heavy combinations.

Outputs:
    wordlists/personal_passwords.txt   (name+date combos, the big one)
    wordlists/first_names.txt          (all first names, one per line)
    wordlists/last_names.txt           (all last names, one per line)
    wordlists/dates.txt                (common date formats)

Run manually with:  py wordlists/generate_wordlists.py
It is also invoked by setup/run scripts when the wordlists are missing.
"""
from __future__ import annotations

import os
import random
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from names_data import FIRST_NAMES, LAST_NAMES, NATIONALITIES  # noqa: E402

random.seed()

# ------------------------------------------------------------------ dates
# Birth years weighted toward modern decades (not "too old" per request)
YEAR_WEIGHTS = {y: 1.0 for y in range(1940, 2012)}
for y in range(1970, 2005):  # boost recent years
    YEAR_WEIGHTS[y] = 3.0
for y in range(1985, 2002):  # even stronger for 20-40 year olds
    YEAR_WEIGHTS[y] = 5.0

MONTHS = [str(m).zfill(2) for m in range(1, 13)]
DAYS = [str(d).zfill(2) for d in range(1, 29)]  # avoid invalid dates


def _weighted_year() -> int:
    years = list(YEAR_WEIGHTS.keys())
    weights = [YEAR_WEIGHTS[y] for y in years]
    return random.choices(years, weights=weights, k=1)[0]


def _random_date() -> str:
    y = _weighted_year()
    m = random.choice(MONTHS)
    d = random.choice(DAYS)
    return f"{y:04d}{m}{d}"


def date_variants(y: int, m: str, d: str) -> list:
    """Common date representations people use in passwords."""
    y2 = str(y)[-2:]
    return [
        f"{y:04d}", f"{y2}", f"{y:04d}{m}{d}", f"{y2}{m}{d}",
        f"{y:04d}{m}", f"{m}{y2}", f"{d}{m}{y2}",
        f"{d}/{m}/{y2}", f"{y2}-{m}-{d}", f"{y:04d}-{m}-{d}",
    ]


# ------------------------------------------------------------ name helpers
def _lower(name: str) -> str:
    return name.lower().replace(" ", "").replace("'", "")


def _leet(name: str) -> str:
    table = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
    out = "".join(table.get(c, c) for c in name.lower())
    return out


def _capitalize(name: str) -> str:
    return name.capitalize()


# --------------------------------------------------------------- patterns
def name_password_patterns(first: str, last: str) -> list:
    """Classic name-based password patterns (no date needed)."""
    f = first
    l = last
    fl = _lower(first)
    ll = _lower(last)
    fcaps = _capitalize(first)
    lcaps = _capitalize(last)

    out = set()
    # single names
    out.add(fl); out.add(fcaps); out.add(ll); out.add(lcaps)
    out.add(fcaps + "123"); out.add(lcaps + "123")
    out.add(fl + "123"); out.add(ll + "123")
    out.add(fcaps + "1234"); out.add(lcaps + "1234")
    out.add(fl + "1234"); out.add(ll + "1234")
    # first+last
    out.add(fl + ll); out.add(fcaps + lcaps); out.add(fcaps + ll)
    out.add(fl + lcaps); out.add(ll + fl); out.add(lcaps + fcaps)
    # first.last / first_last / first-first
    out.add(fl + "." + ll); out.add(fl + "_" + ll); out.add(fl + "-" + ll)
    out.add(fl + "@" + ll); out.add(fcaps + "." + lcaps)
    # initial + last
    out.add(first[0].lower() + ll); out.add(first[0].upper() + lcaps)
    out.add(first[0].lower() + lcaps); out.add(first[0].upper() + ll)
    # leet variants
    out.add(_leet(first)); out.add(_leet(last)); out.add(_leet(first + last))
    out.add(_leet(first) + "123"); out.add(_leet(last) + "123")
    # with common suffixes
    for suf in ("1", "12", "123", "1234", "!", "!!", "!", "07", "77",
                "69", "96", "0", "00", "99", "666", "007"):
        out.add(fl + suf); out.add(fcaps + suf)
        out.add(ll + suf); out.add(lcaps + suf)
        out.add(fl + ll + suf); out.add(ll + fl + suf)
    return list(out)


def name_date_patterns(first: str, last: str, y: int, m: str, d: str) -> list:
    """Name + birth-date combinations (the classic weak password)."""
    f = first
    l = last
    fl = _lower(first)
    ll = _lower(last)
    fcaps = _capitalize(first)
    lcaps = _capitalize(last)
    y2 = str(y)[-2:]
    yd = str(y)

    out = set()
    # first + year
    out.add(fl + yd); out.add(fcaps + yd)
    out.add(fl + y2); out.add(fcaps + y2)
    # last + year
    out.add(ll + yd); out.add(lcaps + yd)
    out.add(ll + y2); out.add(lcaps + y2)
    # first.last + year
    out.add(fl + "." + yd); out.add(fl + "_" + yd)
    out.add(fl + ll + yd); out.add(ll + fl + yd)
    out.add(fcaps + lcaps + yd); out.add(fl + ll + y2)
    # full birth date
    out.add(fl + yd + m + d); out.add(fcaps + yd + m + d)
    out.add(ll + yd + m + d); out.add(lcaps + yd + m + d)
    out.add(fl + ll + yd + m + d); out.add(ll + fl + yd + m + d)
    # year only with separators
    out.add(fl + "." + y2); out.add(fl + "/" + y2)
    out.add(fcaps + "." + y2); out.add(ll + "." + y2)
    out.add(ll + "/" + y2); out.add(lcaps + "." + y2)
    out.add(fcaps + lcaps + y2); out.add(fl + ll + "." + y2)
    # with month/day
    out.add(fl + yd + m); out.add(fcaps + yd + m)
    out.add(fl + y2 + m); out.add(fcaps + y2 + m)
    out.add(fl + d + m + y2); out.add(fcaps + d + m + y2)
    out.add(ll + d + m + y2); out.add(lcaps + d + m + y2)
    # leet year variants
    out.add(_leet(first) + yd); out.add(_leet(last) + y2)
    out.add(_leet(first + last) + yd); out.add(_leet(first) + y2)
    return list(out)


# -------------------------------------------------------------- generator
def build_personal_wordlist(count: int = 6000, seed: int | None = None) -> list:
    """Generate `count` personalized candidates across nationalities.

    Uses *element* quotas (not loop iterations) so every category gets
    real representation: ~10% date-only, ~30% name-only, ~60% name+date.
    """
    rng = random.Random(seed)
    out: set = set()

    def _add_until(target: int, producer):
        guard = 0
        while len(out) < target and guard < target * 8 + 100:
            guard += 1
            for item in producer():
                out.add(item)

    # date-only candidates (birthdates as passwords) ~10%
    def _date_prod():
        y = _weighted_year()
        m = rng.choice(MONTHS)
        d = rng.choice(DAYS)
        return date_variants(y, m, d)

    _add_until(count // 10, _date_prod)

    # name-based (no date) ~30%
    def _name_prod():
        nat = rng.choice(NATIONALITIES)
        first = rng.choice(FIRST_NAMES[nat])
        last = rng.choice(LAST_NAMES[nat])
        return name_password_patterns(first, last)

    _add_until(count * 3 // 10, _name_prod)

    # name + date combos (the meat) ~60%
    def _combo_prod():
        nat = rng.choice(NATIONALITIES)
        first = rng.choice(FIRST_NAMES[nat])
        last = rng.choice(LAST_NAMES[nat])
        y = _weighted_year()
        m = rng.choice(MONTHS)
        d = rng.choice(DAYS)
        return name_date_patterns(first, last, y, m, d)

    _add_until(count, _combo_prod)

    return sorted(out)


def build_all_names() -> tuple:
    firsts = sorted({f for names in FIRST_NAMES.values() for f in names})
    lasts = sorted({l for names in LAST_NAMES.values() for l in names})
    return firsts, lasts


def _quality_filter(candidate: str) -> bool:
    """Drop noisy/implausible candidates."""
    if len(candidate) < 4:
        return False
    if len(candidate) > 32:
        return False
    # pure digits shorter than 6 are too generic (already in common list)
    if candidate.isdigit() and len(candidate) < 6:
        return False
    # single repeated char
    if len(set(candidate)) == 1:
        return False
    return True


def _ranked(personal: list, firsts: list, lasts: list, dates: list) -> dict:
    """Split the personal list into ranked tiers by plausibility."""
    # real-name tokens (lowercased, accents stripped) for matching
    name_tokens = {f.lower() for f in firsts} | {l.lower() for l in lasts}
    name_tokens = {t.replace("'", "").replace(" ", "") for t in name_tokens}

    def _has_real_name(low: str) -> bool:
        return any(t in low for t in name_tokens if len(t) >= 4)

    def _is_leet(low: str) -> bool:
        # leet digits are 0-4 replacing letters in the NAME part;
        # a trailing birth year (19xx/20xx) is not leet
        name_part = re.sub(r"(19|20)[0-9]{2}$", "", low)
        return any(ch in name_part for ch in "01234")

    top, good, full = [], [], []
    for c in sorted(set(personal)):
        if not _quality_filter(c):
            continue
        low = c.lower()
        # strongest: real name + full 4-digit year, non-leet (e.g. Marie1989)
        if (re.search(r"\d{4}$", c) and _has_real_name(low) and not _is_leet(low)):
            top.append(c)
        # second tier: real name + 2-digit year or name+common suffix
        elif (len(c) <= 12 and _has_real_name(low) and not _is_leet(low)):
            good.append(c)
        # third tier: everything else plausible (leet, date-only, combos)
        else:
            full.append(c)
    return {"top": sorted(top), "good": sorted(good), "full": sorted(full)}


def main() -> None:
    out_dir = _HERE
    firsts, lasts = build_all_names()

    # first_names.txt / last_names.txt / dates.txt
    with open(os.path.join(out_dir, "first_names.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(firsts) + "\n")
    with open(os.path.join(out_dir, "last_names.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(lasts) + "\n")
    with open(os.path.join(out_dir, "dates.txt"), "w",
              encoding="utf-8") as fh:
        dates = set()
        for _ in range(2000):
            y = _weighted_year()
            m = random.choice(MONTHS)
            d = random.choice(DAYS)
            dates.update(date_variants(y, m, d))
        fh.write("\n".join(sorted(d for d in dates if _quality_filter(d))) + "\n")

    # personal_passwords.txt — big generated list, quality-filtered
    personal = build_personal_wordlist(count=12000)
    tiers = _ranked(personal, firsts, lasts, dates)

    with open(os.path.join(out_dir, "personal_passwords.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# AutoSecAudit generated personal-password wordlist\n")
        fh.write("# Names + birth dates + common patterns (authorized testing only)\n")
        fh.write("\n".join(tiers["full"]) + "\n")

    # personal_top.txt — most plausible name+year combos (small)
    with open(os.path.join(out_dir, "personal_top.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# Highest-probability personalized candidates\n")
        fh.write("\n".join(tiers["top"][:2000]) + "\n")

    # personal_good.txt — medium tier
    with open(os.path.join(out_dir, "personal_good.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("# Medium-tier personalized candidates\n")
        fh.write("\n".join(tiers["good"][:5000]) + "\n")

    print(f"first_names.txt      : {len(firsts)} names")
    print(f"last_names.txt       : {len(lasts)} names")
    print(f"dates.txt            : generated")
    print(f"personal_passwords.txt: {len(tiers['full'])} candidates")
    print(f"personal_top.txt     : {len(tiers['top'][:2000])} candidates")
    print(f"personal_good.txt    : {len(tiers['good'][:5000])} candidates")


if __name__ == "__main__":
    main()
