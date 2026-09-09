"""Dynamic attack queue.

Every candidate test gets a priority score:

    priority = relevance × attack_surface × confidence × impact × exploitability

The queue is modified in real time: discoveries add tests, findings
boost or demote them, and the scanner always runs the highest-priority
tests first.
"""
from __future__ import annotations

from typing import Dict, List, Optional


class AttackQueue:
    """Priority-sorted queue of test candidates."""

    def __init__(self):
        self._items: Dict[str, dict] = {}  # module_key -> item

    def add(self, module_key: str, **meta) -> None:
        """Add or update a candidate test."""
        item = self._items.setdefault(module_key, {
            "module": module_key, "relevance": 0.0, "surface": 0.0,
            "confidence": 0.5, "impact": 0.5, "exploitability": 0.5,
            "enabled": True,
        })
        for k, v in meta.items():
            if k in item:
                item[k] = max(item[k], v) if isinstance(v, (int, float)) else v

    def boost(self, module_key: str, factor: float) -> None:
        if module_key in self._items:
            self._items[module_key]["relevance"] = max(
                self._items[module_key]["relevance"], factor)

    def demote(self, module_key: str) -> None:
        if module_key in self._items:
            self._items[module_key]["exploitability"] *= 0.5

    def remove(self, module_key: str) -> None:
        self._items.pop(module_key, None)

    def disable(self, module_key: str) -> None:
        if module_key in self._items:
            self._items[module_key]["enabled"] = False

    def score(self, module_key: str) -> float:
        it = self._items.get(module_key)
        if not it:
            return 0.0
        return (it["relevance"] * it["surface"] * it["confidence"]
                * it["impact"] * it["exploitability"])

    def sorted(self) -> List[dict]:
        """Return enabled candidates sorted by priority (highest first)."""
        out = []
        for it in self._items.values():
            if not it["enabled"]:
                continue
            it["priority"] = round(self.score(it["module"]), 3)
            out.append(it)
        out.sort(key=lambda x: x["priority"], reverse=True)
        return out

    def top(self, n: int = 5) -> List[dict]:
        return self.sorted()[:n]

    def keys(self) -> List[str]:
        return list(self._items.keys())

    def render(self, n: int = 8) -> str:
        """Human-readable queue display for the CLI."""
        lines = ["Dynamic Attack Queue"]
        items = self.sorted()
        if not items:
            lines.append("  (empty)")
            return "\n".join(lines)
        for i, it in enumerate(items[:n], 1):
            lines.append(
                f"  {i}. {it['module'].upper():<18} "
                f"prio={it['priority']:.2f} "
                f"(impact {it['impact']:.2f}, surface {it['surface']:.2f})"
            )
        return "\n".join(lines)
