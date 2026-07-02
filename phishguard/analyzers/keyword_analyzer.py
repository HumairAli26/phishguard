"""
keyword_analyzer.py
--------------------
Scans the subject + body for the cognitive-trigger phrase banks defined in
data/trigger_keywords.json (Urgency, Authority, Fear/Greed, Curiosity,
Bypass/Secrecy, Credential Harvesting, Financial Request, MFA Fatigue).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "trigger_keywords.json"

with open(DATA_FILE, "r", encoding="utf-8") as f:
    _TRIGGERS = json.load(f)


@dataclass
class TriggerHit:
    category: str
    phrase: str
    weight: int


@dataclass
class KeywordReport:
    hits: List[TriggerHit] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def score(self) -> int:
        return sum(h.weight for h in self.hits)

    @property
    def triggered_categories(self) -> List[str]:
        return sorted(self.category_counts.keys())


def analyze_keywords(text: str) -> KeywordReport:
    report = KeywordReport()
    lowered = text.lower()

    for category, meta in _TRIGGERS.items():
        weight = meta["weight"]
        for phrase in meta["phrases"]:
            if re.search(re.escape(phrase.lower()), lowered):
                report.hits.append(TriggerHit(category=category, phrase=phrase, weight=weight))
                report.category_counts[category] = report.category_counts.get(category, 0) + 1

    return report
