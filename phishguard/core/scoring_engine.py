"""
scoring_engine.py
-------------------
Combines the outputs of every analyzer module into a single weighted risk
score, then maps that score onto the decision tree required by the
project brief:

    Incoming Suspicious Email
            |
    ----------------------
    Safe | Suspicious | Malicious
      |         |            |
   Close   Warn User   Block & Escalate
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any

from phishguard.core.email_parser import ParsedEmail
from phishguard.analyzers.header_analyzer import analyze_headers, HeaderReport
from phishguard.analyzers.url_analyzer import analyze_urls, UrlReport
from phishguard.analyzers.keyword_analyzer import analyze_keywords, KeywordReport
from phishguard.analyzers.attachment_analyzer import analyze_attachments, AttachmentReport


VERDICT_THRESHOLDS = {
    "SAFE": (0, 24),
    "SUSPICIOUS": (25, 59),
    "MALICIOUS": (60, 10_000),
}

ACTION_MAP = {
    "SAFE": "Close",
    "SUSPICIOUS": "Warn User",
    "MALICIOUS": "Block Domain & Escalate",
}


@dataclass
class TriageResult:
    email_subject: str
    from_address: str
    total_score: int
    verdict: str
    action: str
    header_report: HeaderReport
    url_report: UrlReport
    keyword_report: KeywordReport
    attachment_report: AttachmentReport
    all_red_flags: List[Dict[str, Any]] = field(default_factory=list)

    def red_flag_summary(self) -> Dict[str, int]:
        """Category -> count, used for the dashboard pie chart."""
        summary: Dict[str, int] = {}
        for flag in self.all_red_flags:
            cat = flag.get("category", "other")
            summary[cat] = summary.get(cat, 0) + 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.email_subject,
            "from": self.from_address,
            "score": self.total_score,
            "verdict": self.verdict,
            "action": self.action,
            "red_flags": self.all_red_flags,
        }


def verdict_for_score(score: int) -> str:
    for verdict, (low, high) in VERDICT_THRESHOLDS.items():
        if low <= score <= high:
            return verdict
    return "MALICIOUS"


def triage_email(pe: ParsedEmail, expected_domain: str = "") -> TriageResult:
    header_report = analyze_headers(pe, expected_domain=expected_domain)
    url_report = analyze_urls(pe.urls)
    keyword_report = analyze_keywords(pe.subject + "\n" + pe.body_text)
    attachment_report = analyze_attachments(pe.attachments)

    total_score = (
        header_report.score
        + url_report.score
        + keyword_report.score
        + attachment_report.score
    )
    # Cap for display sanity; still fully reflects severity ordering
    total_score = min(total_score, 150)

    verdict = verdict_for_score(total_score)
    action = ACTION_MAP[verdict]

    all_flags: List[Dict[str, Any]] = []
    for f in header_report.findings:
        all_flags.append({"category": "Header", "code": f.code, "title": f.title,
                           "detail": f.detail, "severity": f.severity, "weight": f.weight})
    for f in url_report.findings:
        all_flags.append({"category": "URL", "code": f.code, "title": f.title,
                           "detail": f.detail, "severity": f.severity, "weight": f.weight,
                           "url": f.url})
    for h in keyword_report.hits:
        all_flags.append({"category": "Psychological Trigger", "code": h.category,
                           "title": f"Trigger phrase: '{h.phrase}'",
                           "detail": f"Matched under the '{h.category}' trigger category.",
                           "severity": "medium", "weight": h.weight})
    for f in attachment_report.findings:
        all_flags.append({"category": "Attachment", "code": f.code, "title": f.title,
                           "detail": f.detail, "severity": f.severity, "weight": f.weight,
                           "filename": f.filename})

    # Sort worst-first for readability
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_flags.sort(key=lambda x: severity_rank.get(x["severity"], 4))

    return TriageResult(
        email_subject=pe.subject,
        from_address=pe.from_address,
        total_score=total_score,
        verdict=verdict,
        action=action,
        header_report=header_report,
        url_report=url_report,
        keyword_report=keyword_report,
        attachment_report=attachment_report,
        all_red_flags=all_flags,
    )
