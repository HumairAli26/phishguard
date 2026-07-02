"""
header_analyzer.py
-------------------
Implements Red Flag 1 (Sender-Domain Mismatch), Red Flag 2 (Fake Forwarded
Chains), and authentication-protocol checks (SPF/DKIM/DMARC), matching the
"Attackers weaponize trust through email header manipulation" slide.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
import re

from phishguard.core.email_parser import ParsedEmail


@dataclass
class Finding:
    code: str
    severity: str  # "low" | "medium" | "high" | "critical"
    title: str
    detail: str
    weight: int


@dataclass
class HeaderReport:
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)


FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "icloud.com", "mail.com", "gmx.com"
}


def _domain_of(addr: str) -> str:
    if "@" in addr:
        return addr.split("@")[-1].strip().lower().rstrip(">")
    return ""


def analyze_headers(pe: ParsedEmail, expected_domain: str = "") -> HeaderReport:
    report = HeaderReport()

    display_name = pe.from_display.lower()
    from_domain = pe.from_domain

    # Red Flag: Display name impersonates an executive/brand but the
    # underlying domain is a free/public mail provider.
    exec_like_titles = ["ceo", "cfo", "cto", "director", "hr", "president", "manager", "support", "admin", "security"]
    if any(title in display_name for title in exec_like_titles) and from_domain in FREE_MAIL_PROVIDERS:
        report.findings.append(Finding(
            code="DISPLAY_NAME_SPOOF",
            severity="high",
            title="Display-name spoofing detected",
            detail=(f"The friendly name '{pe.from_display}' implies an internal executive or "
                    f"department, but the real sending domain is a free public provider "
                    f"({from_domain}). Legitimate corporate mail rarely routes through consumer webmail."),
            weight=20
        ))

    # Red Flag: Reply-To differs from From address (classic BEC pivot)
    if pe.reply_to:
        reply_domain = _domain_of(pe.reply_to)
        if reply_domain and reply_domain != from_domain:
            report.findings.append(Finding(
                code="REPLY_TO_MISMATCH",
                severity="high",
                title="Reply-To domain differs from From domain",
                detail=(f"Replies would be routed to '{reply_domain}' instead of the sending "
                        f"domain '{from_domain}'. This is a common Business Email Compromise (BEC) "
                        f"technique to intercept responses without the victim noticing."),
                weight=18
            ))

    # Red Flag: Return-Path differs from From address
    if pe.return_path:
        return_domain = _domain_of(pe.return_path)
        if return_domain and return_domain != from_domain:
            report.findings.append(Finding(
                code="RETURN_PATH_MISMATCH",
                severity="medium",
                title="Return-Path domain differs from From domain",
                detail=(f"Bounce/return handling points to '{return_domain}', not '{from_domain}'. "
                        f"Often indicates the message was relayed through infrastructure the "
                        f"claimed sender doesn't control."),
                weight=12
            ))

    # Expected-domain comparison, if the analyst supplies the organization's real domain
    if expected_domain and from_domain and expected_domain.lower() not in from_domain:
        report.findings.append(Finding(
            code="DOMAIN_NOT_EXPECTED",
            severity="critical",
            title="Sending domain does not match the expected organization domain",
            detail=(f"Expected mail from '{expected_domain}' but this message originates from "
                    f"'{from_domain}'. Treat this as a likely impersonation attempt."),
            weight=25
        ))

    # Authentication protocol results
    for proto, value in (("SPF", pe.spf), ("DKIM", pe.dkim), ("DMARC", pe.dmarc)):
        if value is None:
            continue
        if value.lower() in ("fail", "softfail", "none", "temperror", "permerror"):
            report.findings.append(Finding(
                code=f"{proto}_FAIL",
                severity="high",
                title=f"{proto} authentication failed ({value})",
                detail=(f"{proto} did not validate this message. A lack of SPF, DKIM, and "
                        f"DMARC alignment is exactly how attackers achieve 'True Domain "
                        f"Spoofing' against organizations with weak email authentication."),
                weight=15
            ))

    # Fake forwarded chain: subject starts with FW:/RE: but body contains
    # a pasted header block the recipient was never part of.
    if re.match(r"^\s*(FW|RE|FWD)\s*:", pe.subject, re.IGNORECASE):
        if re.search(r"\bFrom:\s.+\bTo:\s.+\bSubject:\s", pe.body_text, re.IGNORECASE | re.DOTALL):
            report.findings.append(Finding(
                code="FAKE_FORWARD_CHAIN",
                severity="medium",
                title="Suspicious forwarded conversation thread",
                detail=("The body contains a pasted header block styled as a forwarded "
                        "conversation. Attackers fabricate these threads to imply prior "
                        "legitimate correspondence and lower the target's guard."),
                weight=10
            ))

    return report
