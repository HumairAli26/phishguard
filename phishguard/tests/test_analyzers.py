"""
test_analyzers.py
-------------------
Unit tests covering the parser, each analyzer, and the scoring engine.
Run with:  pytest -v  (from the directory ABOVE phishguard/)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from phishguard.core.email_parser import parse_email_input
from phishguard.core.scoring_engine import triage_email, verdict_for_score
from phishguard.analyzers.url_analyzer import analyze_urls, _levenshtein
from phishguard.analyzers.keyword_analyzer import analyze_keywords
from phishguard.analyzers.attachment_analyzer import analyze_attachments
from phishguard.analyzers.header_analyzer import analyze_headers


SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample_emails")


def _load_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------ parser
def test_parses_headers_correctly():
    pe = parse_email_input(_load_sample("03_bec_wire_transfer.txt"))
    assert pe.from_address == "ceo.urgent@executive-update.com"
    assert pe.reply_to == "ceo.personal2026@gmail.com"
    assert pe.from_domain == "executive-update.com"


def test_extracts_urls():
    pe = parse_email_input(_load_sample("02_mass_phishing_amazon.txt"))
    assert any("amaz0n-secure.com" in u for u in pe.urls)


# ------------------------------------------------------------------ header analyzer
def test_reply_to_mismatch_detected():
    pe = parse_email_input(_load_sample("03_bec_wire_transfer.txt"))
    report = analyze_headers(pe)
    codes = [f.code for f in report.findings]
    assert "REPLY_TO_MISMATCH" in codes


def test_expected_domain_mismatch_flagged():
    pe = parse_email_input(_load_sample("02_mass_phishing_amazon.txt"))
    report = analyze_headers(pe, expected_domain="amazon.com")
    codes = [f.code for f in report.findings]
    assert "DOMAIN_NOT_EXPECTED" in codes


# ------------------------------------------------------------------ URL analyzer
def test_levenshtein_basic():
    assert _levenshtein("amazon", "amaz0n") == 1
    assert _levenshtein("paypal", "paypal") == 0


def test_typosquat_detected():
    report = analyze_urls(["http://amaz0n-secure.com/verify"])
    codes = [f.code for f in report.findings]
    assert "TYPOSQUAT" in codes or "COMBOSQUAT" in codes


def test_subdomain_trap_detected():
    report = analyze_urls(["https://company.tech.login-update.com/reset"])
    # brand isn't in the trusted list here, so we test the generic mechanism
    # with a trusted brand instead:
    report2 = analyze_urls(["https://paypal.attacker-domain.com/login"])
    codes = [f.code for f in report2.findings]
    assert "SUBDOMAIN_TRAP" in codes


def test_shortener_flagged():
    report = analyze_urls(["http://bit.ly/abc123"])
    codes = [f.code for f in report.findings]
    assert "SHORTENER" in codes


# ------------------------------------------------------------------ keyword analyzer
def test_urgency_and_credential_harvesting_triggers():
    report = analyze_keywords("URGENT: verify your password immediately or your account will be locked")
    assert "urgency" in report.category_counts
    assert "credential_harvesting" in report.category_counts


def test_no_triggers_on_clean_text():
    report = analyze_keywords("Hi team, please review the attached status update at your convenience.")
    assert report.score == 0


# ------------------------------------------------------------------ attachment analyzer
def test_double_extension_flagged():
    report = analyze_attachments(["Invoice_Details.pdf.exe"])
    codes = [f.code for f in report.findings]
    assert "DOUBLE_EXTENSION" in codes


def test_safe_attachment_not_flagged():
    report = analyze_attachments(["quarterly_report.pdf"])
    assert report.score == 0


# ------------------------------------------------------------------ end-to-end scoring
def test_legit_email_is_safe():
    pe = parse_email_input(_load_sample("01_legit_email.txt"))
    result = triage_email(pe, expected_domain="company.com")
    assert result.verdict == "SAFE"


def test_bec_email_is_malicious():
    pe = parse_email_input(_load_sample("03_bec_wire_transfer.txt"))
    result = triage_email(pe, expected_domain="company.com")
    assert result.verdict == "MALICIOUS"
    assert result.action == "Block Domain & Escalate"


def test_verdict_thresholds():
    assert verdict_for_score(0) == "SAFE"
    assert verdict_for_score(24) == "SAFE"
    assert verdict_for_score(25) == "SUSPICIOUS"
    assert verdict_for_score(59) == "SUSPICIOUS"
    assert verdict_for_score(60) == "MALICIOUS"
    assert verdict_for_score(140) == "MALICIOUS"
