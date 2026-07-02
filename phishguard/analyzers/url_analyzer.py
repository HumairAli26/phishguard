"""
url_analyzer.py
----------------
Deconstructs every URL found in a message and scores it against several
independent deception techniques described in the DecodeLabs brief:
  - Typosquatting        (Levenshtein/edit-distance vs. trusted brands)
  - Homoglyph substitution (visually identical character swaps)
  - Combosquatting        (brand + security-flavoured word)
  - Subdomain traps        (true root domain buried behind fake subdomains)
  - URL shorteners         (obscured destinations)
  - Suspicious TLDs
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "brand_domains.json"

with open(DATA_FILE, "r", encoding="utf-8") as f:
    _BRAND_DATA = json.load(f)

TRUSTED_BRANDS = _BRAND_DATA["trusted_brands"]
HOMOGLYPH_MAP = _BRAND_DATA["homoglyph_map"]
SHORTENERS = set(_BRAND_DATA["known_url_shorteners"])
SUSPICIOUS_TLDS = _BRAND_DATA["suspicious_tlds"]
COMBOSQUAT_WORDS = _BRAND_DATA["combosquat_keywords"]

# Reverse homoglyph lookup: maps a lookalike char back to the real letter
_REVERSE_HOMOGLYPHS = {}
for real_char, fakes in HOMOGLYPH_MAP.items():
    for fake in fakes:
        _REVERSE_HOMOGLYPHS[fake] = real_char


@dataclass
class UrlFinding:
    url: str
    code: str
    severity: str
    title: str
    detail: str
    weight: int


@dataclass
class UrlReport:
    findings: List[UrlFinding] = field(default_factory=list)
    urls_analyzed: int = 0

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)


def _levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming edit distance (no external deps needed)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            add, remove, change = previous[j] + 1, current[j - 1] + 1, previous[j - 1]
            if ca != cb:
                change += 1
            current[j] = min(add, remove, change)
        previous = current
    return previous[-1]


def _normalize_homoglyphs(domain: str) -> str:
    """Replace known homoglyph characters with their likely real letter."""
    return "".join(_REVERSE_HOMOGLYPHS.get(ch, ch) for ch in domain)


def _extract_root_domain(netloc: str) -> str:
    """Best-effort root-domain extraction without needing the `tldextract` dep."""
    parts = netloc.split(".")
    if len(parts) <= 2:
        return netloc
    # naive heuristic: last two labels are the root (handles .com, .co.uk poorly
    # but good enough for classroom-scale triage without a public suffix list)
    return ".".join(parts[-2:])


def analyze_urls(urls: List[str]) -> UrlReport:
    report = UrlReport()
    report.urls_analyzed = len(urls)

    for raw_url in urls:
        url = raw_url if "://" in raw_url else f"http://{raw_url}"
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        netloc = parsed.netloc.lower()
        host_only = netloc.split(":")[0]
        root_domain = _extract_root_domain(host_only)

        # --- URL shortener ---
        if host_only in SHORTENERS:
            report.findings.append(UrlFinding(
                url=raw_url, code="SHORTENER", severity="medium",
                title="URL shortener obscures true destination",
                detail=(f"'{host_only}' is a known link shortener. The real destination is "
                        f"hidden until clicked, which is a common technique to bypass quick "
                        f"visual URL inspection."),
                weight=10
            ))

        # --- Suspicious TLD ---
        for tld in SUSPICIOUS_TLDS:
            if host_only.endswith(tld):
                report.findings.append(UrlFinding(
                    url=raw_url, code="SUSPICIOUS_TLD", severity="medium",
                    title=f"Suspicious top-level domain ({tld})",
                    detail=(f"The domain uses '{tld}', a TLD disproportionately favored by "
                            f"phishing infrastructure due to low registration cost and lax vetting."),
                    weight=8
                ))
                break

        # --- Homoglyph attack ---
        normalized = _normalize_homoglyphs(host_only)
        if normalized != host_only:
            for brand in TRUSTED_BRANDS:
                brand_label = brand.split(".")[0]
                if len(brand_label) >= 4 and brand_label in normalized and brand_label not in host_only:
                    report.findings.append(UrlFinding(
                        url=raw_url, code="HOMOGLYPH", severity="critical",
                        title="Homoglyph character substitution detected",
                        detail=(f"'{host_only}' contains characters that visually mimic '{brand}' "
                                f"once normalized ({host_only} -> {normalized}). This is a "
                                f"deliberate visual-deception technique."),
                        weight=25
                    ))
                    break

        # --- Typosquatting (edit distance) ---
        label = root_domain.split(".")[0] if "." in root_domain else root_domain
        for brand in TRUSTED_BRANDS:
            brand_label = brand.split(".")[0]
            if label == brand_label:
                continue  # exact match, not a typo
            distance = _levenshtein(label, brand_label)
            if 0 < distance <= 2 and abs(len(label) - len(brand_label)) <= 2:
                report.findings.append(UrlFinding(
                    url=raw_url, code="TYPOSQUAT", severity="critical",
                    title=f"Likely typosquat of '{brand}'",
                    detail=(f"'{host_only}' is only {distance} character(s) different from the "
                            f"legitimate brand domain '{brand}'. Classic typosquatting relies on "
                            f"the eye skipping small spelling errors."),
                    weight=25
                ))
                break

        # --- Combosquatting (also checks the homoglyph-normalized form so
        #     that domains like 'amaz0n-secure.com' are still caught even
        #     though the raw string doesn't literally contain 'amazon') ---
        for brand in TRUSTED_BRANDS:
            brand_label = brand.split(".")[0]
            if len(brand_label) >= 4 and brand_label in normalized and host_only != brand:
                for word in COMBOSQUAT_WORDS:
                    if word in host_only:
                        report.findings.append(UrlFinding(
                            url=raw_url, code="COMBOSQUAT", severity="high",
                            title=f"Combosquatting on brand '{brand_label}'",
                            detail=(f"'{host_only}' pairs the real brand name with the "
                                    f"security-flavoured word '{word}' — a pattern designed to "
                                    f"look official (e.g. '{brand_label}-{word}-login.com')."),
                            weight=18
                        ))
                        break

        # --- Subdomain trap: legit-looking brand name buried as a subdomain
        #     of an unrelated, attacker-controlled root domain ---
        labels = host_only.split(".")
        if len(labels) >= 3:
            subdomain_portion = ".".join(labels[:-2])
            for brand in TRUSTED_BRANDS:
                brand_label = brand.split(".")[0]
                if brand_label in subdomain_portion and root_domain != brand:
                    report.findings.append(UrlFinding(
                        url=raw_url, code="SUBDOMAIN_TRAP", severity="critical",
                        title="Subdomain trap: brand name buried before the true root domain",
                        detail=(f"'{host_only}' places '{brand_label}' in a subdomain while the "
                                f"actual controlling root domain is '{root_domain}'. Read URLs "
                                f"right-to-left: the true owner is always the root domain, not "
                                f"whatever appears first."),
                        weight=25
                    ))
                    break

        # --- IP-literal address instead of a domain name ---
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_only):
            report.findings.append(UrlFinding(
                url=raw_url, code="IP_LITERAL", severity="high",
                title="Raw IP address used instead of a domain name",
                detail=(f"'{host_only}' is a bare IP address. Legitimate corporate services "
                        f"almost never link directly to an IP literal for login pages."),
                weight=15
            ))

        # --- Excessive subdomain depth (obfuscation) ---
        if len(labels) >= 5:
            report.findings.append(UrlFinding(
                url=raw_url, code="EXCESSIVE_SUBDOMAINS", severity="low",
                title="Unusually deep subdomain chain",
                detail=(f"'{host_only}' has {len(labels)} DNS labels. Excessively long "
                        f"subdomain chains are frequently used to push the real, malicious "
                        f"root domain out of the visible URL bar on mobile devices."),
                weight=6
            ))

    return report
