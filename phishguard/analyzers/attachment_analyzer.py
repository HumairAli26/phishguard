"""
attachment_analyzer.py
------------------------
Flags dangerous file extensions, macro-enabled Office documents,
archive-wrapped payloads, and classic double-extension tricks
(e.g. "Invoice.pdf.exe").
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "dangerous_extensions.json"

with open(DATA_FILE, "r", encoding="utf-8") as f:
    _EXT_DATA = json.load(f)

HIGH_RISK = set(_EXT_DATA["high_risk"])
MACRO_RISK = set(_EXT_DATA["macro_risk"])
ARCHIVE_WRAPPING = set(_EXT_DATA["archive_wrapping"])
DOUBLE_EXT_PATTERN = re.compile(_EXT_DATA["double_extension_pattern"], re.IGNORECASE)


@dataclass
class AttachmentFinding:
    filename: str
    code: str
    severity: str
    title: str
    detail: str
    weight: int


@dataclass
class AttachmentReport:
    findings: List[AttachmentFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)


def _ext_of(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:].lower() if idx != -1 else ""


def analyze_attachments(filenames: List[str]) -> AttachmentReport:
    report = AttachmentReport()

    for name in filenames:
        ext = _ext_of(name)

        if DOUBLE_EXT_PATTERN.search(name):
            report.findings.append(AttachmentFinding(
                filename=name, code="DOUBLE_EXTENSION", severity="critical",
                title="Double extension disguise",
                detail=(f"'{name}' uses a double extension to disguise an executable payload "
                        f"as an innocuous document. Windows often hides the true final "
                        f"extension by default."),
                weight=25
            ))
            continue

        if ext in HIGH_RISK:
            report.findings.append(AttachmentFinding(
                filename=name, code="HIGH_RISK_EXTENSION", severity="critical",
                title=f"High-risk executable attachment ({ext})",
                detail=(f"'{name}' has an extension ({ext}) capable of running code directly "
                        f"on the recipient's machine. Legitimate business correspondence "
                        f"almost never needs to send this file type."),
                weight=22
            ))
        elif ext in MACRO_RISK:
            report.findings.append(AttachmentFinding(
                filename=name, code="MACRO_RISK_EXTENSION", severity="high",
                title=f"Macro-enabled Office document ({ext})",
                detail=(f"'{name}' can embed auto-executing VBA macros — one of the most "
                        f"common droppers for follow-on malware."),
                weight=16
            ))
        elif ext in ARCHIVE_WRAPPING:
            report.findings.append(AttachmentFinding(
                filename=name, code="ARCHIVE_WRAPPED", severity="medium",
                title=f"Archive attachment ({ext})",
                detail=(f"'{name}' is a compressed archive. Attackers frequently wrap "
                        f"malicious executables in archives to evade attachment-type "
                        f"filtering at the mail gateway."),
                weight=10
            ))

    return report
