"""
email_parser.py
----------------
Parses raw email text or .eml files into a normalized ParsedEmail object
that every analyzer module can consume. Supports:
  - Standard RFC822 .eml files (via Python's built-in `email` library)
  - Plain pasted text (GUI "paste email" box) with a lightweight
    header/body splitter fallback
"""

from __future__ import annotations

import re
import email
from email import policy
from email.message import Message
from dataclasses import dataclass, field
from typing import List, Dict, Optional


URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
    """
)

HEADER_LINE_REGEX = re.compile(r"^([A-Za-z\-]+):\s*(.*)$")


@dataclass
class ParsedEmail:
    raw_source: str
    subject: str = ""
    from_display: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    body_text: str = ""
    urls: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None

    @property
    def from_domain(self) -> str:
        if "@" in self.from_address:
            return self.from_address.split("@")[-1].strip().lower().rstrip(">")
        return ""


def _extract_urls(text: str) -> List[str]:
    found = URL_REGEX.findall(text) if False else URL_REGEX.finditer(text)
    urls = []
    for m in URL_REGEX.finditer(text):
        url = m.group(0).rstrip(".,;:)")
        urls.append(url)
    # de-duplicate, preserve order
    seen = set()
    unique = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def _parse_address_field(value: str) -> (str, str):
    """Split 'Display Name <addr@domain.com>' -> (display, address)."""
    if not value:
        return "", ""
    match = re.match(r"^(.*?)<([^>]+)>$", value.strip())
    if match:
        display = match.group(1).strip().strip('"')
        addr = match.group(2).strip()
        return display, addr
    if "@" in value:
        return "", value.strip()
    return value.strip(), ""


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parse a genuine RFC822 .eml file using Python's email library."""
    msg: Message = email.message_from_bytes(raw_bytes, policy=policy.default)
    return _parsed_from_message(msg, raw_bytes.decode("utf-8", errors="ignore"))


def parse_eml_text(text: str) -> ParsedEmail:
    """Parse text that looks like a full RFC822 message (has real headers)."""
    msg: Message = email.message_from_string(text, policy=policy.default)
    return _parsed_from_message(msg, text)


def _parsed_from_message(msg: Message, raw_source: str) -> ParsedEmail:
    pe = ParsedEmail(raw_source=raw_source)
    pe.subject = msg.get("Subject", "") or ""
    from_display, from_addr = _parse_address_field(msg.get("From", ""))
    pe.from_display = from_display
    pe.from_address = from_addr or msg.get("From", "")
    pe.reply_to = msg.get("Reply-To", "") or ""
    pe.return_path = msg.get("Return-Path", "") or ""
    pe.to = msg.get("To", "") or ""
    pe.date = msg.get("Date", "") or ""

    for k, v in msg.items():
        pe.headers[k] = str(v)

    auth_results = msg.get("Authentication-Results", "") or ""
    pe.spf = _extract_auth_result(auth_results, "spf")
    pe.dkim = _extract_auth_result(auth_results, "dkim")
    pe.dmarc = _extract_auth_result(auth_results, "dmarc")

    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename:
                pe.attachments.append(filename)
                continue
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
            elif part.get_content_type() == "text/html" and not body_parts:
                try:
                    html = part.get_content()
                    body_parts.append(re.sub(r"<[^>]+>", " ", html))
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            body_parts.append(str(msg.get_payload()))

    pe.body_text = "\n".join(body_parts)
    pe.urls = _extract_urls(pe.body_text + " " + pe.subject)
    return pe


def _extract_auth_result(auth_header: str, mechanism: str) -> Optional[str]:
    match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
    return match.group(1).lower() if match else None


def parse_plain_paste(text: str) -> ParsedEmail:
    """
    Fallback parser for informally pasted email content (e.g. copy-pasted
    from a webmail client) that isn't valid RFC822. Tries to find
    From/Reply-To/Subject-style lines heuristically, then treats the
    remainder as the body.
    """
    lines = text.splitlines()
    headers: Dict[str, str] = {}
    body_start = 0

    for i, line in enumerate(lines[:25]):
        m = HEADER_LINE_REGEX.match(line.strip())
        if m and m.group(1).lower() in (
            "from", "to", "subject", "reply-to", "return-path", "date", "sender"
        ):
            headers[m.group(1).lower()] = m.group(2).strip()
            body_start = i + 1
        elif headers and not m:
            break

    pe = ParsedEmail(raw_source=text)
    from_display, from_addr = _parse_address_field(headers.get("from", ""))
    pe.from_display = from_display
    pe.from_address = from_addr or headers.get("from", "")
    pe.reply_to = headers.get("reply-to", "")
    pe.return_path = headers.get("return-path", "")
    pe.to = headers.get("to", "")
    pe.subject = headers.get("subject", "")
    pe.date = headers.get("date", "")
    pe.headers = headers
    pe.body_text = "\n".join(lines[body_start:]) if headers else text
    pe.urls = _extract_urls(text)

    attach_matches = re.findall(r"[\w\-.]+\.(?:exe|scr|js|vbs|bat|cmd|ps1|jar|iso|img|lnk|hta|docm|xlsm|pptm|zip|rar|pdf)", text, re.IGNORECASE)
    pe.attachments = list(dict.fromkeys(attach_matches))
    return pe


def parse_email_input(text: str) -> ParsedEmail:
    """
    Smart entry point: figures out whether the given text is a real
    RFC822 message (has a proper header block) or a loosely pasted
    snippet, and dispatches to the right parser.
    """
    looks_like_rfc822 = bool(re.search(r"^(From|Subject|Date):", text, re.MULTILINE))
    if looks_like_rfc822:
        try:
            return parse_eml_text(text)
        except Exception:
            pass
    return parse_plain_paste(text)
