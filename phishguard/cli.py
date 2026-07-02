"""
cli.py
-------
Command-line interface for PhishGuard.

Usage:
    python -m phishguard.cli --file sample.eml
    python -m phishguard.cli --batch data/sample_emails/ --expected-domain company.com
    python -m phishguard.cli --file sample.eml --pdf report.pdf --json report.json
"""

from __future__ import annotations

import argparse
import glob
import os
import sys

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _NoColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = _NoColor()

from phishguard.core.email_parser import parse_email_input
from phishguard.core.scoring_engine import triage_email
from phishguard.core.database import log_scan
from phishguard.core.report_generator import (
    export_json, export_csv, export_pdf, make_risk_gauge_chart, make_red_flag_pie_chart
)

VERDICT_COLOR = {
    "SAFE": Fore.GREEN,
    "SUSPICIOUS": Fore.YELLOW,
    "MALICIOUS": Fore.RED,
}


def print_result(result, filename: str = "") -> None:
    color = VERDICT_COLOR.get(result.verdict, "")
    header = f"\n{'=' * 70}\n"
    if filename:
        header += f"File: {filename}\n"
    header += f"Subject: {result.email_subject}\nFrom: {result.from_address}\n"
    print(header)
    print(f"{color}{Style.BRIGHT}Verdict: {result.verdict}  (score {result.total_score}/150)"
          f"{Style.RESET_ALL}")
    print(f"Recommended action: {result.action}\n")

    if not result.all_red_flags:
        print("No red flags detected.")
    else:
        print(f"{len(result.all_red_flags)} red flag(s) found:\n")
        for i, flag in enumerate(result.all_red_flags, 1):
            print(f"  [{i}] ({flag['severity'].upper()}, +{flag['weight']}) "
                  f"{flag['category']} -> {flag['title']}")
            print(f"       {flag['detail']}\n")


def scan_one(path: str, expected_domain: str, save_dir: str = None,
              make_pdf: bool = False, make_json: bool = False, make_csv: bool = False):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    pe = parse_email_input(text)
    result = triage_email(pe, expected_domain=expected_domain)
    log_scan(result.email_subject, result.from_address, result.total_score,
              result.verdict, result.action, result.all_red_flags)
    print_result(result, filename=os.path.basename(path))

    if save_dir:
        os.makedirs(save_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(path))[0]
        if make_json:
            export_json(result, os.path.join(save_dir, f"{base}_report.json"))
        if make_csv:
            export_csv(result, os.path.join(save_dir, f"{base}_report.csv"))
        if make_pdf:
            gauge = make_risk_gauge_chart(result, os.path.join(save_dir, f"{base}_gauge.png"))
            pie = make_red_flag_pie_chart(result, os.path.join(save_dir, f"{base}_pie.png"))
            export_pdf(result, os.path.join(save_dir, f"{base}_report.pdf"), gauge, pie)
            print(f"  -> PDF report saved: {base}_report.pdf")

    return result


def main():
    parser = argparse.ArgumentParser(description="PhishGuard - Phishing Triage CLI")
    parser.add_argument("--file", help="Path to a single email file (.eml or .txt)")
    parser.add_argument("--batch", help="Path to a directory of email files to scan")
    parser.add_argument("--expected-domain", default="", help="Your organization's real domain, e.g. company.com")
    parser.add_argument("--out", default="reports", help="Output directory for generated reports")
    parser.add_argument("--pdf", action="store_true", help="Generate a PDF report")
    parser.add_argument("--json", action="store_true", help="Generate a JSON report")
    parser.add_argument("--csv", action="store_true", help="Generate a CSV report")
    args = parser.parse_args()

    if not args.file and not args.batch:
        parser.print_help()
        sys.exit(1)

    results = []
    if args.file:
        results.append(scan_one(args.file, args.expected_domain, args.out,
                                  args.pdf, args.json, args.csv))
    if args.batch:
        files = sorted(glob.glob(os.path.join(args.batch, "*")))
        if not files:
            print(f"No files found in {args.batch}")
            sys.exit(1)
        for fpath in files:
            if os.path.isfile(fpath):
                results.append(scan_one(fpath, args.expected_domain, args.out,
                                          args.pdf, args.json, args.csv))

    print(f"\n{'=' * 70}")
    print(f"Batch summary: {len(results)} email(s) analyzed")
    for verdict in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
        count = sum(1 for r in results if r.verdict == verdict)
        color = VERDICT_COLOR.get(verdict, "")
        print(f"  {color}{verdict}: {count}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
