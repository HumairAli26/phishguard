"""
report_generator.py
----------------------
Turns a TriageResult into shareable artifacts:
  - JSON  (machine-readable)
  - CSV   (spreadsheet-friendly red-flag table)
  - PDF   (polished analyst report via reportlab)
  - PNG   (matplotlib risk-gauge + red-flag breakdown charts)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Optional

import numpy as np
import matplotlib
matplotlib.use("Agg")  # headless-safe backend
import matplotlib.pyplot as plt

from phishguard.core.scoring_engine import TriageResult

VERDICT_COLORS = {"SAFE": "#4CAF50", "SUSPICIOUS": "#FF9800", "MALICIOUS": "#E53935"}


def export_json(result: TriageResult, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)
    return path


def export_csv(result: TriageResult, path: str) -> str:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Code", "Severity", "Weight", "Title", "Detail"])
        for flag in result.all_red_flags:
            writer.writerow([
                flag.get("category", ""), flag.get("code", ""), flag.get("severity", ""),
                flag.get("weight", ""), flag.get("title", ""), flag.get("detail", ""),
            ])
    return path


def make_risk_gauge_chart(result: TriageResult, path: str) -> str:
    """Semi-circular gauge showing the 0-150 risk score with verdict banding."""
    fig, ax = plt.subplots(figsize=(5, 3.2), subplot_kw={"projection": "polar"})

    max_score = 150
    zones = [(0, 25, "#4CAF50"), (25, 60, "#FF9800"), (60, 150, "#E53935")]
    theta_max = np.pi

    for low, high, color in zones:
        start = np.pi - (low / max_score) * theta_max
        end = np.pi - (high / max_score) * theta_max
        theta = np.linspace(end, start, 100)
        ax.bar(x=theta.mean(), width=(start - end), height=1.0, bottom=1.5,
               color=color, alpha=0.85, edgecolor="white")

    needle_theta = np.pi - (min(result.total_score, max_score) / max_score) * theta_max
    ax.plot([needle_theta, needle_theta], [0, 1.5], color="black", linewidth=3)
    ax.plot(needle_theta, 0, "o", color="black", markersize=10)

    ax.set_theta_zero_location("W")
    ax.set_theta_direction(-1)
    ax.set_thetamin(0)
    ax.set_thetamax(180)
    ax.set_yticklabels([])
    ax.set_xticklabels([])
    ax.grid(False)
    ax.spines["polar"].set_visible(False)

    ax.set_title(f"Risk Score: {result.total_score} / {max_score}\nVerdict: {result.verdict}",
                 fontsize=12, fontweight="bold", pad=20,
                 color=VERDICT_COLORS.get(result.verdict, "black"))

    fig.tight_layout()
    fig.savefig(path, dpi=150, transparent=True)
    plt.close(fig)
    return path


def make_red_flag_pie_chart(result: TriageResult, path: str) -> Optional[str]:
    summary = result.red_flag_summary()
    if not summary:
        return None
    fig, ax = plt.subplots(figsize=(5, 4))
    labels = list(summary.keys())
    sizes = list(summary.values())
    colors = plt.cm.Set2(np.linspace(0, 1, len(labels)))
    ax.pie(sizes, labels=labels, autopct="%1.0f%%", colors=colors, startangle=90,
           textprops={"fontsize": 9})
    ax.set_title("Red Flags by Category", fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=150, transparent=True)
    plt.close(fig)
    return path


def export_pdf(result: TriageResult, path: str, gauge_png: Optional[str] = None,
                pie_png: Optional[str] = None) -> str:
    """Generates a polished analyst-style PDF report using reportlab."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    doc = SimpleDocTemplate(path, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleBig", parent=styles["Title"], fontSize=20, spaceAfter=6)
    verdict_color = colors.HexColor(VERDICT_COLORS.get(result.verdict, "#000000"))
    verdict_style = ParagraphStyle("Verdict", parent=styles["Heading1"], textColor=verdict_color)

    elements = []
    elements.append(Paragraph("PhishGuard Triage Report", title_style))
    elements.append(Paragraph("Project 3 — Phishing Awareness Analysis (DecodeLabs)", styles["Normal"]))
    elements.append(Spacer(1, 14))

    elements.append(Paragraph(f"Subject: {result.email_subject or '(none)'}", styles["Normal"]))
    elements.append(Paragraph(f"From: {result.from_address or '(unknown)'}", styles["Normal"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"Verdict: {result.verdict}", verdict_style))
    elements.append(Paragraph(f"Risk Score: {result.total_score} / 150", styles["Normal"]))
    elements.append(Paragraph(f"Recommended Action: {result.action}", styles["Heading3"]))
    elements.append(Spacer(1, 14))

    if gauge_png and Path(gauge_png).exists():
        elements.append(Image(gauge_png, width=4 * inch, height=2.6 * inch))
    if pie_png and Path(pie_png).exists():
        elements.append(Image(pie_png, width=4 * inch, height=3.2 * inch))

    elements.append(Spacer(1, 14))
    elements.append(Paragraph("Detected Red Flags", styles["Heading2"]))

    table_data = [["Category", "Severity", "Weight", "Finding"]]
    for flag in result.all_red_flags:
        table_data.append([
            flag.get("category", ""), flag.get("severity", "").upper(),
            str(flag.get("weight", "")), flag.get("title", ""),
        ])
    if len(table_data) == 1:
        table_data.append(["-", "-", "-", "No red flags detected."])

    table = Table(table_data, colWidths=[1.3 * inch, 0.9 * inch, 0.6 * inch, 3.0 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
    ]))
    elements.append(table)

    elements.append(Spacer(1, 16))
    elements.append(Paragraph(
        "Generated by PhishGuard — a defensive triage tool built for the DecodeLabs "
        "Cyber Security internship, Project 3.", styles["Italic"]
    ))

    doc.build(elements)
    return path
