"""
gui.py
-------
PhishGuard desktop GUI, built with Tkinter + Matplotlib + NumPy (same stack
as the Password Strength Checker and Sudoku Solver projects), so the whole
"cybersecurity learning track" has one consistent look and feel.

Tabs:
  1. Analyze     - paste an email or load a .eml/.txt file, get an instant
                    triage verdict with a risk gauge + red flag breakdown
  2. Batch Scan   - point at a folder of sample emails, get a summary table
  3. Dashboard    - matplotlib charts sourced from the SQLite scan history
  4. Sample Vault - one-click load of the 6 bundled sample emails for demos
"""

from __future__ import annotations

import os
import glob
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import numpy as np
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from phishguard.core.email_parser import parse_email_input
from phishguard.core.scoring_engine import triage_email, TriageResult
from phishguard.core.database import log_scan, fetch_history, verdict_counts
from phishguard.core.report_generator import export_json, export_csv, export_pdf, \
    make_risk_gauge_chart, make_red_flag_pie_chart

APP_TITLE = "PhishGuard — Phishing Triage & Simulation Toolkit"
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "data", "sample_emails")

VERDICT_COLORS = {"SAFE": "#4CAF50", "SUSPICIOUS": "#FF9800", "MALICIOUS": "#E53935"}
BG = "#F4F6F5"
ACCENT = "#37474F"


class PhishGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(1000, 640)
        self.configure(bg=BG)

        self.current_result: TriageResult | None = None

        self._build_style()
        self._build_layout()

    # ---------------------------------------------------------- styling
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook.Tab", padding=(16, 8), font=("Segoe UI", 10, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), background=BG, foreground=ACCENT)
        style.configure("Sub.TLabel", font=("Segoe UI", 10), background=BG, foreground="#555")
        style.configure("TButton", font=("Segoe UI", 10), padding=6)

    def _build_layout(self):
        header = tk.Frame(self, bg=ACCENT, height=64)
        header.pack(fill="x", side="top")
        tk.Label(header, text="🛡  PhishGuard", bg=ACCENT, fg="white",
                 font=("Segoe UI", 18, "bold")).pack(side="left", padx=20, pady=12)
        tk.Label(header, text="Project 3 · Phishing Awareness Analysis · DecodeLabs",
                 bg=ACCENT, fg="#CFD8DC", font=("Segoe UI", 10)).pack(side="left", pady=12)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.analyze_tab = AnalyzeTab(notebook, self)
        self.batch_tab = BatchTab(notebook, self)
        self.dashboard_tab = DashboardTab(notebook, self)
        self.vault_tab = VaultTab(notebook, self)

        notebook.add(self.analyze_tab, text="  🔍 Analyze  ")
        notebook.add(self.batch_tab, text="  📁 Batch Scan  ")
        notebook.add(self.dashboard_tab, text="  📊 Dashboard  ")
        notebook.add(self.vault_tab, text="  🧪 Sample Vault  ")

        notebook.bind("<<NotebookTabChanged>>", lambda e: self.dashboard_tab.refresh())


# ================================================================= TAB 1
class AnalyzeTab(tk.Frame):
    def __init__(self, parent, app: PhishGuardApp):
        super().__init__(parent, bg=BG)
        self.app = app
        self._build()

    def _build(self):
        left = tk.Frame(self, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(self, bg=BG, width=420)
        right.pack(side="right", fill="y")

        ttk.Label(left, text="Paste an email (with headers) or load a file", style="Header.TLabel").pack(anchor="w", pady=(4, 2))
        ttk.Label(left, text="Tip: include From / Reply-To / Return-Path / Subject lines for the fullest header analysis.",
                  style="Sub.TLabel").pack(anchor="w", pady=(0, 8))

        self.text_box = scrolledtext.ScrolledText(left, wrap="word", font=("Consolas", 10), height=22)
        self.text_box.pack(fill="both", expand=True)

        controls = tk.Frame(left, bg=BG)
        controls.pack(fill="x", pady=8)

        ttk.Button(controls, text="📂 Load File...", command=self.load_file).pack(side="left", padx=4)
        ttk.Button(controls, text="🧹 Clear", command=lambda: self.text_box.delete("1.0", tk.END)).pack(side="left", padx=4)

        tk.Label(controls, text="Expected org domain (optional):", bg=BG).pack(side="left", padx=(20, 4))
        self.domain_entry = ttk.Entry(controls, width=22)
        self.domain_entry.pack(side="left")

        ttk.Button(controls, text="🚨 Analyze Email", command=self.analyze).pack(side="right", padx=4)

        # ---- right-hand results panel ----
        ttk.Label(right, text="Triage Result", style="Header.TLabel").pack(anchor="w", pady=(4, 8))

        self.verdict_label = tk.Label(right, text="No scan yet", font=("Segoe UI", 20, "bold"),
                                        bg=BG, fg="#888")
        self.verdict_label.pack(anchor="w")
        self.score_label = tk.Label(right, text="", font=("Segoe UI", 11), bg=BG, fg="#555")
        self.score_label.pack(anchor="w", pady=(0, 8))
        self.action_label = tk.Label(right, text="", font=("Segoe UI", 12, "bold"), bg=BG, fg=ACCENT)
        self.action_label.pack(anchor="w", pady=(0, 10))

        self.chart_frame = tk.Frame(right, bg=BG)
        self.chart_frame.pack(fill="x")

        ttk.Label(right, text="Red Flags", style="Header.TLabel").pack(anchor="w", pady=(12, 4))
        self.flags_box = scrolledtext.ScrolledText(right, wrap="word", font=("Segoe UI", 9), height=14, width=48)
        self.flags_box.pack(fill="both", expand=True)

        export_row = tk.Frame(right, bg=BG)
        export_row.pack(fill="x", pady=8)
        ttk.Button(export_row, text="Export PDF", command=lambda: self.export("pdf")).pack(side="left", padx=2)
        ttk.Button(export_row, text="Export JSON", command=lambda: self.export("json")).pack(side="left", padx=2)
        ttk.Button(export_row, text="Export CSV", command=lambda: self.export("csv")).pack(side="left", padx=2)

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Email files", "*.eml *.txt"), ("All files", "*.*")])
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.text_box.delete("1.0", tk.END)
                self.text_box.insert(tk.END, f.read())

    def analyze(self):
        raw = self.text_box.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("PhishGuard", "Please paste or load an email first.")
            return
        pe = parse_email_input(raw)
        expected = self.domain_entry.get().strip()
        result = triage_email(pe, expected_domain=expected)
        self.app.current_result = result

        log_scan(result.email_subject, result.from_address, result.total_score,
                  result.verdict, result.action, result.all_red_flags)

        color = VERDICT_COLORS.get(result.verdict, "#888")
        self.verdict_label.config(text=result.verdict, fg=color)
        self.score_label.config(text=f"Risk score: {result.total_score} / 150   ·   "
                                       f"{len(result.all_red_flags)} red flag(s)")
        self.action_label.config(text=f"Recommended action: {result.action}")

        self._render_chart(result)
        self._render_flags(result)

    def _render_chart(self, result: TriageResult):
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(4.0, 1.0))
        score = min(result.total_score, 150)
        ax.barh([0], [150], color="#E0E0E0", height=0.5)
        color = VERDICT_COLORS.get(result.verdict, "#888")
        ax.barh([0], [score], color=color, height=0.5)
        ax.set_xlim(0, 150)
        ax.set_yticks([])
        ax.set_xticks([0, 25, 60, 150])
        ax.set_title(f"{score} / 150", fontsize=10, fontweight="bold")
        for spine in ax.spines.values():
            spine.set_visible(False)
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="x")
        plt.close(fig)

    def _render_flags(self, result: TriageResult):
        self.flags_box.delete("1.0", tk.END)
        if not result.all_red_flags:
            self.flags_box.insert(tk.END, "No red flags detected. This message looks clean.")
            return
        for i, flag in enumerate(result.all_red_flags, 1):
            self.flags_box.insert(tk.END, f"[{i}] {flag['severity'].upper()} (+{flag['weight']}) "
                                            f"{flag['category']}\n")
            self.flags_box.insert(tk.END, f"    {flag['title']}\n")
            self.flags_box.insert(tk.END, f"    {flag['detail']}\n\n")

    def export(self, fmt: str):
        result = self.app.current_result
        if result is None:
            messagebox.showwarning("PhishGuard", "Run an analysis first.")
            return
        default_name = f"phishguard_report.{fmt}"
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}", initialfile=default_name)
        if not path:
            return
        try:
            if fmt == "json":
                export_json(result, path)
            elif fmt == "csv":
                export_csv(result, path)
            elif fmt == "pdf":
                tmp_dir = os.path.dirname(path) or "."
                gauge = make_risk_gauge_chart(result, os.path.join(tmp_dir, "_gauge_tmp.png"))
                pie = make_red_flag_pie_chart(result, os.path.join(tmp_dir, "_pie_tmp.png"))
                export_pdf(result, path, gauge, pie)
            messagebox.showinfo("PhishGuard", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("PhishGuard", f"Export failed: {e}")


# ================================================================= TAB 2
class BatchTab(tk.Frame):
    def __init__(self, parent, app: PhishGuardApp):
        super().__init__(parent, bg=BG)
        self.app = app
        self._build()

    def _build(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", pady=8)
        ttk.Label(top, text="Batch Scan a Folder of Emails", style="Header.TLabel").pack(anchor="w")

        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", pady=6)
        ttk.Button(row, text="📁 Choose Folder...", command=self.choose_folder).pack(side="left")
        tk.Label(row, text="Expected org domain (optional):", bg=BG).pack(side="left", padx=(20, 4))
        self.domain_entry = ttk.Entry(row, width=22)
        self.domain_entry.pack(side="left")
        self.folder_label = tk.Label(row, text="No folder selected", bg=BG, fg="#777")
        self.folder_label.pack(side="left", padx=12)

        columns = ("file", "subject", "from", "score", "verdict", "action")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=18)
        headers = {"file": "File", "subject": "Subject", "from": "From", "score": "Score",
                    "verdict": "Verdict", "action": "Recommended Action"}
        widths = {"file": 160, "subject": 220, "from": 200, "score": 60, "verdict": 100, "action": 160}
        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col])
        self.tree.pack(fill="both", expand=True, pady=10)
        self.tree.tag_configure("SAFE", background="#E8F5E9")
        self.tree.tag_configure("SUSPICIOUS", background="#FFF3E0")
        self.tree.tag_configure("MALICIOUS", background="#FFEBEE")

        self.summary_label = tk.Label(self, text="", bg=BG, font=("Segoe UI", 11, "bold"))
        self.summary_label.pack(anchor="w")

    def choose_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.folder_label.config(text=folder)
        self.run_batch(folder)

    def run_batch(self, folder: str):
        for item in self.tree.get_children():
            self.tree.delete(item)

        files = sorted(glob.glob(os.path.join(folder, "*")))
        expected = self.domain_entry.get().strip()
        counts = {"SAFE": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}

        for fpath in files:
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            pe = parse_email_input(text)
            result = triage_email(pe, expected_domain=expected)
            log_scan(result.email_subject, result.from_address, result.total_score,
                      result.verdict, result.action, result.all_red_flags)
            counts[result.verdict] = counts.get(result.verdict, 0) + 1

            self.tree.insert("", tk.END, values=(
                os.path.basename(fpath), result.email_subject[:40], result.from_address[:30],
                result.total_score, result.verdict, result.action
            ), tags=(result.verdict,))

        self.summary_label.config(
            text=f"Scanned {len(files)} file(s)  |  SAFE: {counts['SAFE']}   "
                 f"SUSPICIOUS: {counts['SUSPICIOUS']}   MALICIOUS: {counts['MALICIOUS']}"
        )


# ================================================================= TAB 3
class DashboardTab(tk.Frame):
    def __init__(self, parent, app: PhishGuardApp):
        super().__init__(parent, bg=BG)
        self.app = app
        self.canvas_widget = None
        self._build()

    def _build(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", pady=8)
        ttk.Label(top, text="Scan History Dashboard", style="Header.TLabel").pack(side="left")
        ttk.Button(top, text="🔄 Refresh", command=self.refresh).pack(side="right")

        self.chart_container = tk.Frame(self, bg=BG)
        self.chart_container.pack(fill="both", expand=True)
        self.refresh()

    def refresh(self):
        for widget in self.chart_container.winfo_children():
            widget.destroy()

        history = fetch_history(limit=200)
        counts = verdict_counts()

        fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))

        # Verdict distribution bar chart
        verdicts = ["SAFE", "SUSPICIOUS", "MALICIOUS"]
        values = [counts.get(v, 0) for v in verdicts]
        colors = [VERDICT_COLORS[v] for v in verdicts]
        axes[0].bar(verdicts, values, color=colors)
        axes[0].set_title("Total Scans by Verdict", fontweight="bold")
        axes[0].set_ylabel("Count")
        for i, v in enumerate(values):
            axes[0].text(i, v + 0.05, str(v), ha="center", fontweight="bold")

        # Score trend over the most recent scans
        if history:
            scores = [h["score"] for h in reversed(history)][-30:]
            x = np.arange(len(scores))
            axes[1].plot(x, scores, marker="o", color=ACCENT, linewidth=1.5, markersize=4)
            axes[1].axhspan(0, 25, color=VERDICT_COLORS["SAFE"], alpha=0.15)
            axes[1].axhspan(25, 60, color=VERDICT_COLORS["SUSPICIOUS"], alpha=0.15)
            axes[1].axhspan(60, max(150, max(scores) + 5), color=VERDICT_COLORS["MALICIOUS"], alpha=0.15)
            axes[1].set_title("Risk Score Trend (recent scans)", fontweight="bold")
            axes[1].set_xlabel("Scan #")
            axes[1].set_ylabel("Score")
        else:
            axes[1].text(0.5, 0.5, "No scans yet", ha="center", va="center", transform=axes[1].transAxes)
            axes[1].set_title("Risk Score Trend", fontweight="bold")

        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.chart_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        plt.close(fig)

        # Recent scans table
        table_frame = tk.Frame(self.chart_container, bg=BG)
        table_frame.pack(fill="both", expand=False, pady=(6, 0))
        columns = ("time", "subject", "score", "verdict")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        for col, w in zip(columns, (150, 320, 70, 100)):
            tree.heading(col, text=col.capitalize())
            tree.column(col, width=w)
        tree.tag_configure("SAFE", background="#E8F5E9")
        tree.tag_configure("SUSPICIOUS", background="#FFF3E0")
        tree.tag_configure("MALICIOUS", background="#FFEBEE")
        for h in history[:8]:
            tree.insert("", tk.END, values=(h["timestamp"], (h["subject"] or "")[:50],
                                              h["score"], h["verdict"]), tags=(h["verdict"],))
        tree.pack(fill="x")


# ================================================================= TAB 4
class VaultTab(tk.Frame):
    """One-click sample loader so a demo/interview never needs a real phishing email."""
    def __init__(self, parent, app: PhishGuardApp):
        super().__init__(parent, bg=BG)
        self.app = app
        self._build()

    def _build(self):
        ttk.Label(self, text="Sample Email Vault", style="Header.TLabel").pack(anchor="w", pady=(4, 2))
        ttk.Label(self, text="Six curated samples spanning safe mail, mass phishing, BEC, spear "
                              "phishing, TOAD callback scams, and MFA-fatigue attacks.",
                  style="Sub.TLabel").pack(anchor="w", pady=(0, 10))

        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True)

        if not os.path.isdir(SAMPLES_DIR):
            tk.Label(container, text="Sample directory not found.", bg=BG).pack()
            return

        files = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*.txt")))
        for fpath in files:
            name = os.path.basename(fpath)
            row = tk.Frame(container, bg="white", relief="solid", borderwidth=1)
            row.pack(fill="x", pady=4, padx=2)
            tk.Label(row, text=name, bg="white", font=("Segoe UI", 10, "bold"), anchor="w").pack(
                side="left", padx=10, pady=8, fill="x", expand=True)
            ttk.Button(row, text="Load into Analyze tab",
                       command=lambda p=fpath: self.load_sample(p)).pack(side="right", padx=10, pady=6)

    def load_sample(self, path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        analyze_tab = self.app.analyze_tab
        analyze_tab.text_box.delete("1.0", tk.END)
        analyze_tab.text_box.insert(tk.END, content)
        # Switch to Analyze tab
        notebook = self.app.nametowidget(self.winfo_parent())
        for i, tab_id in enumerate(notebook.tabs()):
            if notebook.nametowidget(tab_id) is analyze_tab:
                notebook.select(i)
                break
        messagebox.showinfo("PhishGuard", f"Loaded '{os.path.basename(path)}' into the Analyze tab. "
                                            f"Click 'Analyze Email' to triage it.")


def main():
    app = PhishGuardApp()
    app.mainloop()


if __name__ == "__main__":
    main()
