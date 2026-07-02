# 🛡️ PhishGuard

PhishGuard is a Python-based phishing email analysis toolkit that helps identify malicious emails using multiple detection techniques. It analyzes email headers, URLs, social engineering indicators, and attachment risks to classify emails as **Safe**, **Suspicious**, or **Malicious**.

Built for cybersecurity students, security analysts, and Blue Team enthusiasts, PhishGuard provides both a modern desktop GUI and a command-line interface while keeping all analysis completely offline.

---

# ✨ Features

- 📧 Analyze raw email text or `.eml` files
- 🛡️ Four independent phishing detection engines
- 📨 Header spoofing detection (SPF, DKIM & DMARC)
- 🌐 URL analysis for phishing indicators
- 🧠 Psychological trigger & social engineering detection
- 📎 Attachment risk assessment
- 🚦 Safe / Suspicious / Malicious verdict system
- 📊 Risk scoring with detailed findings
- 🖥️ Modern Tkinter desktop GUI
- 💻 Command Line Interface (CLI)
- 🗃️ SQLite history dashboard
- 📄 Export reports as PDF, JSON & CSV
- ⚡ Lightweight, fast and fully offline
- 🧪 Automated testing with PyTest

---

# 🔍 Detection Engines

## 📧 Header Analysis

Detects email spoofing and sender inconsistencies by analyzing:

- SPF validation
- DKIM validation
- DMARC validation
- Reply-To mismatch
- Expected sender domain mismatch

---

## 🌐 URL Analysis

Examines embedded URLs for common phishing techniques including:

- Typosquatting
- Homoglyph attacks
- URL shorteners
- Suspicious Top-Level Domains
- Subdomain traps
- Brand impersonation

---

## 🧠 Psychological Trigger Detection

Detects common social engineering techniques including:

- Urgency
- Fear
- Authority
- Curiosity
- Financial incentives
- Password reset scams
- Account verification requests
- MFA fatigue attacks

---

## 📎 Attachment Analysis

Identifies potentially dangerous attachments including:

- Executable files
- Script files
- Macro-enabled Office documents
- Archive files
- Double-extension attacks

---

# 🚦 Verdict System

Each analyzed email receives an overall verdict.

🟢 **Safe**

No significant phishing indicators detected.

🟡 **Suspicious**

Some phishing indicators were identified. Manual review is recommended.

🔴 **Malicious**

Multiple high-confidence phishing indicators were detected. Immediate action is recommended.

---

# 📄 Report Generation

Export analysis results as:

- PDF
- JSON
- CSV

Each report includes:

- Overall verdict
- Risk score
- Detection summary
- Triggered indicators
- Recommended actions

---

# 📊 Analysis History

Every scan is automatically stored inside a local SQLite database.

Stored information includes:

- Email filename
- Verdict
- Risk score
- Analysis timestamp
- Report information

---

# ⚙️ Configuration

Detection rules are data-driven and can be customized without changing the Python source code.

| File | Purpose |
|------|---------|
| `brand_domains.json` | Trusted brands, homoglyph mappings, URL shorteners and suspicious TLDs |
| `trigger_keywords.json` | Social engineering keywords and weighted trigger categories |
| `dangerous_extensions.json` | Dangerous attachment types and detection rules |

---

# 🛠️ Technologies Used

- Python 3
- Tkinter
- SQLite3
- JSON
- PyTest
- Object-Oriented Programming (OOP)

---

# 📁 Project Structure

```text
PhishGuard/
│
├── main.py
├── gui.py
├── cli.py
├── requirements.txt
├── README.md
│
├── analyzers/
│   ├── header_analyzer.py
│   ├── url_analyzer.py
│   ├── keyword_analyzer.py
│   └── attachment_analyzer.py
│
├── core/
│   ├── email_parser.py
│   ├── scoring_engine.py
│   ├── report_generator.py
│   └── database.py
│
├── data/
│   ├── brand_domains.json
│   ├── trigger_keywords.json
│   ├── dangerous_extensions.json
│   └── sample_emails/
│
├── reports/
│
└── tests/
    └── test_analyzers.py
```

---

# 🚀 Installation

## Clone the repository

```bash
git clone https://github.com/yourusername/PhishGuard.git
cd PhishGuard
```

## Install dependencies

```bash
pip install -r requirements.txt
```

## Run the application

```bash
python main.py
```

---

# 💻 Command Line Usage

```bash
python cli.py sample_email.txt
```

---

# 🖥️ Desktop Usage

1. Launch PhishGuard.
2. Open an email file or paste raw email content.
3. Click **Analyze**.
4. Review the findings from all four detection engines.
5. View the overall verdict and risk score.
6. Export the report if desired.
7. Browse previous analyses from the history database.

---

# 🧪 Running Tests

Install PyTest:

```bash
pip install pytest
```

Run the test suite:

```bash
pytest tests -v
```

The automated tests validate:

- Email parsing
- Header analysis
- URL detection
- Keyword detection
- Attachment analysis
- Risk scoring
- Verdict generation

---

# 🎯 Future Enhancements

- WHOIS & Domain Age Lookup
- VirusTotal Integration
- AbuseIPDB Integration
- QR Code Phishing Detection
- Browser-in-the-Browser Detection
- HTML Email Analysis
- Batch Email Processing
- Multi-language Detection
- Web Dashboard (Flask/FastAPI)
- AI-powered threat explanation

---

# 📸 Screenshots

<img width="1919" height="1018" alt="image" src="https://github.com/user-attachments/assets/943fa59b-94b3-439f-9427-0ece08753f5a" />
<img width="1919" height="1015" alt="image" src="https://github.com/user-attachments/assets/ee717370-9bf7-4527-8aac-65c5ba22082a" />
<img width="1919" height="1019" alt="image" src="https://github.com/user-attachments/assets/f7729609-e1b4-4f0b-bd33-35e7f772cf46" />
<img width="1919" height="1018" alt="image" src="https://github.com/user-attachments/assets/73bc7824-9d88-46da-96e2-2954abbdf982" />

---

# 🤝 Contributing

Contributions are welcome!

If you'd like to improve PhishGuard:

1. Fork the repository.
2. Create a new feature branch.
3. Add tests for your changes.
4. Ensure all tests pass.
5. Submit a Pull Request.

---

# 📄 License

This project is licensed under the **MIT License**.

See the `LICENSE` file for details.

---

# 👨‍💻 Author

**Humair Ali**

Cybersecurity & Software Engineering Student

Interested in:

- Blue Team Security
- Threat Detection
- Ethical Hacking
- Python Development
- Digital Forensics
- Malware Analysis

---

<div align="center">

## 🛡️ PhishGuard

**Offline • Explainable • Privacy-First • Defensive by Design**

⭐ If you found this project useful, consider giving it a star!

</div>
