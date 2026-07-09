
# 🦅 HawkEye — AI-Assisted Bug Hunting Framework

> Modular bug hunting tool with CLI + Web Dashboard. Covers web vulnerabilities (XSS, SQLi, IDOR, SSRF), network scanning, and API security — with an AI layer that scores risk and explains every finding in plain English.

**Built by [Kalpin Patel](https://github.com/kalpin05) | B.Tech CS (AI & ML) — Adani University**

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![React](https://img.shields.io/badge/React-18-cyan)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ⚠️ Legal Disclaimer

HawkEye is for **authorized security testing only**. Only scan systems you own or have **written permission** to test. Unauthorized scanning is illegal under India's IT Act and equivalent laws worldwide. The author is not responsible for misuse.

---

## 🚀 Features

- **6 Security Modules** — Headers/SSL, Network, XSS, SQLi, IDOR, SSRF, API Security
- **AI Triage Engine** — Groq LLaMA3 explains every finding in plain English with risk score 0-10
- **Dual Interface** — CLI for power users + Web Dashboard for clients
- **3 Report Formats** — JSON, HTML, PDF
- **Rule-based Fallback** — Works even without an AI API key
- **Threaded Scanning** — 100 parallel workers for fast network scans

---

## 📦 Quick Start

```bash
# Clone
git clone https://github.com/kalpin05/hawkeye.git
cd hawkeye

# Install
pip install -r requirements.txt

# CLI
python hawkeye.py --help

# Web Dashboard
uvicorn api.main:app --reload --port 8000
cd dashboard && npm install && npm start
```

---

## 🖥️ CLI Usage

```bash
# Full scan — all modules
python hawkeye.py scan --target https://example.com --all

# Specific modules
python hawkeye.py scan --target https://example.com --headers --web
python hawkeye.py scan --target 192.168.1.1 --network --fast
python hawkeye.py scan --target https://api.example.com --api

# With AI triage
set GROQ_API_KEY=your_key_here
python hawkeye.py scan --target https://example.com --all --ai

# Export reports
python hawkeye.py scan --target https://example.com --all --output pdf
python hawkeye.py scan --target https://example.com --all --output html
python hawkeye.py scan --target https://example.com --all --output json
```

---

## 🧩 Modules

| Module | Flag | What it detects |
|---|---|---|
| Header & SSL Checker | `--headers` | Missing CSP, HSTS, X-Frame-Options, cookie flags, SSL expiry, weak TLS |
| Network Scanner | `--network` | Open ports, dangerous services (Redis, MongoDB, RDP, SMB, Docker) |
| Web Vulnerability Scanner | `--web` | XSS, SQL injection, IDOR, SSRF |
| API Security Tester | `--api` | Broken auth, missing rate limiting, CORS misconfiguration, exposed docs |
| AI Triage Engine | `--ai` | Risk scoring 0-10, plain English explanation, fix recommendations |
| Report Generator | `--output` | JSON, HTML, PDF reports with executive summary |

---

## 🏗️ Architecture
---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| CLI | Python, Click, Rich |
| Web Scanning | Requests, BeautifulSoup |
| Network | python-nmap, socket (threaded) |
| Subdomain Enum | crt.sh API, AlienVault OTX, HackerTarget, DNS |
| AI Triage | Groq API (LLaMA3-8b) + rule-based fallback |
| Authentication | Requests sessions, form detection, token auth |
| Backend API | FastAPI, SQLite, Uvicorn, APScheduler |
| Frontend | React 18, Recharts, Axios |
| Reports | WeasyPrint, Jinja2 |
| Proxy/Stealth | SOCKS5 (Tor), rotating user agents, random delays |

---

## 🧪 Testing

```bash
# Install pytest
pip install pytest

# Run all tests
python -m pytest tests/ -v

# Run specific sprint
python -m pytest tests/test_sprint14.py -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/ --cov=modules --cov-report=term-missing
```

**207 tests across 14 sprints — all passing.**

---

## 🔑 AI Triage Setup

```bash
# Get free API key at console.groq.com

# Windows
set GROQ_API_KEY=your_key_here

# Linux/Mac
export GROQ_API_KEY=your_key_here

# Scan with AI
python hawkeye.py scan --target https://example.com --headers --ai
```

Works without a key too — falls back to intelligent rule-based triage automatically.

---

## 🎯 Legal Test Targets

```bash
# 100% legal — intentionally vulnerable sites
python hawkeye.py scan --target http://testphp.vulnweb.com --all --fast
python hawkeye.py scan --target http://testphp.vulnweb.com --web --ai

# For network scanning — your own local network only
python hawkeye.py scan --target 192.168.1.1 --network --fast
```

---

## 📋 Project Roadmap

- [x] Sprint 1 — CLI skeleton
- [x] Sprint 2 — Header & SSL checker
- [x] Sprint 3 — Network scanner
- [x] Sprint 4 — XSS + SQLi scanner
- [x] Sprint 5 — IDOR + SSRF scanner
- [x] Sprint 6 — API security tester
- [x] Sprint 7 — AI triage engine
- [x] Sprint 8 — Report generator
- [x] Sprint 9 — FastAPI + React dashboard
- [x] Sprint 10 — Launch
- [x] Sprint 11 — Subdomain enumeration
- [x] Sprint 12 — Authenticated scanning
- [x] Sprint 13 — Business logic scanner
- [x] Sprint 14 — Differential scanning
- [ ] Sprint 15 — Headless browser (JavaScript-rendered pages)
- [ ] Sprint 16 — JWT/session attack testing
- [ ] Sprint 17 — Scheduled email reports

---

## ⚠️ Legal Disclaimer

HawkEye is designed for **authorized security testing and educational purposes only**.

- ✅ Scan systems you **own**
- ✅ Scan with **written permission** from the target owner
- ✅ Use on **CTF platforms** (HackTheBox, TryHackMe, DVWA)
- ❌ Never scan systems without explicit authorization
- ❌ Unauthorized scanning violates India's IT Act 2000 and equivalent laws worldwide

The author accepts no liability for misuse.

---

## 🤝 Contributing

Pull requests welcome! Please:
1. Test on authorized environments only
2. Add tests for new modules
3. Follow the existing sprint structure

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file.

---

## 👨‍💻 Author

**Kalpin Patel**
- B.Tech CS (AI & ML) — Adani University, Gujarat
- Executional Head — Cyber Sphere Club
- [LinkedIn](https://linkedin.com/in/kalpin-patel-5644762a8)
- [GitHub](https://github.com/kalpin05)
- 📧 skpatel12311@gmail.com

---

<div align="center">

**If HawkEye helped you, give it a ⭐ on GitHub!**

*Built with ❤️ and 14 Agile sprints*

</div>