# Cyber Intelligence Dashboard

A web-based OSINT platform I built while learning Python, Flask, and cybersecurity. Started as a simple username checker, grew into a 15-tool intelligence suite.

---

## What it does

**Target Analyzer** is the main module — enter any IP or domain and it runs 6 scans simultaneously: geolocation, DNS, port scan, WHOIS, security headers, and HTTP/SSL analysis. Results come back in one tabbed report with a threat score.

| Module | Description |
|---|---|
| Target Analyzer | All-in-one: IP, DNS, Ports, WHOIS, Headers, SSL |
| Username Scan | Checks 16 platforms simultaneously |
| Bulk Scan | Multiple usernames and domains at once |
| Email Checker | Format, MX records, provider, disposable detection |
| Domain Analyzer | HTTP/HTTPS status, SSL, server headers |
| IP Lookup | Geolocation, ISP, proxy/VPN detection |
| DNS Lookup | A, AAAA, MX, NS, TXT, SOA, CAA records |
| Port Scanner | 16 common ports with service detection |
| Security Headers | A-F grade, CSP, HSTS, X-Frame-Options |
| SSL Inspector | Certificate details, expiry countdown, SANs |
| Subdomain Scanner | DNS-based discovery against 50 common names |
| Tech Fingerprint | Server, CMS, CDN, Analytics, Framework detection |
| WHOIS Lookup | Registrar, dates, nameservers |
| Hash Tools | MD5, SHA-1, SHA-256, SHA-512, SHA3-256 |
| URL Analyzer | Parse, redirect tracking, encode/decode |

Everything saves automatically to SQLite and can be exported as PDF.

---

## Stack

Python 3, Flask, SQLite, dnspython, python-whois, ReportLab, Chart.js

---

## Setup
git clone https://github.com/mdrhoobe/cyber-intelligence-dashboard.git
cd cyber-intelligence-dashboard
pip install -r requirements.txt
python app.py

Open http://127.0.0.1:5000 in your browser.
Default password: cid2025 (change it in app.py before sharing)

---

## Termux (Android)
pkg install python git
pip install flask requests python-whois dnspython
python app.py

---

## Linux
pip3 install -r requirements.txt
python3 app.py

---

## Project structure
cid/
├── app.py          main Flask backend
├── db.py           SQLite database layer
├── templates/      HTML templates (20 files)
├── static/
│   ├── css/        dark theme stylesheet
│   └── js/         clock, loading, sidebar
├── reports/        SQLite DB stored here
└── requirements.txt

---

## Known issues

- Some platforms return 200 for non-existent usernames. Treat results as leads, not confirmed facts.
- Port scanner uses a short timeout for speed. Results may vary on slow connections.
- WHOIS data depends on registrar privacy settings.
- Tech fingerprinting is heuristic-based, not exhaustive.

---

## Roadmap

- [x] Username scanner across 16 platforms
- [x] Domain analyzer with SSL and headers
- [x] SQLite database with search and filter
- [x] Statistics page with charts
- [x] IP lookup, DNS, ports, security headers
- [x] SSL inspector, subdomain scanner, tech fingerprint
- [x] Target Analyzer combining all tools
- [x] Hash tools and URL analyzer
- [x] PDF export, dark/light mode, login system
- [ ] REST API endpoints
- [ ] Threat intelligence feed integration
- [ ] Scheduled and automated scans

---

## Disclaimer

Educational and research purposes only.
Only scan targets you have explicit permission to investigate.
Port scanning without authorization may be illegal in your jurisdiction.

---

Built by Mohammed Salih — learning cybersecurity and OSINT.
