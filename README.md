# Cyber Intelligence Dashboard

A web-based OSINT tool I built while learning Python, Flask, and cybersecurity basics. The idea was to combine a few useful investigation tools in one place instead of jumping between different scripts.

The project is actively maintained and new modules are planned.
---

## What it does

**Username scan** — enter any username and it checks across 16 platforms simultaneously (GitHub, Instagram, Reddit, TikTok, Twitch, Steam, and more). Results show whether the account exists, with response time for each platform.

**Domain analyzer** — takes a domain name and returns the IP address, HTTP/HTTPS status codes, SSL certificate status, server header, and response time. Useful for quick recon on a target domain.

**Reports** — every scan is automatically saved to a JSON file so you can go back and review old results without re-running the scan.

**Dashboard** — overview of all your past investigations with quick access to each module.

---

## Screenshots

*will add after final UI polish*

---

## Setup

**Requirements:** Python 3.8 or higher

```bash
git clone https://github.com/mdrhoobe/cyber-intelligence-dashboard.git
cd cyber-intelligence-dashboard
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

**On Termux (Android):**

```bash
pkg install python git
pip install flask requests
python app.py
```

---

**On Linux:**

```bash
sudo apt install python3 python3-pip -y
pip3 install flask requests
python3 app.py
```

---

## Project structure

```
cyber-intelligence-dashboard/
├── app.py                  # Flask backend, all routes and logic
├── templates/
│   ├── base.html           # main layout, sidebar, navigation
│   ├── dashboard.html
│   ├── username.html
│   ├── domain.html
│   ├── reports.html
│   └── about.html
├── static/
│   ├── css/style.css
│   └── js/main.js
├── reports/                # scan results saved here as JSON
├── requirements.txt
└── README.md
```

---

## Platforms checked (username scan)

GitHub, GitLab, Twitter/X, Instagram, Reddit, TikTok, YouTube, Twitch, Pinterest, LinkedIn, Medium, Dev.to, HackerNews, Steam, SoundCloud, Pastebin

---

## Roadmap

- [x] Username scanner (16 platforms)
- [x] Domain analyzer
- [x] Auto-save reports
- [ ] SQLite database instead of flat JSON
- [ ] Search history and filtering
- [ ] PDF report export
- [ ] Statistics and charts
- [ ] More OSINT modules

---

## Known issues / notes

- Some platforms return a 200 status even for usernames that don't exist (they redirect to a default page instead of returning 404). So treat "found" results as leads, not confirmed facts — always verify manually.
- The app runs in debug mode by default. Not meant for public deployment.
- Response times vary a lot depending on your connection and how the platform responds.

---

## Disclaimer

This project is for educational and research purposes only. Only use it on targets you have explicit permission to investigate. I'm not responsible for any misuse.

---

Built by Mohammed Drhoobe — learning cybersecurity and OSINT.
