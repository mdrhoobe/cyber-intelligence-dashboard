# ⬡ Cyber Intelligence Dashboard

> An educational OSINT web platform built with Python & Flask.  
> Username investigation · Domain analysis · Report management.

---

## ✦ Features

| Module | Description |
|---|---|
| 🗂 Dashboard | Stats overview, radar indicator, recent activity |
| 👤 Username Scan | Checks 16 platforms (GitHub, Instagram, Reddit, TikTok…) |
| 🌐 Domain Analyzer | DNS · IP · HTTP/HTTPS status · SSL · Server headers |
| 📁 Reports | Auto-saves every investigation as JSON |
| ℹ️ About | Project info, roadmap, technologies |

---

## ✦ Screenshots

> Add screenshots to the `screenshots/` folder after running the app.

---

## ✦ Project Structure

```
cyber-intelligence-dashboard/
│
├── app.py                  ← Flask backend (all routes + logic)
│
├── templates/
│   ├── base.html           ← Sidebar layout, topbar, fonts
│   ├── dashboard.html      ← Home stats + radar + quick actions
│   ├── username.html       ← Username scan + results grid
│   ├── domain.html         ← Domain readout panel
│   ├── reports.html        ← Saved investigations table
│   └── about.html          ← Project info + roadmap + author
│
├── static/
│   ├── css/style.css       ← Tactical Dark theme
│   └── js/main.js          ← Clock · Loading · Sidebar toggle
│
├── reports/
│   └── results.json        ← Auto-created on first scan
│
├── screenshots/            ← Add your own screenshots here
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ✦ Setup & Run

Choose your platform:

---

### 🤖 Android — Termux

```bash
# 1. Install Termux from F-Droid (not Play Store)
# 2. Update packages
pkg update && pkg upgrade -y

# 3. Install Python and Git
pkg install python git -y

# 4. Clone the project
git clone https://github.com/YOUR_USERNAME/cyber-intelligence-dashboard.git
cd cyber-intelligence-dashboard

# 5. Install dependencies
pip install -r requirements.txt

# 6. Run the app
python app.py
```

Open your browser and go to: **`http://127.0.0.1:5000`**

---

### 🐧 Linux (Ubuntu / Debian / Kali)

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Python 3 and pip (if not already installed)
sudo apt install python3 python3-pip git -y

# 3. Clone the project
git clone https://github.com/YOUR_USERNAME/cyber-intelligence-dashboard.git
cd cyber-intelligence-dashboard

# 4. (Optional but recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 5. Install dependencies
pip install -r requirements.txt

# 6. Run the app
python3 app.py
```

Open your browser and go to: **`http://127.0.0.1:5000`**

---

### 🪟 Windows

```powershell
# 1. Install Python from https://python.org (check "Add to PATH")
# 2. Install Git from https://git-scm.com

# 3. Open Command Prompt or PowerShell
git clone https://github.com/YOUR_USERNAME/cyber-intelligence-dashboard.git
cd cyber-intelligence-dashboard

# 4. (Optional) Create a virtual environment
python -m venv venv
venv\Scripts\activate

# 5. Install dependencies
pip install -r requirements.txt

# 6. Run the app
python app.py
```

Open your browser and go to: **`http://127.0.0.1:5000`**

---

## ✦ Upload to GitHub — Step by Step

Follow these steps exactly once to publish your project.

---

### Step 1 — Create a GitHub Account

Go to **https://github.com** and sign up if you don't have an account.

---

### Step 2 — Create a New Repository

1. Click the **`+`** button (top-right) → **New repository**
2. Repository name: `cyber-intelligence-dashboard`
3. Description: `Web-based OSINT dashboard built with Python & Flask`
4. Set to **Public** (or Private)
5. ❌ Do NOT check "Initialize this repository" (we'll push our own code)
6. Click **Create repository**

---

### Step 3 — Configure Git (first time only)

```bash
git config --global user.name "Mohammed Saleh"
git config --global user.email "your@email.com"
```

---

### Step 4 — Initialize and Push

Run these commands inside your project folder:

```bash
# Go into the project directory
cd cyber-intelligence-dashboard

# Initialize git
git init

# Add all files
git add .

# First commit
git commit -m "🚀 Initial commit — Cyber Intelligence Dashboard v1.0.0"

# Set main branch
git branch -M main

# Link to your GitHub repository (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/cyber-intelligence-dashboard.git

# Push to GitHub
git push -u origin main
```

GitHub will ask for your username and password.  
> ⚠️ Use a **Personal Access Token** instead of your password.  
> Get one at: **GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)**

---

### Step 5 — Verify

Go to `https://github.com/YOUR_USERNAME/cyber-intelligence-dashboard`  
Your project should now be live on GitHub. ✅

---

### Future Updates (after making changes)

```bash
git add .
git commit -m "✨ Added new feature / fixed bug"
git push
```

---

## ✦ Platforms Checked (Username Scan)

```
GitHub · GitLab · Dev.to · Twitter/X · Instagram · Reddit
TikTok · Pinterest · YouTube · Twitch · LinkedIn · Medium
HackerNews · Steam · SoundCloud · Pastebin
```

---

## ✦ Roadmap

- **v1.0** — Dashboard · Username Scan · Domain Analyzer · Reports ✅
- **v2.0** — SQLite database · Search history · Statistics charts · Dark mode toggle
- **v3.0** — PDF export · Interactive charts · REST API
- **v4.0** — Full OSINT Suite · Threat intelligence · Data visualization

---

## ✦ Disclaimer

> This tool is intended for **educational and ethical research purposes only**.  
> Always obtain proper authorization before investigating any target.  
> The author is not responsible for any misuse of this software.

---

## ✦ Author

**Mohammed Saleh** — Cybersecurity & OSINT Learner  
GitHub: [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)
