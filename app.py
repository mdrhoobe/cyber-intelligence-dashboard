"""
╔══════════════════════════════════════╗
║   CYBER INTELLIGENCE DASHBOARD       ║
║   Backend  ·  Flask  ·  v1.0.0       ║
║   Author   : Mohammed Saleh          ║
╚══════════════════════════════════════╝
"""

from flask import Flask, render_template, request, redirect, url_for
import requests, json, os, socket, time
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'cid-secret-2025-ms'

# ── Config ────────────────────────────────────────────────
REPORTS_DIR  = 'reports'
REPORTS_FILE = os.path.join(REPORTS_DIR, 'results.json')
os.makedirs(REPORTS_DIR, exist_ok=True)

PLATFORMS = [
    {'name': 'GitHub',     'url': 'https://github.com/{}',                     'cat': 'dev',      'icon': '🐙'},
    {'name': 'GitLab',     'url': 'https://gitlab.com/{}',                     'cat': 'dev',      'icon': '🦊'},
    {'name': 'Dev.to',     'url': 'https://dev.to/{}',                         'cat': 'dev',      'icon': '💻'},
    {'name': 'Twitter/X',  'url': 'https://x.com/{}',                          'cat': 'social',   'icon': '🐦'},
    {'name': 'Instagram',  'url': 'https://www.instagram.com/{}/',              'cat': 'social',   'icon': '📸'},
    {'name': 'Reddit',     'url': 'https://www.reddit.com/user/{}',             'cat': 'social',   'icon': '👾'},
    {'name': 'TikTok',     'url': 'https://www.tiktok.com/@{}',                'cat': 'social',   'icon': '🎵'},
    {'name': 'Pinterest',  'url': 'https://www.pinterest.com/{}/',              'cat': 'social',   'icon': '📌'},
    {'name': 'YouTube',    'url': 'https://www.youtube.com/@{}',               'cat': 'video',    'icon': '▶️'},
    {'name': 'Twitch',     'url': 'https://www.twitch.tv/{}',                  'cat': 'video',    'icon': '🎮'},
    {'name': 'LinkedIn',   'url': 'https://www.linkedin.com/in/{}',            'cat': 'pro',      'icon': '💼'},
    {'name': 'Medium',     'url': 'https://medium.com/@{}',                    'cat': 'blog',     'icon': '✍️'},
    {'name': 'SoundCloud', 'url': 'https://soundcloud.com/{}',                 'cat': 'music',    'icon': '🎧'},
    {'name': 'Steam',      'url': 'https://steamcommunity.com/id/{}',          'cat': 'gaming',   'icon': '🎲'},
    {'name': 'HackerNews', 'url': 'https://news.ycombinator.com/user?id={}',  'cat': 'dev',      'icon': '🔶'},
    {'name': 'Pastebin',   'url': 'https://pastebin.com/u/{}',                 'cat': 'dev',      'icon': '📋'},
]

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

# ── Reports helpers ───────────────────────────────────────
def load_reports():
    if os.path.exists(REPORTS_FILE):
        try:
            with open(REPORTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_report(rtype, target, results, summary=None):
    reports = load_reports()
    report  = {
        'id':        len(reports) + 1,
        'type':      rtype,
        'target':    target,
        'results':   results,
        'summary':   summary or {},
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    reports.append(report)
    with open(REPORTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)
    return report

# ── Username checker ──────────────────────────────────────
def check_username(username):
    found = not_found = errors = 0
    results = []

    for p in PLATFORMS:
        url = p['url'].format(username)
        try:
            t0 = time.time()
            r  = requests.get(url, headers=HEADERS, timeout=6, allow_redirects=True)
            ms = round((time.time() - t0) * 1000)

            if r.status_code == 200:
                status = 'found';     found     += 1
            elif r.status_code in (404, 410):
                status = 'not_found'; not_found += 1
            else:
                status = 'unknown';   errors    += 1

            results.append({
                'platform': p['name'], 'url': url, 'icon': p['icon'],
                'cat': p['cat'],       'status': status,
                'code': r.status_code, 'ms': ms,
            })
        except requests.exceptions.Timeout:
            results.append({'platform': p['name'], 'url': url, 'icon': p['icon'],
                            'cat': p['cat'], 'status': 'timeout', 'code': None, 'ms': None})
            errors += 1
        except Exception:
            results.append({'platform': p['name'], 'url': url, 'icon': p['icon'],
                            'cat': p['cat'], 'status': 'error', 'code': None, 'ms': None})
            errors += 1

    summary = {'total': len(results), 'found': found,
               'not_found': not_found, 'errors': errors}
    return results, summary

# ── Domain analyzer ───────────────────────────────────────
def check_domain(raw):
    domain = (raw.strip()
                 .replace('https://', '')
                 .replace('http://', '')
                 .replace('www.', '')
                 .split('/')[0]
                 .split('?')[0])

    info = {
        'domain':        domain,
        'ip':            None,
        'http_status':   None,
        'https_status':  None,
        'response_time': None,
        'server':        None,
        'content_type':  None,
        'reachable':     False,
        'ssl':           False,
        'redirect':      None,
        'error':         None,
    }

    # DNS
    try:
        info['ip'] = socket.gethostbyname(domain)
    except socket.gaierror as e:
        info['error'] = f'DNS lookup failed — {e}'
        return info

    # HTTPS
    try:
        t0 = time.time()
        r  = requests.get(f'https://{domain}', headers=HEADERS,
                          timeout=8, allow_redirects=True)
        info.update({
            'https_status':  r.status_code,
            'response_time': round((time.time() - t0) * 1000),
            'reachable':     True,
            'ssl':           True,
            'server':        r.headers.get('Server', 'Unknown'),
            'content_type':  r.headers.get('Content-Type', 'Unknown').split(';')[0],
            'redirect':      r.url if r.url != f'https://{domain}' else None,
        })
    except requests.exceptions.SSLError:
        info['https_status'] = 'SSL Error'
    except Exception:
        info['https_status'] = 'Unreachable'

    # HTTP
    try:
        r = requests.get(f'http://{domain}', headers=HEADERS,
                         timeout=5, allow_redirects=False)
        info['http_status'] = r.status_code
        if not info['reachable']:
            info['reachable'] = True
    except Exception:
        info['http_status'] = 'Unreachable'

    return info

# ── Routes ────────────────────────────────────────────────
@app.route('/')
def dashboard():
    reports       = load_reports()
    uname_count   = sum(1 for r in reports if r.get('type') == 'username')
    domain_count  = sum(1 for r in reports if r.get('type') == 'domain')
    recent        = list(reversed(reports))[:5]
    return render_template(
        'dashboard.html',
        total=len(reports),
        uname=uname_count,
        domain=domain_count,
        recent=recent,
        active='dashboard',
    )

@app.route('/username', methods=['GET', 'POST'])
def username():
    results = summary = searched = None
    if request.method == 'POST':
        searched = request.form.get('username', '').strip()
        if searched:
            results, summary = check_username(searched)
            save_report('username', searched, results, summary)
    return render_template('username.html', results=results,
                           summary=summary, searched=searched, active='username')

@app.route('/domain', methods=['GET', 'POST'])
def domain():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('domain', '').strip()
        if searched:
            result = check_domain(searched)
            save_report('domain', searched, result)
    return render_template('domain.html', result=result,
                           searched=searched, active='domain')

@app.route('/reports')
def reports():
    all_reports = list(reversed(load_reports()))
    return render_template('reports.html', reports=all_reports, active='reports')

@app.route('/reports/clear', methods=['POST'])
def clear_reports():
    if os.path.exists(REPORTS_FILE):
        os.remove(REPORTS_FILE)
    return redirect(url_for('reports'))

@app.route('/about')
def about():
    return render_template('about.html', active='about')

# ── Run ───────────────────────────────────────────────────
if __name__ == '__main__':
    print('\n\033[36m  ╔════════════════════════════════════╗')
    print('  ║   CYBER INTELLIGENCE DASHBOARD     ║')
    print('  ║   Mohammed Saleh  ·  v1.0.0         ║')
    print('  ╚════════════════════════════════════╝\033[0m')
    print(f'\033[32m  ✓  http://127.0.0.1:5000\033[0m')
    print(f'\033[33m  ⚡  Debug mode ON — do not use in production\033[0m\n')
    app.run(debug=True, host='0.0.0.0', port=5000)
