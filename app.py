from flask import Flask, render_template, request, redirect, url_for, session, make_response
from functools import wraps
import requests, socket, time, json, io, re
from db import (init_db, save_report, get_all_reports,
                get_recent_reports, count_reports,
                clear_reports, get_stats_data, search_reports)
from threat import full_threat_report
app = Flask(__name__)
app.secret_key = 'ms-secret-2026-xyz'
init_db()

PASSWORD = 'cid2025'

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

PLATFORMS = [
    {'name':'GitHub',    'url':'https://github.com/{}',                   'cat':'dev',    'icon':'🐙'},
    {'name':'GitLab',    'url':'https://gitlab.com/{}',                   'cat':'dev',    'icon':'🦊'},
    {'name':'Dev.to',    'url':'https://dev.to/{}',                       'cat':'dev',    'icon':'💻'},
    {'name':'Twitter/X', 'url':'https://x.com/{}',                        'cat':'social', 'icon':'🐦'},
    {'name':'Instagram', 'url':'https://www.instagram.com/{}/',            'cat':'social', 'icon':'📸'},
    {'name':'Reddit',    'url':'https://www.reddit.com/user/{}',           'cat':'social', 'icon':'👾'},
    {'name':'TikTok',    'url':'https://www.tiktok.com/@{}',              'cat':'social', 'icon':'🎵'},
    {'name':'Pinterest', 'url':'https://www.pinterest.com/{}/',            'cat':'social', 'icon':'📌'},
    {'name':'YouTube',   'url':'https://www.youtube.com/@{}',             'cat':'video',  'icon':'▶️'},
    {'name':'Twitch',    'url':'https://www.twitch.tv/{}',                'cat':'video',  'icon':'🎮'},
    {'name':'LinkedIn',  'url':'https://www.linkedin.com/in/{}',          'cat':'pro',    'icon':'💼'},
    {'name':'Medium',    'url':'https://medium.com/@{}',                  'cat':'blog',   'icon':'✍️'},
    {'name':'SoundCloud','url':'https://soundcloud.com/{}',               'cat':'music',  'icon':'🎧'},
    {'name':'Steam',     'url':'https://steamcommunity.com/id/{}',        'cat':'gaming', 'icon':'🎲'},
    {'name':'HackerNews','url':'https://news.ycombinator.com/user?id={}','cat':'dev',    'icon':'🔶'},
    {'name':'Pastebin',  'url':'https://pastebin.com/u/{}',               'cat':'dev',    'icon':'📋'},
]

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
}

# ── Username checker ──────────────────────────────────────
def check_username(username):
    found = not_found = errors = 0
    results = []
    for p in PLATFORMS:
        url = p['url'].format(username)
        try:
            t0 = time.time()
            r  = requests.get(url, headers=HEADERS, timeout=6, allow_redirects=True)
            ms = round((time.time()-t0)*1000)
            if r.status_code == 200:
                status = 'found';     found     += 1
            elif r.status_code in (404, 410):
                status = 'not_found'; not_found += 1
            else:
                status = 'unknown';   errors    += 1
            results.append({'platform':p['name'],'url':url,'icon':p['icon'],
                            'cat':p['cat'],'status':status,'code':r.status_code,'ms':ms})
        except requests.exceptions.Timeout:
            results.append({'platform':p['name'],'url':url,'icon':p['icon'],
                            'cat':p['cat'],'status':'timeout','code':None,'ms':None})
            errors += 1
        except:
            results.append({'platform':p['name'],'url':url,'icon':p['icon'],
                            'cat':p['cat'],'status':'error','code':None,'ms':None})
            errors += 1
    return results, {'total':len(results),'found':found,'not_found':not_found,'errors':errors}

# ── Domain checker ────────────────────────────────────────
def check_domain(raw):
    domain = raw.strip().replace('https://','').replace('http://','').replace('www.','').split('/')[0].split('?')[0]
    info = {'domain':domain,'ip':None,'http_status':None,'https_status':None,
            'response_time':None,'server':None,'content_type':None,
            'reachable':False,'ssl':False,'redirect':None,'error':None}
    try:
        info['ip'] = socket.gethostbyname(domain)
    except socket.gaierror as e:
        info['error'] = f'DNS lookup failed — {e}'
        return info
    try:
        t0 = time.time()
        r  = requests.get(f'https://{domain}', headers=HEADERS, timeout=8, allow_redirects=True)
        info.update({'https_status':r.status_code,'response_time':round((time.time()-t0)*1000),
                     'reachable':True,'ssl':True,'server':r.headers.get('Server','Unknown'),
                     'content_type':r.headers.get('Content-Type','Unknown').split(';')[0],
                     'redirect':r.url if r.url!=f'https://{domain}' else None})
    except requests.exceptions.SSLError:
        info['https_status'] = 'SSL Error'
    except:
        info['https_status'] = 'Unreachable'
    try:
        r = requests.get(f'http://{domain}', headers=HEADERS, timeout=5, allow_redirects=False)
        info['http_status'] = r.status_code
        if not info['reachable']: info['reachable'] = True
    except:
        info['http_status'] = 'Unreachable'
    return info

# ── IP Lookup ─────────────────────────────────────────────
def lookup_ip(ip):
    try:
        fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query'
        r = requests.get(f'http://ip-api.com/json/{ip}?fields={fields}', timeout=8)
        return r.json()
    except Exception as e:
        return {'status': 'fail', 'message': str(e)}

# ── Email Checker ─────────────────────────────────────────
def check_email(email):
    result = {
        'email':       email,
        'valid_format': False,
        'domain':      '',
        'mx_records':  [],
        'mx_found':    False,
        'provider':    'Unknown',
        'disposable':  False,
        'error':       None,
    }

    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        result['error'] = 'Invalid email format'
        return result
    result['valid_format'] = True
    domain = email.split('@')[1]
    result['domain'] = domain

    # MX records
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, 'MX')
        result['mx_records'] = sorted([str(r.exchange) for r in mx])
        result['mx_found']   = True
    except Exception as e:
        result['error'] = f'MX lookup failed: {e}'

    # Provider detection
    providers = {
        'gmail.com': 'Gmail', 'googlemail.com': 'Gmail',
        'yahoo.com': 'Yahoo', 'yahoo.co.uk': 'Yahoo',
        'outlook.com': 'Outlook', 'hotmail.com': 'Hotmail',
        'live.com': 'Microsoft Live', 'icloud.com': 'Apple iCloud',
        'protonmail.com': 'ProtonMail', 'proton.me': 'ProtonMail',
        'tutanota.com': 'Tutanota', 'zoho.com': 'Zoho',
    }
    disposable = ['tempmail.com','10minutemail.com','guerrillamail.com',
                  'throwam.com','mailinator.com','yopmail.com']

    result['provider']   = providers.get(domain.lower(), 'Custom / Unknown')
    result['disposable'] = domain.lower() in disposable
    return result

# ── WHOIS Lookup ──────────────────────────────────────────
def get_whois(domain):
    domain = domain.strip().replace('https://','').replace('http://','').replace('www.','').split('/')[0]
    try:
        import whois
        w = whois.whois(domain)
        def fmt(val):
            if val is None: return '—'
            if isinstance(val, list):
                val = val[0] if val else '—'
            return str(val).split(' ')[0] if 'datetime' in type(val).__name__.lower() else str(val)
        ns = w.name_servers
        if isinstance(ns, list):
            ns = [str(n).lower() for n in ns]
        elif ns:
            ns = [str(ns).lower()]
        else:
            ns = []
        return {
            'domain':          domain,
            'registrar':       fmt(w.registrar),
            'creation_date':   fmt(w.creation_date),
            'expiration_date': fmt(w.expiration_date),
            'updated_date':    fmt(w.updated_date),
            'name_servers':    ns[:4],
            'status':          fmt(w.status),
            'emails':          fmt(w.emails),
            'country':         fmt(w.country),
            'org':             fmt(w.org),
            'error':           None,
        }
    except Exception as e:
        return {'domain': domain, 'error': str(e)}
# ── DNS Lookup ────────────────────────────────────────────
def dns_lookup(domain):
    domain = domain.strip().replace('https://','').replace('http://','').replace('www.','').split('/')[0]
    record_types = ['A','AAAA','MX','NS','TXT','CNAME','SOA','CAA']
    records = {}
    try:
        import dns.resolver
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except:
                records[rtype] = []
    except ImportError:
        return {'domain': domain, 'error': 'dnspython not installed', 'records': {}}
    
    has_any = any(len(v) > 0 for v in records.values())
    return {'domain': domain, 'records': records, 'has_any': has_any, 'error': None}

# ── Port Scanner ──────────────────────────────────────────
COMMON_PORTS = {
    21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
    80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
    3306:'MySQL', 5432:'PostgreSQL', 6379:'Redis',
    8080:'HTTP-Alt', 8443:'HTTPS-Alt', 27017:'MongoDB'
}

def port_scan(host):
    host = host.strip().replace('https://','').replace('http://','').replace('www.','').split('/')[0]
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {'host':host,'ip':None,'error':str(e),'ports':[],'open':0}
    results = []
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            status = 'open' if sock.connect_ex((ip, port)) == 0 else 'closed'
            sock.close()
        except:
            status = 'filtered'
        results.append({'port':port,'service':service,'status':status})
    open_count = sum(1 for r in results if r['status'] == 'open')
    return {'host':host,'ip':ip,'error':None,'ports':results,'open':open_count}

# ── Security Headers ──────────────────────────────────────
SEC_HEADERS = {
    'Strict-Transport-Security': {'name':'HSTS',              'risk':'high'},
    'Content-Security-Policy':   {'name':'CSP',               'risk':'high'},
    'X-Frame-Options':           {'name':'Clickjacking Guard', 'risk':'medium'},
    'X-Content-Type-Options':    {'name':'MIME Sniff Guard',   'risk':'medium'},
    'Referrer-Policy':           {'name':'Referrer Policy',    'risk':'low'},
    'Permissions-Policy':        {'name':'Permissions Policy', 'risk':'low'},
    'X-XSS-Protection':          {'name':'XSS Protection',     'risk':'medium'},
    'Cache-Control':             {'name':'Cache Control',      'risk':'low'},
}

def check_headers(url):
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        found, missing = {}, []
        for h, meta in SEC_HEADERS.items():
            if h in r.headers:
                found[h] = {'name':meta['name'],'value':r.headers[h],'risk':meta['risk']}
            else:
                missing.append({'header':h,'name':meta['name'],'risk':meta['risk']})
        score = round(len(found) / len(SEC_HEADERS) * 100)
        grade = 'A' if score>=87 else 'B' if score>=75 else 'C' if score>=50 else 'D' if score>=25 else 'F'
        server  = r.headers.get('Server','Hidden')
        powered = r.headers.get('X-Powered-By','Hidden')
        return {
            'url':url,'status':r.status_code,'found':found,'missing':missing,
            'score':score,'grade':grade,'server':server,'powered':powered,'error':None
        }
    except Exception as e:
        return {'url':url,'error':str(e),'found':{},'missing':[],'score':0,'grade':'F'}
# ── Universal Target Analyzer ─────────────────────────────
def universal_analyze(target):
    import concurrent.futures, re
    original = target.strip()
    clean    = original.replace('https://','').replace('http://','').replace('www.','').split('/')[0].split('?')[0].strip()
    is_ip    = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', clean))
    url_t    = f'https://{clean}'

    result = {'target':original,'clean':clean,'is_ip':is_ip,
              'ip_info':None,'dns':None,'ports':None,
              'whois':None,'headers':None,'domain_info':None}

    def _ip():
        ip = clean if is_ip else None
        if not is_ip:
            try:    ip = socket.gethostbyname(clean)
            except: return {'status':'fail','message':'DNS resolution failed'}
        return lookup_ip(ip) if ip else None

    tasks = {
        'ip_info':     _ip,
        'dns':         lambda: dns_lookup(clean)    if not is_ip else None,
        'ports':       lambda: port_scan(clean),
        'whois':       lambda: get_whois(clean)     if not is_ip else None,
        'headers':     lambda: check_headers(url_t),
        'domain_info': lambda: check_domain(clean)  if not is_ip else None,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {k: ex.submit(fn) for k, fn in tasks.items()}
        for k, f in futures.items():
            try:    result[k] = f.result(timeout=12)
            except: result[k] = None
    return result

# ── Hash Tools ────────────────────────────────────────────
import hashlib

def generate_hashes(text):
    enc = text.encode('utf-8')
    return {
        'MD5':      hashlib.md5(enc).hexdigest(),
        'SHA-1':    hashlib.sha1(enc).hexdigest(),
        'SHA-256':  hashlib.sha256(enc).hexdigest(),
        'SHA-512':  hashlib.sha512(enc).hexdigest(),
        'SHA3-256': hashlib.sha3_256(enc).hexdigest(),
    }

def detect_hash_type(h):
    types = {32:'MD5',40:'SHA-1',56:'SHA-224',64:'SHA-256/SHA3-256',96:'SHA-384',128:'SHA-512'}
    return types.get(len(h.strip()), 'Unknown')

# ── URL Analyzer ──────────────────────────────────────────
from urllib.parse import urlparse, parse_qs, quote, unquote
import base64

def analyze_url(url):
    if not url.startswith('http'): url = 'https://' + url
    p = urlparse(url)
    params = parse_qs(p.query)
    final = url; status = None; redirected = False
    try:
        r = requests.get(url, headers=HEADERS, timeout=6, allow_redirects=True)
        final = r.url; status = r.status_code
        redirected = final.rstrip('/') != url.rstrip('/')
    except: pass
    suspicious = any(kw in url.lower() for kw in ['eval(','base64','<script','javascript:','onload=','onerror='])
    return {
        'original':url,'scheme':p.scheme,'domain':p.netloc,
        'path':p.path or '/',
        'params':{k:v[0] for k,v in params.items()},
        'fragment':p.fragment,'final_url':final,
        'status':status,'redirected':redirected,
        'param_count':len(params),'suspicious':suspicious,
        'b64_encoded':  base64.b64encode(url.encode()).decode(),
        'url_encoded':  quote(url, safe=''),
        'url_decoded':  unquote(url),
    }


# ── SSL Certificate Inspector ─────────────────────────────
def ssl_inspect(domain):
    domain = domain.replace('https://','').replace('http://','').split('/')[0]
    try:
        import ssl as ssl_lib
        from datetime import datetime
        ctx  = ssl_lib.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
        expire     = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        start      = datetime.strptime(cert['notBefore'],'%b %d %H:%M:%S %Y %Z')
        days_left  = (expire - datetime.now()).days
        subject    = dict(x[0] for x in cert.get('subject', []))
        issuer     = dict(x[0] for x in cert.get('issuer', []))
        san        = [x[1] for x in cert.get('subjectAltName', []) if x[0]=='DNS']
        return {
            'domain':    domain,
            'cn':        subject.get('commonName', '—'),
            'org':       subject.get('organizationName', '—'),
            'issuer':    issuer.get('organizationName', '—'),
            'issuer_cn': issuer.get('commonName', '—'),
            'not_before':cert['notBefore'],
            'not_after': cert['notAfter'],
            'days_left': days_left,
            'expired':   days_left < 0,
            'soon':      0 <= days_left <= 30,
            'san':       san[:10],
            'wildcard':  any('*' in s for s in san),
            'error':     None
        }
    except ssl_lib.SSLCertVerificationError as e:
        return {'domain':domain,'error':f'Cert verification failed: {e}','expired':True}
    except Exception as e:
        return {'domain':domain,'error':str(e),'expired':False}

# ── Subdomain Scanner ─────────────────────────────────────
SUB_WORDLIST = [
    'www','mail','ftp','smtp','pop','ns1','ns2','ns3','cpanel',
    'webmail','blog','api','dev','test','staging','admin','portal',
    'vpn','remote','shop','cdn','cloud','app','mobile','static',
    'media','img','login','secure','support','docs','wiki','forum',
    'news','status','beta','git','monitor','panel','mx','web',
    'email','server','data','db','files','assets','dashboard','m',
]

def subdomain_scan(domain):
    domain = domain.replace('https://','').replace('http://','').split('/')[0]
    found  = []
    for sub in SUB_WORDLIST:
        target = f'{sub}.{domain}'
        try:
            ip = socket.gethostbyname(target)
            found.append({'subdomain': target, 'ip': ip})
        except: pass
    return {
        'domain':  domain,
        'found':   found,
        'count':   len(found),
        'checked': len(SUB_WORDLIST),
    }

# ── Technology Fingerprinting ─────────────────────────────
def tech_fingerprint(url):
    if not url.startswith('http'): url = 'https://' + url
    categories = {
        'Server': [],    'Backend': [],   'Frontend': [],
        'CMS': [],       'Security': [],  'CDN': [],
        'Analytics': [], 'Database': [],
    }
    try:
        r    = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        h    = r.headers
        html = r.text[:8000]
        hl   = html.lower()

        # Server
        sv = h.get('Server','')
        for kw,name in [('nginx','Nginx'),('apache','Apache'),('iis','IIS'),
                         ('litespeed','LiteSpeed'),('caddy','Caddy'),('openresty','OpenResty')]:
            if kw in sv.lower(): categories['Server'].append(name)
        if h.get('CF-Ray'): categories['Server'].append('Cloudflare')

        # Backend
        pw = h.get('X-Powered-By','')
        for kw,name in [('php','PHP'),('asp.net','ASP.NET'),('express','Node.js'),
                         ('python','Python'),('ruby','Ruby'),('java','Java')]:
            if kw in pw.lower(): categories['Backend'].append(name)
        if 'laravel_session' in r.text: categories['Backend'].append('Laravel')
        if 'csrfmiddlewaretoken' in html: categories['Backend'].append('Django')
        if '_rails' in r.cookies: categories['Backend'].append('Ruby on Rails')

        # CMS
        for kw,name in [('wp-content','WordPress'),('wp-includes','WordPress'),
                         ('joomla','Joomla'),('/sites/default','Drupal'),
                         ('shopify','Shopify'),('wix.com','Wix'),
                         ('squarespace','Squarespace'),('ghost.io','Ghost'),
                         ('prestashop','PrestaShop'),('magento','Magento')]:
            if kw in hl and name not in categories['CMS']:
                categories['CMS'].append(name)

        # Frontend
        for kw,name in [('react','React'),('vue.js','Vue.js'),('angular','Angular'),
                         ('jquery','jQuery'),('bootstrap','Bootstrap'),
                         ('tailwind','Tailwind CSS'),('svelte','Svelte'),
                         ('next.js','Next.js'),('nuxt','Nuxt.js')]:
            if kw in hl and name not in categories['Frontend']:
                categories['Frontend'].append(name)

        # Analytics
        for kw,name in [('google-analytics','Google Analytics'),('gtag','Google Tag Manager'),
                         ('fbevents','Facebook Pixel'),('hotjar','Hotjar'),
                         ('segment.com','Segment'),('mixpanel','Mixpanel')]:
            if kw in hl: categories['Analytics'].append(name)

        # CDN
        if 'cloudfront.net' in html or 'CloudFront' in h.get('Via',''): categories['CDN'].append('AWS CloudFront')
        if 'akamai' in h.get('X-Cache','').lower(): categories['CDN'].append('Akamai')
        if 'fastly' in h.get('X-Served-By','').lower(): categories['CDN'].append('Fastly')
        if h.get('CF-Ray'): categories['CDN'].append('Cloudflare')

        # Security
        for hdr,name in [('Strict-Transport-Security','HSTS'),
                          ('Content-Security-Policy','CSP'),
                          ('X-Frame-Options','X-Frame-Options')]:
            if hdr in h: categories['Security'].append(name)
        if 'recaptcha' in hl: categories['Security'].append('reCAPTCHA')
        if 'cloudflare' in hl.lower(): categories['Security'].append('Cloudflare Bot Protect')

        tech = {k:v for k,v in categories.items() if v}
        return {
            'url':    url,
            'status': r.status_code,
            'tech':   tech,
            'total':  sum(len(v) for v in tech.values()),
            'error':  None
        }
    except Exception as e:
        return {'url':url,'error':str(e),'tech':{},'total':0}

# ── Threat Score Calculator ───────────────────────────────
def calculate_threat_score(result):
    score = 0
    flags = []
    ip    = result.get('ip_info') or {}
    heads = result.get('headers') or {}
    ports = result.get('ports') or {}
    ssl_r = result.get('ssl') or {}

    if ip.get('proxy'):
        score += 30
        flags.append({'msg':'Proxy / VPN detected on this IP','sev':'high'})
    if ip.get('hosting'):
        score += 15
        flags.append({'msg':'IP belongs to a datacenter/hosting provider','sev':'medium'})

    risky = {21:'FTP',23:'Telnet',445:'SMB',3306:'MySQL',6379:'Redis',27017:'MongoDB'}
    for p in (ports.get('ports') or []):
        if p.get('status')=='open' and p['port'] in risky:
            score += 20
            flags.append({'msg':f"Exposed service: {risky[p['port']]} (:{p['port']})","sev":'high'})

    hs = heads.get('score')
    if hs is not None:
        if hs < 40:
            score += 20
            flags.append({'msg':f'Very low security score: {hs}%','sev':'high'})
        elif hs < 65:
            score += 10
            flags.append({'msg':f'Poor security headers: {hs}%','sev':'medium'})

    if ssl_r.get('expired'):
        score += 20
        flags.append({'msg':'SSL certificate is expired','sev':'high'})
    elif ssl_r.get('soon'):
        score += 10
        flags.append({'msg':f"SSL expires in {ssl_r.get('days_left','?')} days",'sev':'medium'})

    sv = heads.get('server','')
    if sv and sv not in ('Hidden','Unknown','—',''):
        score += 5
        flags.append({'msg':f'Server version exposed: {sv}','sev':'low'})

    score = min(score, 100)
    if score >= 70:   lvl,clr = 'Critical','red'
    elif score >= 50: lvl,clr = 'High Risk','red'
    elif score >= 30: lvl,clr = 'Medium Risk','amber'
    elif score >= 10: lvl,clr = 'Low Risk','green'
    else:             lvl,clr = 'Clean','green'

    return {'score':score,'level':lvl,'color':clr,'flags':flags}

# ── Auth routes ───────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('password') == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        error = 'Wrong password'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── Main routes ───────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    total, uname, domain = count_reports()
    return render_template('dashboard.html', total=total, uname=uname,
                           domain=domain, recent=get_recent_reports(5), active='dashboard')

@app.route('/username', methods=['GET','POST'])
@login_required
def username():
    results = summary = searched = None
    if request.method == 'POST':
        searched = request.form.get('username','').strip()
        if searched:
            results, summary = check_username(searched)
            save_report('username', searched, results, summary)
    return render_template('username.html', results=results,
                           summary=summary, searched=searched, active='username')

@app.route('/domain', methods=['GET','POST'])
@login_required
def domain():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('domain','').strip()
        if searched:
            result = check_domain(searched)
            save_report('domain', searched, result)
    return render_template('domain.html', result=result,
                           searched=searched, active='domain')

@app.route('/bulk', methods=['GET','POST'])
@login_required
def bulk():
    results = None
    if request.method == 'POST':
        usernames = request.form.get('usernames','').strip().split('\n')
        domains   = request.form.get('domains','').strip().split('\n')
        results   = {'usernames':[], 'domains':[]}
        for u in usernames:
            u = u.strip()
            if not u: continue
            res, summary = check_username(u)
            save_report('username', u, res, summary)
            results['usernames'].append({'target':u,'found':summary.get('found',0),'total':summary.get('total',0)})
        for d in domains:
            d = d.strip()
            if not d: continue
            res = check_domain(d)
            save_report('domain', d, res)
            results['domains'].append({'target':d,'reachable':res.get('reachable',False),'ip':res.get('ip','—')})
    return render_template('bulk.html', results=results, active='bulk')

# ── OSINT Tools ───────────────────────────────────────────
@app.route('/ip-lookup', methods=['GET','POST'])
@login_required
def ip_lookup():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('ip','').strip()
        if searched:
            result = lookup_ip(searched)
            save_report('ip_lookup', searched, result)
    return render_template('ip-lookup.html', result=result, searched=searched, active='ip_lookup')

@app.route('/email-checker', methods=['GET','POST'])
@login_required
def email_checker():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('email','').strip()
        if searched:
            result = check_email(searched)
            save_report('email', searched, result)
    return render_template('email-checker.html', result=result, searched=searched, active='email_checker')

@app.route('/dns-lookup', methods=['GET','POST'])
@login_required
def dns_lookup_route():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('domain','').strip()
        if searched:
            result = dns_lookup(searched)
            save_report('dns', searched, result)
    return render_template('dns-lookup.html', result=result, searched=searched, active='dns')

@app.route('/port-scanner', methods=['GET','POST'])
@login_required
def port_scanner():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('host','').strip()
        if searched:
            result = port_scan(searched)
            save_report('port_scan', searched, result)
    return render_template('port-scanner.html', result=result, searched=searched, active='port_scanner')

@app.route('/headers', methods=['GET','POST'])
@login_required
def headers_check():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('url','').strip()
        if searched:
            result = check_headers(searched)
            save_report('headers', searched, result)
    return render_template('headers.html', result=result, searched=searched, active='headers')

@app.route('/whois', methods=['GET','POST'])
@login_required
def whois_lookup():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('domain','').strip()
        if searched:
            result = get_whois(searched)
            save_report('whois', searched, result)
    return render_template('whois.html', result=result, searched=searched, active='whois')

# ── Reports ───────────────────────────────────────────────
@app.route('/reports')
@login_required
def reports():
    q, t = request.args.get('q','').strip(), request.args.get('type','').strip()
    data  = search_reports(q, t) if (q or t) else get_all_reports()
    return render_template('reports.html', reports=data, query=q, rtype=t, active='reports')

@app.route('/reports/<int:report_id>')
@login_required
def view_report(report_id):
    from db import get_conn
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM reports WHERE id=?',(report_id,)).fetchone()
    if not row:
        return redirect(url_for('reports'))
    report = dict(row)
    report['results'] = json.loads(report['results'])
    report['summary'] = json.loads(report['summary'])
    return render_template('view-report.html', report=report, active='reports')

@app.route('/reports/<int:report_id>/pdf')
@login_required
def export_pdf(report_id):
    from db import get_conn
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM reports WHERE id=?',(report_id,)).fetchone()
    if not row:
        return redirect(url_for('reports'))
    r = dict(row)
    r['results'] = json.loads(r['results'])
    r['summary'] = json.loads(r['summary'])
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm,
                             leftMargin=2*cm, rightMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []
    ts = ParagraphStyle('t', parent=styles['Title'], fontSize=20, textColor=colors.HexColor('#00c8ff'))
    story.append(Paragraph(f"CID Report #{r['id']} — {r['target']}", ts))
    story.append(Spacer(1, 0.4*cm))
    ms = ParagraphStyle('m', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#4a6080'))
    story.append(Paragraph(f"Type: {r['type'].title()}  |  {r['timestamp']}", ms))
    story.append(Spacer(1, 0.8*cm))
    if r['type'] == 'username':
        s = r['summary']
        td = [['Platforms','Found','Not Found','Errors'],
              [str(s.get('total',0)),str(s.get('found',0)),str(s.get('not_found',0)),str(s.get('errors',0))]]
        t2 = Table(td, colWidths=[4*cm]*4)
        t2.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0c1829')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#00c8ff')),
            ('FONTSIZE',(0,0),(-1,-1),10),('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#1a3050')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f0f4f8')]),
        ]))
        story.append(t2)
        story.append(Spacer(1,0.8*cm))
        found = [x for x in r['results'] if x.get('status')=='found']
        if found:
            story.append(Paragraph("Found Profiles", styles['Heading2']))
            story.append(Spacer(1,0.3*cm))
            rows = [['Platform','URL','ms']]
            for p in found:
                rows.append([p.get('platform',''),p.get('url',''),str(p.get('ms','—'))])
            t3 = Table(rows, colWidths=[3*cm,11*cm,2*cm])
            t3.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#10b981')),
                ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                ('FONTSIZE',(0,0),(-1,-1),8),
                ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#c8d8e8')),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f0f4f8')]),
            ]))
            story.append(t3)
    else:
        d = r['results'] if isinstance(r['results'], dict) else {}
        rows = [[k, str(v)] for k,v in d.items() if k != 'error' and v]
        if rows:
            t4 = Table(rows, colWidths=[5*cm,11*cm])
            t4.setStyle(TableStyle([
                ('FONTSIZE',(0,0),(-1,-1),10),
                ('TEXTCOLOR',(0,0),(0,-1),colors.HexColor('#4a6080')),
                ('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'),
                ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#c8d8e8')),
                ('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.white,colors.HexColor('#f0f4f8')]),
            ]))
            story.append(t4)
    story.append(Spacer(1,1.5*cm))
    fs = ParagraphStyle('f', parent=styles['Normal'], fontSize=8,
                        textColor=colors.HexColor('#4a6080'), alignment=1)
    story.append(Paragraph("Generated by Cyber Intelligence Dashboard · Educational Use Only", fs))
    doc.build(story)
    buf.seek(0)
    resp = make_response(buf.read())
    resp.headers['Content-Type']        = 'application/pdf'
    resp.headers['Content-Disposition'] = f'attachment; filename=report_{report_id}.pdf'
    return resp

@app.route('/reports/clear', methods=['POST'])
@login_required
def clear_reports_route():
    clear_reports()
    return redirect(url_for('reports'))

@app.route('/stats')
@login_required
def stats():
    return render_template('stats.html', stats=get_stats_data(), active='stats')

@app.route('/about')
@login_required
def about():
    return render_template('about.html', active='about')
@app.route('/analyze', methods=['GET','POST'])
@login_required
def analyze():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('target','').strip()
        if searched:
            result = universal_analyze(searched)
            save_report('analyze', searched, result)
    return render_template('analyze.html', result=result, searched=searched, active='analyze')

@app.route('/hash-tools', methods=['GET','POST'])
@login_required
def hash_tools():
    hashes = detected = text = hash_input = None
    action = request.form.get('action','generate')
    if request.method == 'POST':
        if action == 'generate':
            text = request.form.get('text','').strip()
            if text: hashes = generate_hashes(text)
        elif action == 'detect':
            hash_input = request.form.get('hash','').strip()
            if hash_input: detected = detect_hash_type(hash_input)
    return render_template('hash-tools.html', hashes=hashes, detected=detected,
                           text=text, hash_input=hash_input, active='hash_tools')

@app.route('/url-analyzer', methods=['GET','POST'])
@login_required
def url_analyzer():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('url','').strip()
        if searched:
            result = analyze_url(searched)
    return render_template('url-analyzer.html', result=result, searched=searched, active='url_analyzer')
@app.route('/ssl', methods=['GET','POST'])
@login_required
def ssl_inspector():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('domain','').strip()
        if searched:
            result = ssl_inspect(searched)
            save_report('ssl', searched, result)
    return render_template('ssl.html', result=result, searched=searched, active='ssl')

@app.route('/subdomains', methods=['GET','POST'])
@login_required
def subdomain_finder():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('domain','').strip()
        if searched:
            result = subdomain_scan(searched)
            save_report('subdomain', searched, result)
    return render_template('subdomains.html', result=result, searched=searched, active='subdomains')

@app.route('/tech', methods=['GET','POST'])
@login_required
def tech_detect():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('url','').strip()
        if searched:
            result = tech_fingerprint(searched)
            save_report('tech', searched, result)
    return render_template('tech.html', result=result, searched=searched, active='tech')

# ══════════════════════════════════════════════
#  REST API — v1
#  Base URL: /api/v1/
#  Auth: Header  X-API-Key: <key>
# ══════════════════════════════════════════════
from flask import jsonify
from functools import wraps

API_KEY = 'cid-api-2025-ms'   # غيّره بمفتاحك

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if key != API_KEY:
            return jsonify({'success':False,'error':'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated

def api_response(data=None, error=None, status=200):
    if error:
        return jsonify({'success':False,'error':error}), status
    return jsonify({'success':True,'data':data}), status

# ── Info ───────────────────────────────────────
@app.route('/api/v1')
def api_index():
    return jsonify({
        'name':    'Cyber Intelligence Dashboard API',
        'version': '1.0',
        'author':  'Mohammed Saleh',
        'endpoints': {
            'POST /api/v1/username':   'Username scan across 16 platforms',
            'POST /api/v1/domain':     'Domain HTTP/SSL analysis',
            'POST /api/v1/ip':         'IP geolocation and threat info',
            'POST /api/v1/dns':        'DNS records lookup',
            'POST /api/v1/ports':      'Port scanner',
            'POST /api/v1/headers':    'Security headers analysis',
            'POST /api/v1/whois':      'WHOIS lookup',
            'POST /api/v1/ssl':        'SSL certificate inspection',
            'POST /api/v1/email':      'Email validation and MX check',
            'POST /api/v1/hash':       'Generate hashes',
            'POST /api/v1/url':        'URL analysis and parsing',
            'POST /api/v1/analyze':    'All-in-one target analysis',
            'GET  /api/v1/reports':    'List all saved reports',
            'GET  /api/v1/reports/:id':'Get single report',
            'GET  /api/v1/stats':      'Platform statistics',
        },
        'auth': 'Header: X-API-Key or ?api_key=',
        'note': 'Educational use only'
    })

# ── Username ───────────────────────────────────
@app.route('/api/v1/username', methods=['POST'])
@api_key_required
def api_username():
    data     = request.get_json() or {}
    username = data.get('username','').strip()
    if not username:
        return api_response(error='username field required', status=400)
    results, summary = check_username(username)
    save_report('username', username, results, summary)
    return api_response({
        'username': username,
        'summary':  summary,
        'results':  results,
    })

# ── Domain ─────────────────────────────────────
@app.route('/api/v1/domain', methods=['POST'])
@api_key_required
def api_domain():
    data   = request.get_json() or {}
    domain = data.get('domain','').strip()
    if not domain:
        return api_response(error='domain field required', status=400)
    result = check_domain(domain)
    save_report('domain', domain, result)
    return api_response(result)

# ── IP ─────────────────────────────────────────
@app.route('/api/v1/ip', methods=['POST'])
@api_key_required
def api_ip():
    data = request.get_json() or {}
    ip   = data.get('ip','').strip()
    if not ip:
        return api_response(error='ip field required', status=400)
    result = lookup_ip(ip)
    save_report('ip_lookup', ip, result)
    return api_response(result)

# ── DNS ────────────────────────────────────────
@app.route('/api/v1/dns', methods=['POST'])
@api_key_required
def api_dns():
    data   = request.get_json() or {}
    domain = data.get('domain','').strip()
    if not domain:
        return api_response(error='domain field required', status=400)
    result = dns_lookup(domain)
    save_report('dns', domain, result)
    return api_response(result)

# ── Ports ──────────────────────────────────────
@app.route('/api/v1/ports', methods=['POST'])
@api_key_required
def api_ports():
    data = request.get_json() or {}
    host = data.get('host','').strip()
    if not host:
        return api_response(error='host field required', status=400)
    result = port_scan(host)
    save_report('port_scan', host, result)
    return api_response(result)

# ── Headers ────────────────────────────────────
@app.route('/api/v1/headers', methods=['POST'])
@api_key_required
def api_headers():
    data = request.get_json() or {}
    url  = data.get('url','').strip()
    if not url:
        return api_response(error='url field required', status=400)
    result = check_headers(url)
    save_report('headers', url, result)
    return api_response(result)

# ── WHOIS ──────────────────────────────────────
@app.route('/api/v1/whois', methods=['POST'])
@api_key_required
def api_whois():
    data   = request.get_json() or {}
    domain = data.get('domain','').strip()
    if not domain:
        return api_response(error='domain field required', status=400)
    result = get_whois(domain)
    save_report('whois', domain, result)
    return api_response(result)

# ── SSL ────────────────────────────────────────
@app.route('/api/v1/ssl', methods=['POST'])
@api_key_required
def api_ssl():
    data   = request.get_json() or {}
    domain = data.get('domain','').strip()
    if not domain:
        return api_response(error='domain field required', status=400)
    result = ssl_inspect(domain)
    save_report('ssl', domain, result)
    return api_response(result)

# ── Email ──────────────────────────────────────
@app.route('/api/v1/email', methods=['POST'])
@api_key_required
def api_email():
    data  = request.get_json() or {}
    email = data.get('email','').strip()
    if not email:
        return api_response(error='email field required', status=400)
    result = check_email(email)
    save_report('email', email, result)
    return api_response(result)

# ── Hash ───────────────────────────────────────
@app.route('/api/v1/hash', methods=['POST'])
@api_key_required
def api_hash():
    data = request.get_json() or {}
    text = data.get('text','')
    if not text:
        return api_response(error='text field required', status=400)
    return api_response({
        'input':  text,
        'hashes': generate_hashes(text)
    })

# ── URL ────────────────────────────────────────
@app.route('/api/v1/url', methods=['POST'])
@api_key_required
def api_url():
    data = request.get_json() or {}
    url  = data.get('url','').strip()
    if not url:
        return api_response(error='url field required', status=400)
    return api_response(analyze_url(url))

# ── Analyze (all-in-one) ───────────────────────
@app.route('/api/v1/analyze', methods=['POST'])
@api_key_required
def api_analyze():
    data   = request.get_json() or {}
    target = data.get('target','').strip()
    if not target:
        return api_response(error='target field required', status=400)
    result = universal_analyze(target)
    threat = calculate_threat_score(result)
    if not result.get('is_ip'):
        import concurrent.futures
        clean = result.get('clean','')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_ssl  = ex.submit(ssl_inspect, clean)
            f_tech = ex.submit(tech_fingerprint, f'https://{clean}')
            try:    result['ssl']  = f_ssl.result(timeout=10)
            except: result['ssl']  = None
            try:    result['tech'] = f_tech.result(timeout=10)
            except: result['tech'] = None
    save_report('analyze', target, result)
    return api_response({
        'target':  target,
        'result':  result,
        'threat':  threat,
    })

# ── Reports ────────────────────────────────────
@app.route('/api/v1/reports', methods=['GET'])
@api_key_required
def api_reports():
    limit = min(int(request.args.get('limit', 50)), 200)
    rtype = request.args.get('type','').strip()
    q     = request.args.get('q','').strip()
    from db import search_reports, get_all_reports
    reports = search_reports(q, rtype) if (q or rtype) else get_all_reports()
    return api_response({
        'count':   len(reports[:limit]),
        'reports': reports[:limit],
    })

@app.route('/api/v1/reports/<int:report_id>', methods=['GET'])
@api_key_required
def api_report_single(report_id):
    from db import get_conn
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM reports WHERE id=?',(report_id,)).fetchone()
    if not row:
        return api_response(error='Report not found', status=404)
    r = dict(row)
    r['results'] = json.loads(r['results'])
    r['summary'] = json.loads(r['summary'])
    return api_response(r)

# ── Stats ──────────────────────────────────────
@app.route('/api/v1/stats', methods=['GET'])
@api_key_required
def api_stats():
    from db import get_stats_data
    return api_response(get_stats_data())
# ── Threat Intelligence ───────────────────────
@app.route('/threat', methods=['GET','POST'])
@login_required
def threat_intel():
    result = searched = None
    if request.method == 'POST':
        searched = request.form.get('target','').strip()
        if searched:
            result = full_threat_report(searched)
            save_report('threat', searched, result)
    return render_template('threat.html', result=result,
                           searched=searched, active='threat')

# ── Network Map ───────────────────────────────
@app.route('/network-map')
@login_required
def network_map():
    from db import get_all_reports
    reports = get_all_reports()
    # Build nodes and edges from saved reports
    nodes, edges = [], []
    seen = set()

    for r in reports:
        target = r.get('target','')
        rtype  = r.get('type','')
        res    = r.get('results') or {}

        if target and target not in seen:
            node_color = {
                'username':'#39d353','domain':'#7c4dba',
                'ip_lookup':'#e8a020','analyze':'#39d353',
                'port_scan':'#cc2936','headers':'#39d353',
                'ssl':'#39d353','dns':'#7c4dba','whois':'#7c4dba',
                'subdomain':'#39d353','tech':'#7c4dba','threat':'#cc2936',
                'email':'#e8a020',
            }.get(rtype,'#3a5c3a')
            nodes.append({'id':target,'label':target,'type':rtype,'color':node_color})
            seen.add(target)

        # Domain → IP edge
        if rtype == 'domain' and isinstance(res, dict) and res.get('ip'):
            ip = res['ip']
            if ip not in seen:
                nodes.append({'id':ip,'label':ip,'type':'ip','color':'#e8a020'})
                seen.add(ip)
            edges.append({'from':target,'to':ip,'label':'resolves to'})

        # Analyze → IP
        if rtype == 'analyze' and isinstance(res, dict):
            ip_info = res.get('ip_info') or {}
            if ip_info.get('query') and ip_info['query'] not in seen:
                ip = ip_info['query']
                nodes.append({'id':ip,'label':ip,'type':'ip','color':'#e8a020'})
                seen.add(ip)
                edges.append({'from':target,'to':ip,'label':'resolves to'})

        # Subdomain → parent
        if rtype == 'subdomain' and isinstance(res, dict):
            for sub in (res.get('found') or [])[:5]:
                sd = sub.get('subdomain','')
                if sd and sd not in seen:
                    nodes.append({'id':sd,'label':sd,'type':'subdomain','color':'#2a6db5'})
                    seen.add(sd)
                edges.append({'from':target,'to':sd,'label':'subdomain'})

    return render_template('network-map.html',
                           nodes=json.dumps(nodes),
                           edges=json.dumps(edges),
                           active='network_map')

# ── Threat API ────────────────────────────────
@app.route('/api/v1/threat', methods=['POST'])
@api_key_required
def api_threat():
    data   = request.get_json() or {}
    target = data.get('target','').strip()
    if not target:
        return api_response(error='target field required', status=400)
    result = full_threat_report(target)
    save_report('threat', target, result)
    return api_response(result)


@app.route('/api-docs')
@login_required
def api_docs():
    return render_template('api-docs.html', api_key=API_KEY, active='api_docs')

if __name__ == '__main__':
    print('\n\033[36m  ╔══════════════════════════════════╗')
    print('  ║  CYBER INTELLIGENCE DASHBOARD   ║')
    print('  ║  Mohammed Drhoobe  ·  v3.0.0       ║')
    print('  ╚══════════════════════════════════╝\033[0m')
    print('\033[32m  ✓  http://127.0.0.1:5000\033[0m\n')
    app.run(debug=True, host='0.0.0.0', port=5000)
