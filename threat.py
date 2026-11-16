"""
threat.py — Threat Intelligence Layer
Connects to free threat databases
Author: Mohammed Saleh
"""

import requests, os, json
from datetime import datetime

# ── API Keys (اختياري — يعمل بدونها بشكل محدود) ──────────
ABUSEIPDB_KEY  = os.environ.get('ABUSEIPDB_KEY',  '')
VIRUSTOTAL_KEY = os.environ.get('VIRUSTOTAL_KEY', '')
OTX_KEY        = os.environ.get('OTX_KEY',        '')

TIMEOUT = 8
HEADERS = {'User-Agent': 'CID-ThreatIntel/1.0'}

# ── AbuseIPDB ─────────────────────────────────────────────
def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return {'available': False, 'reason': 'No API key'}
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={**HEADERS, 'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=TIMEOUT
        )
        if r.status_code != 200:
            return {'available': False, 'reason': f'HTTP {r.status_code}'}
        d = r.json().get('data', {})
        return {
            'available':       True,
            'abuse_score':     d.get('abuseConfidenceScore', 0),
            'total_reports':   d.get('totalReports', 0),
            'country':         d.get('countryCode', '—'),
            'isp':             d.get('isp', '—'),
            'is_whitelisted':  d.get('isWhitelisted', False),
            'last_reported':   d.get('lastReportedAt', '—'),
            'domain':          d.get('domain', '—'),
        }
    except Exception as e:
        return {'available': False, 'reason': str(e)}

# ── AlienVault OTX ────────────────────────────────────────
def check_otx(target, target_type='IPv4'):
    """target_type: IPv4, domain, hostname, url"""
    base = 'https://otx.alienvault.com/api/v1/indicators'
    headers = {**HEADERS}
    if OTX_KEY:
        headers['X-OTX-API-KEY'] = OTX_KEY
    try:
        url = f'{base}/{target_type}/{target}/general'
        r   = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return {'available': False, 'reason': f'HTTP {r.status_code}'}
        d = r.json()
        pulses = d.get('pulse_info', {})
        return {
            'available':     True,
            'pulse_count':   pulses.get('count', 0),
            'malicious':     pulses.get('count', 0) > 0,
            'tags':          list({
                tag
                for p in pulses.get('pulses', [])[:5]
                for tag in p.get('tags', [])
            })[:10],
            'pulse_names':   [p.get('name','') for p in pulses.get('pulses',[])[:3]],
            'reputation':    d.get('reputation', 0),
            'country':       d.get('country_name', '—'),
        }
    except Exception as e:
        return {'available': False, 'reason': str(e)}

# ── VirusTotal ────────────────────────────────────────────
def check_virustotal(target, vt_type='ip-addresses'):
    """vt_type: ip-addresses, domains, urls"""
    if not VIRUSTOTAL_KEY:
        return {'available': False, 'reason': 'No API key'}
    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/{vt_type}/{target}',
            headers={**HEADERS, 'x-apikey': VIRUSTOTAL_KEY},
            timeout=TIMEOUT
        )
        if r.status_code != 200:
            return {'available': False, 'reason': f'HTTP {r.status_code}'}
        stats = r.json().get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
        return {
            'available':  True,
            'malicious':  stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'clean':      stats.get('undetected', 0),
            'total':      sum(stats.values()),
            'flagged':    stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0,
        }
    except Exception as e:
        return {'available': False, 'reason': str(e)}

# ── Shodan (no key needed for basic info) ─────────────────
def check_shodan(ip):
    try:
        r = requests.get(
            f'https://internetdb.shodan.io/{ip}',
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code == 200:
            d = r.json()
            return {
                'available': True,
                'ports':     d.get('ports', []),
                'vulns':     d.get('vulns', []),
                'tags':      d.get('tags', []),
                'hostnames': d.get('hostnames', []),
                'cpes':      d.get('cpes', [])[:5],
            }
        return {'available': False, 'reason': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'available': False, 'reason': str(e)}

# ── Full Threat Report ────────────────────────────────────
def full_threat_report(target):
    import re
    is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target.strip()))
    report = {
        'target':    target,
        'is_ip':     is_ip,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'sources':   {},
        'summary':   {},
    }

    if is_ip:
        report['sources']['abuseipdb'] = check_abuseipdb(target)
        report['sources']['otx']       = check_otx(target, 'IPv4')
        report['sources']['virustotal']= check_virustotal(target, 'ip-addresses')
        report['sources']['shodan']    = check_shodan(target)
    else:
        domain = target.replace('https://','').replace('http://','').split('/')[0]
        report['sources']['otx']       = check_otx(domain, 'domain')
        report['sources']['virustotal']= check_virustotal(domain, 'domains')

    # Summary
    risk_score = 0
    flags      = []

    abuse = report['sources'].get('abuseipdb', {})
    if abuse.get('available') and abuse.get('abuse_score', 0) > 25:
        risk_score += 40
        flags.append(f"AbuseIPDB score: {abuse['abuse_score']}% — {abuse.get('total_reports',0)} reports")

    otx = report['sources'].get('otx', {})
    if otx.get('available') and otx.get('malicious'):
        risk_score += 30
        flags.append(f"AlienVault OTX: {otx['pulse_count']} threat pulses")

    vt = report['sources'].get('virustotal', {})
    if vt.get('available') and vt.get('flagged'):
        risk_score += 30
        flags.append(f"VirusTotal: {vt['malicious']} malicious, {vt['suspicious']} suspicious")

    sh = report['sources'].get('shodan', {})
    if sh.get('available') and sh.get('vulns'):
        risk_score += 20
        flags.append(f"Shodan CVEs: {', '.join(list(sh['vulns'])[:3])}")

    risk_score = min(risk_score, 100)
    if risk_score >= 70:   level, color = 'Critical',   'red'
    elif risk_score >= 40: level, color = 'High Risk',  'red'
    elif risk_score >= 20: level, color = 'Medium Risk','amber'
    elif risk_score > 0:   level, color = 'Low Risk',   'amber'
    elif not any(s.get('available') for s in report['sources'].values()):
        level, color = 'Insufficient Data', 'amber'
    else:                  level, color = 'No Reported Indicators', 'green'

    report['summary'] = {
        'risk_score': risk_score,
        'level':      level,
        'color':      color,
        'flags':      flags,
    }
    return report
