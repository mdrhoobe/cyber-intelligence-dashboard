import phonenumbers
from phonenumbers import (
    geocoder, carrier, timezone,
    PhoneNumberType, number_type,
    is_valid_number, parse as pn_parse
)
import requests, re, time, json, socket, os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

NUM_TYPES = {
    PhoneNumberType.MOBILE:               'Mobile',
    PhoneNumberType.FIXED_LINE:           'Fixed Line',
    PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixed/Mobile',
    PhoneNumberType.TOLL_FREE:            'Toll Free',
    PhoneNumberType.PREMIUM_RATE:         'Premium Rate',
    PhoneNumberType.VOIP:                 'VoIP',
    PhoneNumberType.PERSONAL_NUMBER:      'Personal',
    PhoneNumberType.UNKNOWN:              'Unknown',
}

COUNTRY_COORDS = {
    'US':{'lat':37.09,'lon':-95.71,'name':'United States'},
    'GB':{'lat':55.37,'lon':-3.43, 'name':'United Kingdom'},
    'SA':{'lat':23.88,'lon':45.07, 'name':'Saudi Arabia'},
    'LY':{'lat':26.33,'lon':17.22, 'name':'Libya'},
    'EG':{'lat':26.82,'lon':30.80, 'name':'Egypt'},
    'AE':{'lat':23.42,'lon':53.84, 'name':'UAE'},
    'DE':{'lat':51.16,'lon':10.45, 'name':'Germany'},
    'FR':{'lat':46.22,'lon':2.21,  'name':'France'},
    'IN':{'lat':20.59,'lon':78.96, 'name':'India'},
    'TR':{'lat':38.96,'lon':35.24, 'name':'Turkey'},
    'MA':{'lat':31.79,'lon':-7.09, 'name':'Morocco'},
    'DZ':{'lat':28.03,'lon':1.65,  'name':'Algeria'},
    'TN':{'lat':33.88,'lon':9.53,  'name':'Tunisia'},
    'IQ':{'lat':33.22,'lon':43.67, 'name':'Iraq'},
    'SY':{'lat':34.80,'lon':38.99, 'name':'Syria'},
    'JO':{'lat':30.58,'lon':36.23, 'name':'Jordan'},
    'PK':{'lat':30.37,'lon':69.34, 'name':'Pakistan'},
    'RU':{'lat':61.52,'lon':105.31,'name':'Russia'},
    'CN':{'lat':35.86,'lon':104.19,'name':'China'},
    'BR':{'lat':-14.23,'lon':-51.92,'name':'Brazil'},
    'NG':{'lat':9.08,'lon':8.67,   'name':'Nigeria'},
    'ZA':{'lat':-30.55,'lon':22.93,'name':'South Africa'},
    'ID':{'lat':-0.78,'lon':113.92,'name':'Indonesia'},
}

# ════════════════════════════════════════════════
# 1. PARSE
# ════════════════════════════════════════════════
def parse_phone(raw):
    raw = raw.strip()
    if not raw.startswith('+'):
        raw = '+' + raw

    result = {
        'raw': raw, 'formatted': None, 'e164': None,
        'national': None, 'country_code': None,
        'country_name': None, 'country_iso': None,
        'region': None, 'carrier': None,
        'line_type': None, 'timezones': [],
        'valid': False, 'possible': False,
        'coords': None, 'error': None,
    }
    try:
        pn = pn_parse(raw, None)
        result['valid']       = is_valid_number(pn)
        result['possible']    = phonenumbers.is_possible_number(pn)
        result['e164']        = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
        result['formatted']   = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        result['national']    = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
        result['country_code']= f'+{pn.country_code}'
        result['country_iso'] = phonenumbers.region_code_for_number(pn)
        result['country_name']= geocoder.country_name_for_number(pn, 'en')
        result['region']      = geocoder.description_for_number(pn, 'en') or '—'
        result['carrier']     = carrier.name_for_number(pn, 'en') or 'Unknown'
        result['line_type']   = NUM_TYPES.get(number_type(pn), 'Unknown')
        result['timezones']   = list(timezone.time_zones_for_number(pn))
        iso = result['country_iso']
        result['coords']      = COUNTRY_COORDS.get(iso)
    except Exception as e:
        result['error'] = str(e)
    return result

# ════════════════════════════════════════════════
# 2. SEARCH ENGINES
# ════════════════════════════════════════════════
def search_duckduckgo(query, max_results=6):
    hits = []
    try:
        r = requests.post('https://html.duckduckgo.com/html/',
                          data={'q': query, 'b': '', 'kl': ''},
                          headers=HEADERS, timeout=10)
        for href, title in re.findall(
            r'<a class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>', r.text
        )[:max_results]:
            if href.startswith('http'):
                hits.append({'title': title.strip(), 'url': href, 'engine': 'DuckDuckGo'})
    except: pass
    return hits

def search_bing(query, max_results=6):
    hits = []
    try:
        r = requests.get(
            'https://www.bing.com/search',
            params={'q': query, 'count': max_results},
            headers={**HEADERS, 'Accept-Language': 'en-US'}, timeout=10
        )
        for href, title in re.findall(
            r'<h2[^>]*><a[^>]*href="([^"]+)"[^>]*><strong>([^<]+)</strong>', r.text
        )[:max_results]:
            if href.startswith('http'):
                hits.append({'title': title.strip(), 'url': href, 'engine': 'Bing'})
    except: pass
    return hits

def multi_engine_search(formatted, e164, national):
    queries = [
        f'"{formatted}"',
        f'"{e164}"',
        f'"{formatted}" name contact',
        f'"{formatted}" site:truecaller.com OR site:whitepages.com OR site:spokeo.com',
    ]
    all_hits = []
    seen_urls = set()
    for q in queries[:2]:
        for hit in search_duckduckgo(q, 4):
            if hit['url'] not in seen_urls:
                seen_urls.add(hit['url'])
                all_hits.append(hit)
        for hit in search_bing(q, 3):
            if hit['url'] not in seen_urls:
                seen_urls.add(hit['url'])
                all_hits.append(hit)
    return all_hits[:12]

# ════════════════════════════════════════════════
# 3. SOCIAL NETWORKS
# ════════════════════════════════════════════════
def get_social_platforms(e164, formatted):
    plain = e164.replace('+', '')
    return [
        {'name':'Truecaller', 'url':f'https://www.truecaller.com/search/us/{plain}',
         'icon':'📞', 'type':'caller_id'},
        {'name':'WhatsApp',   'url':f'https://wa.me/{plain}',
         'icon':'💬', 'type':'messaging'},
        {'name':'Telegram',   'url':f'https://t.me/{plain}',
         'icon':'✈️', 'type':'messaging'},
        {'name':'Viber',      'url':f'viber://chat?number={plain}',
         'icon':'📳', 'type':'messaging'},
        {'name':'Facebook',   'url':f'https://www.facebook.com/search/top?q={e164}',
         'icon':'👤', 'type':'social'},
        {'name':'Instagram',  'url':f'https://www.instagram.com/explore/tags/{plain}',
         'icon':'📸', 'type':'social'},
        {'name':'LinkedIn',   'url':f'https://www.linkedin.com/search/results/all/?keywords={e164}',
         'icon':'💼', 'type':'professional'},
        {'name':'Snapchat',   'url':f'https://www.snapchat.com/add/{plain}',
         'icon':'👻', 'type':'social'},
        {'name':'TikTok',     'url':f'https://www.tiktok.com/search?q={e164}',
         'icon':'🎵', 'type':'social'},
        {'name':'Twitter/X',  'url':f'https://x.com/search?q={e164}',
         'icon':'🐦', 'type':'social'},
    ]

# ════════════════════════════════════════════════
# 4. EMAIL EXTRACTION + HaveIBeenPwned
# ════════════════════════════════════════════════
def extract_emails_from_hits(hits):
    emails = set()
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    for hit in hits:
        found = re.findall(email_pattern, hit.get('title','') + hit.get('url',''))
        emails.update(found)
    return list(emails)[:5]

def check_hibp(email):
    """HaveIBeenPwned — checks if email appeared in data breaches"""
    key = os.environ.get('HIBP_API_KEY', '')
    if not key:
        return {'email': email, 'breached': None, 'error': 'HIBP API key not configured'}
    try:
        r = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers={**HEADERS, 'hibp-api-key': key, 'User-Agent': 'CID-OSINT/1.0'},
            timeout=8
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                'email':      email,
                'breached':   True,
                'count':      len(breaches),
                'breaches':   [b.get('Name','') for b in breaches[:5]],
            }
        elif r.status_code == 404:
            return {'email': email, 'breached': False, 'count': 0, 'breaches': []}
        return {'email': email, 'breached': None, 'error': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'email': email, 'error': str(e)}

# ════════════════════════════════════════════════
# 5. WHOIS / RDAP
# ════════════════════════════════════════════════
def rdap_lookup(domain):
    try:
        r = requests.get(f'https://rdap.org/domain/{domain}',
                         headers=HEADERS, timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {
                'domain':     domain,
                'registrar':  next((e.get('ldhName','') for e in d.get('entities',[])
                                    if 'registrar' in e.get('roles',[])), '—'),
                'status':     [s.replace('https://icann.org/epp#','')
                               for s in d.get('status',[])],
                'registered': d.get('events',[{}])[0].get('eventDate','—')[:10],
                'updated':    next((e.get('eventDate','—')[:10]
                                    for e in d.get('events',[])
                                    if e.get('eventAction')=='last changed'), '—'),
                'available':  True,
            }
    except: pass
    return {'domain': domain, 'available': False}

# ════════════════════════════════════════════════
# 6. THREAT INTELLIGENCE (for IPs found)
# ════════════════════════════════════════════════
def check_otx_ip(ip):
    try:
        r = requests.get(
            f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
            headers=HEADERS, timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            pulses = d.get('pulse_info', {})
            return {
                'ip':          ip,
                'pulse_count': pulses.get('count', 0),
                'malicious':   pulses.get('count', 0) > 0,
                'tags':        list({tag for p in pulses.get('pulses',[])[:3]
                                     for tag in p.get('tags',[])}),
                'available':   True,
            }
    except: pass
    return {'ip': ip, 'available': False}

def extract_ips_from_hits(hits):
    ips = set()
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    for hit in hits:
        found = re.findall(ip_pattern, hit.get('url',''))
        ips.update(found)
    return list(ips)[:3]

# ════════════════════════════════════════════════
# 7. NAME EXTRACTION
# ════════════════════════════════════════════════
def extract_names(hits):
    names = []
    seen  = set()
    patterns = [
        r'\b([A-Z][a-z]{2,15}\s[A-Z][a-z]{2,15})\b',
        r'\b([A-Z][a-z]{2,15}\s[A-Z][a-z]{2,15}\s[A-Z][a-z]{2,15})\b',
    ]
    for hit in hits:
        text = hit.get('title','') + ' ' + hit.get('url','')
        for pattern in patterns:
            for name in re.findall(pattern, text):
                if name not in seen and len(name) > 5:
                    seen.add(name)
                    names.append(name)
    # Filter common false positives
    skip = {'About Us','Contact Us','Search Results','Phone Number',
            'White Pages','True Caller','Find People'}
    return [n for n in names if n not in skip][:8]

# ════════════════════════════════════════════════
# 8. AI CORRELATION (Claude API)
# ════════════════════════════════════════════════
def ai_correlate(phone_data):
    key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not key:
        return manual_confidence(phone_data)
    try:
        summary = {
            'number':     phone_data['info'].get('formatted'),
            'country':    phone_data['info'].get('country_name'),
            'carrier':    phone_data['info'].get('carrier'),
            'line_type':  phone_data['info'].get('line_type'),
            'names_found':phone_data.get('names', []),
            'emails_found':phone_data.get('emails', []),
            'web_hits':   len(phone_data.get('web_hits', [])),
            'breaches':   [b for e in phone_data.get('hibp_results', [])
                           for b in e.get('breaches', [])],
            'threat_hits': any(t.get('malicious') for t in phone_data.get('threat_data', [])),
        }

        prompt = f"""You are a professional OSINT analyst. Analyze this phone number investigation data and provide:

1. A brief summary (2-3 sentences) of what was found
2. Key observations about the number's owner (if data exists)
3. Risk assessment: Low / Medium / High
4. Recommended next steps for investigation
5. Confidence score (0-100) based on data quality

Data collected:
{json.dumps(summary, indent=2)}

Respond in this exact JSON format only:
{{
  "summary": "brief summary here",
  "observations": ["observation 1", "observation 2"],
  "risk": "Low|Medium|High",
  "next_steps": ["step 1", "step 2"],
  "confidence": 0-100,
  "confidence_reason": "why this score"
}}"""

        r = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={'Content-Type': 'application/json',
                     'x-api-key': key, 'anthropic-version': '2023-06-01'},
            json={
                'model':      os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6'),
                'max_tokens': 1000,
                'messages':   [{'role': 'user', 'content': prompt}],
            },
            timeout=30
        )
        if r.status_code == 200:
            content = r.json()['content'][0]['text']
            # Clean JSON
            clean = re.sub(r'```json|```', '', content).strip()
            return json.loads(clean)
    except Exception as e:
        pass

    # Fallback — calculate score manually
    return manual_confidence(phone_data)

def manual_confidence(data):
    score = 0
    obs   = []
    info  = data.get('info', {})

    if info.get('valid'):      score += 20; obs.append('Valid phone number format')
    if info.get('carrier') and info['carrier'] != 'Unknown':
        score += 10; obs.append(f"Carrier identified: {info['carrier']}")
    if info.get('region') and info['region'] != '—':
        score += 10; obs.append(f"Region identified: {info['region']}")
    if data.get('names'):      score += 20; obs.append(f"{len(data['names'])} possible names found")
    if data.get('emails'):     score += 15; obs.append(f"{len(data['emails'])} emails extracted")
    if data.get('web_hits'):   score += 15; obs.append(f"{len(data['web_hits'])} web results found")
    if any(e.get('breached') for e in data.get('hibp_results',[])):
        score += 10; obs.append('Email found in data breach')

    risk = 'Unassessed'

    return {
        'summary':           f"Phone number from {info.get('country_name','unknown')} "
                             f"({info.get('carrier','unknown carrier')}). "
                             f"{len(data.get('names',[]))} names and "
                             f"{len(data.get('web_hits',[]))} web references found.",
        'observations':      obs,
        'risk':              risk,
        'next_steps':        [
            'Search found names on social media',
            'Check extracted emails in breach databases',
            'Run username scan on discovered names',
            'Cross-reference with Threat Intelligence module',
        ],
        'confidence':        min(score, 95),
        'confidence_reason': f'Based on {len(obs)} data points collected',
    }

# ════════════════════════════════════════════════
# 9. CONFIDENCE SCORE
# ════════════════════════════════════════════════
def calculate_confidence(data, ai_result):
    """Final confidence based on data + AI"""
    base    = ai_result.get('confidence', 0)
    sources = 0
    if data.get('web_hits'):     sources += 1
    if data.get('names'):        sources += 1
    if data.get('emails'):       sources += 1
    if data.get('hibp_results'): sources += 1
    if data.get('threat_data'):  sources += 1

    final = min(int(base + (sources * 2)), 98)
    if final >= 80:   level, color = 'High Confidence',   'green'
    elif final >= 55: level, color = 'Medium Confidence', 'amber'
    elif final >= 30: level, color = 'Low Confidence',    'red'
    else:             level, color = 'Insufficient Data', 'red'

    return {'score': final, 'level': level, 'color': color, 'sources': sources}

# ════════════════════════════════════════════════
# MAIN PIPELINE
# ════════════════════════════════════════════════
def phone_osint(raw_number):
    start  = time.time()
    result = {
        'raw':          raw_number,
        'info':         {},
        'web_hits':     [],
        'social':       [],
        'names':        [],
        'emails':       [],
        'hibp_results': [],
        'threat_data':  [],
        'rdap_data':    [],
        'ai':           {},
        'confidence':   {},
        'map_nodes':    [],
        'dorks':        [],
        'scan_time':    0,
        'error':        None,
    }

    # 1. Parse
    info = parse_phone(raw_number)
    result['info'] = info
    if info.get('error') or not info.get('valid'):
        result['error'] = info.get('error') or 'Invalid phone number — add country code (e.g. +218)'
        return result

    e164      = info['e164']
    formatted = info['formatted']
    national  = info['national']
    plain     = e164.replace('+','')

    # 2. Social
    result['social'] = get_social_platforms(e164, formatted)

    # 3. Dorks
    result['dorks'] = [
        f'"{formatted}"',
        f'"{e164}"',
        f'"{formatted}" name',
        f'"{formatted}" email',
        f'"{formatted}" site:facebook.com OR site:linkedin.com OR site:instagram.com',
        f'"{formatted}" site:truecaller.com OR site:whitepages.com',
        f'"{national}" "{info["country_name"]}"',
        f'intext:"{formatted}" contact',
        f'"{plain}" mobile',
        f'"{formatted}" -advertisement -spam -scam',
    ]

    # 4. Multi-engine search (parallel)
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_ddg  = ex.submit(search_duckduckgo, f'"{formatted}"', 8)
        f_bing = ex.submit(search_bing,       f'"{formatted}"', 6)
        f_ddg2 = ex.submit(search_duckduckgo,
                           f'"{formatted}" name OR email OR contact', 5)
        hits   = []
        for f in as_completed([f_ddg, f_bing, f_ddg2]):
            try: hits.extend(f.result())
            except: pass

    # Deduplicate
    seen = set()
    for h in hits:
        if h['url'] not in seen:
            seen.add(h['url'])
            result['web_hits'].append(h)
    result['web_hits'] = result['web_hits'][:15]

    # 5. Extract names & emails
    result['names']  = extract_names(result['web_hits'])
    result['emails'] = extract_emails_from_hits(result['web_hits'])

    # 6. HIBP for found emails
    for email in result['emails'][:2]:
        hibp = check_hibp(email)
        result['hibp_results'].append(hibp)

    # 7. Threat intel for found IPs
    ips = extract_ips_from_hits(result['web_hits'])
    for ip in ips[:2]:
        td = check_otx_ip(ip)
        if td.get('available'):
            result['threat_data'].append(td)

    # 8. RDAP for domains in URLs
    domains = set()
    for h in result['web_hits']:
        m = re.search(r'https?://([^/]+)', h.get('url',''))
        if m:
            dom = m.group(1).replace('www.','')
            if '.' in dom and dom not in ('google.com','bing.com','duckduckgo.com'):
                domains.add(dom)
    for dom in list(domains)[:2]:
        result['rdap_data'].append(rdap_lookup(dom))

    # 9. AI correlation
    result['ai'] = ai_correlate(result)

    # 10. Confidence
    result['confidence'] = calculate_confidence(result, result['ai'])

    # Country centroid only: a phone number does not establish a device location.
    if info.get('coords'):
        result['map_nodes'] = [{
            'type': 'country', 'label': info.get('country_name') or 'Country',
            'sub': 'Approximate country-level reference, not phone location',
            'lat': info['coords']['lat'], 'lon': info['coords']['lon'],
            'color': '#39d353', 'icon': '🌍', 'size': 12,
        }]

    result['scan_time'] = round(time.time() - start, 1)
    return result

