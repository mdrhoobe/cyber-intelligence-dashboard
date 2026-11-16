import sqlite3, json, os
from datetime import datetime

DB_PATH   = os.path.join('reports', 'cid.db')
JSON_PATH = os.path.join('reports', 'results.json')

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs('reports', exist_ok=True)
    with get_conn() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                type      TEXT NOT NULL,
                target    TEXT NOT NULL,
                results   TEXT NOT NULL DEFAULT '{}',
                summary   TEXT DEFAULT '{}',
                timestamp TEXT NOT NULL
            )
        ''')
        conn.commit()
    _migrate_from_json()

def _migrate_from_json():
    if not os.path.exists(JSON_PATH):
        return
    with get_conn() as conn:
        if conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0] > 0:
            return
    try:
        with open(JSON_PATH, 'r', encoding='utf-8') as f:
            old = json.load(f)
        with get_conn() as conn:
            for r in old:
                conn.execute(
                    'INSERT INTO reports (type,target,results,summary,timestamp) VALUES (?,?,?,?,?)',
                    (r.get('type'), r.get('target'),
                     json.dumps(r.get('results', {}), ensure_ascii=False),
                     json.dumps(r.get('summary',  {}), ensure_ascii=False),
                     r.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                )
            conn.commit()
        os.rename(JSON_PATH, JSON_PATH + '.bak')
        print(f'  ✓ Migrated {len(old)} records to SQLite')
    except Exception as e:
        print(f'  ⚠ Migration error: {e}')

def get_all_reports():
    with get_conn() as conn:
        rows = conn.execute('SELECT * FROM reports ORDER BY id DESC').fetchall()
    return [_to_dict(r) for r in rows]

def get_recent_reports(limit=5):
    with get_conn() as conn:
        rows = conn.execute('SELECT * FROM reports ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    return [_to_dict(r) for r in rows]

def count_reports():
    with get_conn() as conn:
        total  = conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        uname  = conn.execute("SELECT COUNT(*) FROM reports WHERE type='username'").fetchone()[0]
        domain = conn.execute("SELECT COUNT(*) FROM reports WHERE type='domain'").fetchone()[0]
    return total, uname, domain

def search_reports(query='', rtype=''):
    sql, params = 'SELECT * FROM reports WHERE 1=1', []
    if query:
        sql += ' AND LOWER(target) LIKE ?'
        params.append(f'%{query.lower()}%')
    if rtype in ('username', 'domain'):
        sql += ' AND type = ?'
        params.append(rtype)
    sql += ' ORDER BY id DESC'
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_to_dict(r) for r in rows]

def save_report(rtype, target, results, summary=None):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_conn() as conn:
        cur = conn.execute(
            'INSERT INTO reports (type,target,results,summary,timestamp) VALUES (?,?,?,?,?)',
            (rtype, target,
             json.dumps(results,        ensure_ascii=False),
             json.dumps(summary or {}, ensure_ascii=False), ts)
        )
        conn.commit()
        row = conn.execute('SELECT * FROM reports WHERE id=?', (cur.lastrowid,)).fetchone()
    return _to_dict(row)

def clear_reports():
    with get_conn() as conn:
        conn.execute('DELETE FROM reports')
        conn.execute("DELETE FROM sqlite_sequence WHERE name='reports'")
        conn.commit()

def get_stats_data():
    from collections import defaultdict
    from datetime import datetime, timedelta
    total, uname_count, domain_count = count_reports()
    if total == 0:
        return None
    with get_conn() as conn:
        rows      = conn.execute('SELECT type,results,summary,timestamp FROM reports').fetchall()
        type_rows = conn.execute('SELECT type, COUNT(*) as cnt FROM reports GROUP BY type').fetchall()
        type_counts = dict(sorted(
        {r['type']: r['cnt'] for r in type_rows}.items(),
        key=lambda x: x[1], reverse=True
    ))
    
    
    daily = defaultdict(int)
    for r in rows:
        try: daily[r['timestamp'].split(' ')[0]] += 1
        except: pass
    
    day_labels, day_counts = [], []
    for i in range(13, -1, -1):
        d = datetime.now() - timedelta(days=i)
        day_labels.append(d.strftime('%b %d'))
        day_counts.append(daily.get(d.strftime('%Y-%m-%d'), 0))
    
    plat_found = defaultdict(int)
    total_found = total_checked = 0
    d_reach = d_ssl = 0
    times = []
    open_ports_total = 0
    headers_scores = []
    
    for r in rows:
        t = r['type']
        try:
            res = json.loads(r['results'] or '{}')
            s   = json.loads(r['summary'] or '{}') if r['summary'] else {}
        except: continue
        
        if t == 'username':
            total_found   += s.get('found', 0)
            total_checked += s.get('total', 0)
            if isinstance(res, list):
                for item in res:
                    if item.get('status') == 'found':
                        plat_found[item.get('platform','?')] += 1
        elif t == 'domain':
            if res.get('reachable'): d_reach += 1
            if res.get('ssl'):       d_ssl   += 1
            if res.get('response_time'): times.append(res['response_time'])
        elif t == 'port_scan':
            open_ports_total += res.get('open', 0)
        elif t == 'headers':
            if res.get('score') is not None:
                headers_scores.append(res['score'])
    
    top = sorted(plat_found.items(), key=lambda x: x[1], reverse=True)[:8]
    
    return {
        'total':        total,
        'uname_count':  uname_count,
        'domain_count': domain_count,
        'type_counts':  type_counts,
        'found_rate':   round((total_found/total_checked*100) if total_checked else 0, 1),
        'd_reach':      d_reach,
        'd_rate':       round((d_reach/domain_count*100) if domain_count else 0, 1),
        'd_ssl':        d_ssl,
        'avg_ms':       round(sum(times)/len(times)) if times else 0,
        'open_ports':   open_ports_total,
        'avg_sec_score':round(sum(headers_scores)/len(headers_scores)) if headers_scores else 0,
        'day_labels':   day_labels,
        'day_counts':   day_counts,
        'top_names':    [p[0] for p in top],
        'top_counts':   [p[1] for p in top],
    }

def _to_dict(row):
    if row is None: return None
    d = dict(row)
    for f in ('results', 'summary'):
        try:    d[f] = json.loads(d[f])
        except: d[f] = {}
    return d
