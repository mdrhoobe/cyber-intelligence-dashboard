"""
scheduler.py — Automated Scheduled Scans
Author: Mohammed Salih
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from datetime import datetime
import json, os

# ── Job Store (SQLite) ────────────────────────────────────
DB_PATH  = 'reports/cid.db'
jobstore = {'default': SQLAlchemyJobStore(url=f'sqlite:///{DB_PATH}')}
scheduler = BackgroundScheduler(jobstores=jobstore, timezone='UTC')

# ── Helpers ───────────────────────────────────────────────
def get_scheduler_db():
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_scheduler_table():
    with get_scheduler_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                scan_type   TEXT    NOT NULL,
                frequency   TEXT    NOT NULL,
                last_run    TEXT,
                next_run    TEXT,
                run_count   INTEGER DEFAULT 0,
                active      INTEGER DEFAULT 1,
                created_at  TEXT    NOT NULL
            )
        ''')
        conn.commit()

def get_all_schedules():
    with get_scheduler_db() as conn:
        rows = conn.execute(
            'SELECT * FROM scheduled_scans ORDER BY id DESC'
        ).fetchall()
    return [dict(r) for r in rows]

def get_schedule(schedule_id):
    with get_scheduler_db() as conn:
        row = conn.execute(
            'SELECT * FROM scheduled_scans WHERE id=?', (schedule_id,)
        ).fetchone()
    return dict(row) if row else None

def create_schedule(name, target, scan_type, frequency):
    from datetime import datetime
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_scheduler_db() as conn:
        cur = conn.execute(
            '''INSERT INTO scheduled_scans
               (name, target, scan_type, frequency, created_at)
               VALUES (?,?,?,?,?)''',
            (name, target, scan_type, frequency, now)
        )
        conn.commit()
        return cur.lastrowid

def update_schedule_run(schedule_id):
    from datetime import datetime
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with get_scheduler_db() as conn:
        conn.execute(
            '''UPDATE scheduled_scans
               SET last_run=?, run_count=run_count+1
               WHERE id=?''',
            (now, schedule_id)
        )
        conn.commit()

def delete_schedule_db(schedule_id):
    with get_scheduler_db() as conn:
        conn.execute('DELETE FROM scheduled_scans WHERE id=?', (schedule_id,))
        conn.commit()

def toggle_schedule_db(schedule_id, active):
    with get_scheduler_db() as conn:
        conn.execute(
            'UPDATE scheduled_scans SET active=? WHERE id=?',
            (1 if active else 0, schedule_id)
        )
        conn.commit()

# ── Scan Runner ───────────────────────────────────────────
def run_scheduled_scan(schedule_id, target, scan_type):
    """Called by APScheduler at scheduled time"""
    from app import (check_username, check_domain, lookup_ip,
                     dns_lookup, port_scan, check_headers,
                     get_whois, ssl_inspect, universal_analyze)
    from db import save_report
    from datetime import datetime

    print(f'[{datetime.now().strftime("%H:%M:%S")}] Scheduled scan: {scan_type} → {target}')

    try:
        if scan_type != 'username':
            from target_validation import validate_public_target
            validate_public_target(target)
        if scan_type == 'username':
            results, summary = check_username(target)
            save_report('username', target, results, summary)
        elif scan_type == 'domain':
            result = check_domain(target)
            save_report('domain', target, result)
        elif scan_type == 'ip':
            result = lookup_ip(target)
            save_report('ip_lookup', target, result)
        elif scan_type == 'dns':
            result = dns_lookup(target)
            save_report('dns', target, result)
        elif scan_type == 'ports':
            result = port_scan(target)
            save_report('port_scan', target, result)
        elif scan_type == 'headers':
            result = check_headers(target)
            save_report('headers', target, result)
        elif scan_type == 'ssl':
            result = ssl_inspect(target)
            save_report('ssl', target, result)
        elif scan_type == 'analyze':
            result = universal_analyze(target)
            save_report('analyze', target, result)

        update_schedule_run(schedule_id)
        print(f'    ✓ Done')
    except Exception as e:
        print(f'    ✗ Error: {e}')

# ── Add Job ───────────────────────────────────────────────
def add_job(schedule_id, target, scan_type, frequency):
    """frequency: hourly, daily, weekly"""
    job_id = f'scan_{schedule_id}'

    # Remove old job if exists
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    kwargs = dict(
        func=run_scheduled_scan,
        args=[schedule_id, target, scan_type],
        id=job_id,
        replace_existing=True,
        misfire_grace_time=300,
    )

    if frequency == 'hourly':
        scheduler.add_job(trigger='interval', hours=1, **kwargs)
    elif frequency == 'daily':
        scheduler.add_job(trigger='interval', days=1, **kwargs)
    elif frequency == 'weekly':
        scheduler.add_job(trigger='interval', weeks=1, **kwargs)
    elif frequency == 'every_5m':   # للتجربة
        scheduler.add_job(trigger='interval', minutes=5, **kwargs)

def remove_job(schedule_id):
    job_id = f'scan_{schedule_id}'
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

# ── Start ─────────────────────────────────────────────────
def start_scheduler():
    init_scheduler_table()
    if not scheduler.running:
        scheduler.start()
    # Restore active schedules from DB
    for s in get_all_schedules():
        if s['active']:
            add_job(s['id'], s['target'], s['scan_type'], s['frequency'])
    print(f'  ✓ Scheduler started — {len(get_all_schedules())} jobs loaded')
