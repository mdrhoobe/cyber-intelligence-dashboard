"""
pdf_gen.py — Professional PDF Report Generator
Author: Mohammed Saleh
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import io
from xml.sax.saxutils import escape

# ── Colors ────────────────────────────────────────────────
C_BG      = colors.HexColor('#050a05')
C_CARD    = colors.HexColor('#080f08')
C_GREEN   = colors.HexColor('#39d353')
C_AMBER   = colors.HexColor('#e8a020')
C_RED     = colors.HexColor('#cc2936')
C_VIOLET  = colors.HexColor('#7c4dba')
C_TEXT    = colors.HexColor('#c8e8c8')
C_DIM     = colors.HexColor('#3a5c3a')
C_WHITE   = colors.white
C_BORDER  = colors.HexColor('#1a2e1a')

# ── Styles ────────────────────────────────────────────────
def get_styles():
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle('title',
            fontName='Helvetica-Bold', fontSize=22,
            textColor=C_GREEN, spaceAfter=4,
            leading=26),
        'subtitle': ParagraphStyle('subtitle',
            fontName='Helvetica', fontSize=10,
            textColor=C_DIM, spaceAfter=2),
        'section': ParagraphStyle('section',
            fontName='Helvetica-Bold', fontSize=11,
            textColor=C_AMBER, spaceBefore=14, spaceAfter=6,
            leading=14),
        'body': ParagraphStyle('body',
            fontName='Helvetica', fontSize=9,
            textColor=C_TEXT, leading=13),
        'mono': ParagraphStyle('mono',
            fontName='Courier', fontSize=8,
            textColor=C_GREEN, leading=11),
        'footer': ParagraphStyle('footer',
            fontName='Helvetica', fontSize=8,
            textColor=C_DIM, alignment=TA_CENTER),
        'label': ParagraphStyle('label',
            fontName='Helvetica-Bold', fontSize=8,
            textColor=C_DIM),
        'value': ParagraphStyle('value',
            fontName='Courier', fontSize=9,
            textColor=C_TEXT),
        'danger': ParagraphStyle('danger',
            fontName='Helvetica-Bold', fontSize=9,
            textColor=C_RED),
        'ok': ParagraphStyle('ok',
            fontName='Helvetica-Bold', fontSize=9,
            textColor=C_GREEN),
    }

# ── Table Style ───────────────────────────────────────────
def header_table_style(header_color=None):
    hc = header_color or C_CARD
    return TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  hc),
        ('TEXTCOLOR',    (0,0), (-1,0),  C_AMBER),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0),  8),
        ('FONTNAME',     (0,1), (-1,-1), 'Courier'),
        ('FONTSIZE',     (0,1), (-1,-1), 8),
        ('TEXTCOLOR',    (0,1), (-1,-1), C_TEXT),
        ('BACKGROUND',   (0,1), (-1,-1), C_CARD),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_CARD, colors.HexColor('#0a140a')]),
        ('GRID',         (0,0), (-1,-1), 0.3, C_BORDER),
        ('ALIGN',        (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ('LEFTPADDING',  (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ])

def kv_table(rows, col_widths=None):
    """Key-Value table"""
    w = col_widths or [5*cm, 11.5*cm]
    t = Table(rows, colWidths=w)
    t.setStyle(TableStyle([
        ('FONTNAME',     (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',     (1,0), (1,-1), 'Courier'),
        ('FONTSIZE',     (0,0), (-1,-1), 8),
        ('TEXTCOLOR',    (0,0), (0,-1),  C_DIM),
        ('TEXTCOLOR',    (1,0), (1,-1),  C_TEXT),
        ('BACKGROUND',   (0,0), (-1,-1), C_CARD),
        ('ROWBACKGROUNDS',(0,0),(-1,-1), [C_CARD, colors.HexColor('#0a140a')]),
        ('GRID',         (0,0), (-1,-1), 0.3, C_BORDER),
        ('LEFTPADDING',  (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
    ]))
    return t

# ── Header Block ──────────────────────────────────────────
def build_header(story, styles, report):
    # Top bar
    story.append(Table(
        [[
            Paragraph('⬡  CYBER INTELLIGENCE DASHBOARD', ParagraphStyle(
                'logo', fontName='Helvetica-Bold', fontSize=13,
                textColor=C_GREEN)),
            Paragraph('CLASSIFIED // EDUCATIONAL USE ONLY', ParagraphStyle(
                'cls', fontName='Helvetica-Bold', fontSize=8,
                textColor=C_RED, alignment=TA_RIGHT)),
        ]],
        colWidths=[10*cm, 6.5*cm],
        style=TableStyle([
            ('BACKGROUND', (0,0),(-1,-1), C_CARD),
            ('LEFTPADDING',(0,0),(-1,-1), 10),
            ('RIGHTPADDING',(0,0),(-1,-1),10),
            ('TOPPADDING', (0,0),(-1,-1), 8),
            ('BOTTOMPADDING',(0,0),(-1,-1),8),
            ('LINEBELOW',  (0,0),(-1,-1), 1, C_GREEN),
        ])
    ))
    story.append(Spacer(1, 0.4*cm))

    # Title
    rtype = report.get('type','').replace('_',' ').upper()
    story.append(Paragraph(f"INVESTIGATION REPORT — {rtype}", styles['title']))
    story.append(Paragraph(f"Target: {escape(str(report.get('target','')))}  ·  "
                           f"ID: #{report.get('id','')}  ·  "
                           f"{escape(str(report.get('timestamp','')))}", styles['subtitle']))
    story.append(HRFlowable(width='100%', thickness=0.5,
                             color=C_BORDER, spaceAfter=12))

# ── Footer ────────────────────────────────────────────────
def build_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_DIM)
    canvas.setFont('Helvetica', 7)
    canvas.drawString(2*cm, 1.2*cm,
        f"CID v8.0 — Mohammed Saleh — Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} — Educational Use Only")
    canvas.drawRightString(19*cm, 1.2*cm, f"Page {doc.page}")
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.3)
    canvas.line(2*cm, 1.5*cm, 19*cm, 1.5*cm)
    canvas.restoreState()

# ── Section helpers ───────────────────────────────────────
def section_title(story, styles, title, icon='◈'):
    story.append(Paragraph(f"{icon}  {title.upper()}", styles['section']))

def flag_block(story, styles, flags):
    if not flags:
        story.append(Paragraph('✓  No indicators recorded; safety is not established', styles['ok']))
        return
    for flag in flags:
        sev   = flag.get('sev','low')
        color = C_RED if sev=='high' else C_AMBER
        t = Table([[Paragraph(f"⚠  {escape(str(flag['msg']))}", ParagraphStyle(
            'fl', fontName='Helvetica', fontSize=8, textColor=color))]],
            colWidths=[16.5*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1), colors.HexColor(
                '#330a0a' if sev=='high' else '#332200')),
            ('LEFTPADDING',(0,0),(-1,-1),8),
            ('TOPPADDING',(0,0),(-1,-1),5),
            ('BOTTOMPADDING',(0,0),(-1,-1),5),
            ('LINEBELOW',(0,0),(-1,-1),0.3,C_BORDER),
        ]))
        story.append(t)

# ══════════════════════════════════════════════════════════
#  Report Builders
# ══════════════════════════════════════════════════════════

def build_username_report(story, styles, results, summary):
    section_title(story, styles, 'Summary')
    story.append(Table([
        ['Platforms Checked', 'Found', 'Not Found', 'Errors/Timeouts'],
        [str(summary.get('total',0)), str(summary.get('found',0)),
         str(summary.get('not_found',0)), str(summary.get('errors',0))]
    ], colWidths=[4.1*cm]*4, style=header_table_style()))
    story.append(Spacer(1, 0.5*cm))

    found = [r for r in results if r.get('status')=='found']
    if found:
        section_title(story, styles, f'Found Profiles ({len(found)})', '✓')
        rows = [['Platform', 'URL', 'Response (ms)']]
        for r in found:
            rows.append([r.get('platform',''), r.get('url',''), str(r.get('ms','—'))])
        t = Table(rows, colWidths=[3.5*cm, 11*cm, 2*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),  colors.HexColor('#0a1a0a')),
            ('TEXTCOLOR', (0,0),(-1,0),  C_GREEN),
            ('FONTNAME',  (0,0),(-1,0),  'Helvetica-Bold'),
            ('FONTNAME',  (0,1),(-1,-1), 'Courier'),
            ('FONTSIZE',  (0,0),(-1,-1), 8),
            ('TEXTCOLOR', (0,1),(-1,-1), C_TEXT),
            ('BACKGROUND',(0,1),(-1,-1), C_CARD),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_CARD,colors.HexColor('#0a140a')]),
            ('GRID',      (0,0),(-1,-1), 0.3, C_BORDER),
            ('LEFTPADDING',(0,0),(-1,-1),8),
            ('TOPPADDING',(0,0),(-1,-1),5),
            ('BOTTOMPADDING',(0,0),(-1,-1),5),
        ]))
        story.append(t)

    not_found = [r for r in results if r.get('status')=='not_found']
    if not_found:
        story.append(Spacer(1,0.4*cm))
        section_title(story, styles, f'Not Found ({len(not_found)})', '✗')
        platforms = [r.get('platform','') for r in not_found]
        rows = [platforms[i:i+4] for i in range(0, len(platforms), 4)]
        t = Table(rows, colWidths=[4.1*cm]*4)
        t.setStyle(TableStyle([
            ('FONTNAME', (0,0),(-1,-1),'Courier'),
            ('FONTSIZE', (0,0),(-1,-1), 8),
            ('TEXTCOLOR',(0,0),(-1,-1), C_DIM),
            ('BACKGROUND',(0,0),(-1,-1),C_CARD),
            ('GRID',(0,0),(-1,-1),0.3,C_BORDER),
            ('LEFTPADDING',(0,0),(-1,-1),8),
            ('TOPPADDING',(0,0),(-1,-1),4),
            ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ]))
        story.append(t)

def build_domain_report(story, styles, res):
    section_title(story, styles, 'Domain Analysis')
    rows = [
        ['IP Address',    res.get('ip','—')],
        ['HTTPS Status',  str(res.get('https_status','—'))],
        ['HTTP Status',   str(res.get('http_status','—'))],
        ['SSL',           '✓ Valid' if res.get('ssl') else '✗ None / Error'],
        ['Response Time', f"{res.get('response_time','—')} ms"],
        ['Server',        res.get('server','—')],
        ['Content-Type',  res.get('content_type','—')],
        ['Redirect',      res.get('redirect','None') or 'None'],
        ['Reachable',     'YES' if res.get('reachable') else 'NO'],
    ]
    story.append(kv_table(rows))

def build_ip_report(story, styles, res):
    section_title(story, styles, 'IP Intelligence')
    rows = [
        ['Query IP',      res.get('query','—')],
        ['Country',       f"{res.get('country','—')} ({res.get('countryCode','')})"],
        ['Region',        res.get('regionName','—')],
        ['City',          res.get('city','—')],
        ['Timezone',      res.get('timezone','—')],
        ['ISP',           res.get('isp','—')],
        ['Organization',  res.get('org','—')],
        ['AS Number',     res.get('as','—')],
        ['Proxy / VPN',   'YES ⚠' if res.get('proxy') else 'NO'],
        ['Hosting / DC',  'YES' if res.get('hosting') else 'NO'],
        ['Mobile',        'YES' if res.get('mobile') else 'NO'],
    ]
    story.append(kv_table(rows))

def build_ports_report(story, styles, res):
    section_title(story, styles, f"Port Scan — {res.get('open',0)} Open Ports")
    open_ports  = [p for p in res.get('ports',[]) if p['status']=='open']
    closed_ports = [p for p in res.get('ports',[]) if p['status']!='open']
    if open_ports:
        rows = [['Port','Service','Status']]
        for p in open_ports:
            rows.append([str(p['port']), p['service'], '● OPEN'])
        t = Table(rows, colWidths=[3*cm, 10*cm, 3.5*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a0a0a')),
            ('TEXTCOLOR', (0,0),(-1,0),C_RED),
            ('FONTNAME',  (0,0),(-1,0),'Helvetica-Bold'),
            ('FONTNAME',  (0,1),(-1,-1),'Courier'),
            ('FONTSIZE',  (0,0),(-1,-1),8),
            ('TEXTCOLOR', (0,1),(-1,-1),C_TEXT),
            ('TEXTCOLOR', (2,1),(2,-1),C_RED),
            ('BACKGROUND',(0,1),(-1,-1),colors.HexColor('#0a0808')),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#2a1a1a')),
            ('LEFTPADDING',(0,0),(-1,-1),8),
            ('TOPPADDING',(0,0),(-1,-1),5),
            ('BOTTOMPADDING',(0,0),(-1,-1),5),
        ]))
        story.append(t)
    if closed_ports:
        story.append(Spacer(1,0.4*cm))
        story.append(Paragraph('Closed / Filtered Ports:', styles['label']))
        names = [f"{p['port']}/{p['service']}" for p in closed_ports]
        story.append(Paragraph('  '.join(names), styles['mono']))

def build_headers_report(story, styles, res):
    grade = res.get('grade','?')
    score = res.get('score',0)
    gc    = C_GREEN if score>=75 else C_AMBER if score>=50 else C_RED
    section_title(story, styles, f"Security Headers — Grade {grade} ({score}%)")
    story.append(Table([
        [Paragraph(grade, ParagraphStyle('g', fontName='Helvetica-Bold',
            fontSize=36, textColor=gc, alignment=TA_CENTER)),
         kv_table([
            ['HTTP Status', str(res.get('status','—'))],
            ['Server',      res.get('server','—')],
            ['X-Powered-By',res.get('powered','Hidden')],
            ['Score',       f"{score}/100"],
         ], col_widths=[3.5*cm, 7*cm])
        ]],
        colWidths=[3*cm, 13.5*cm]
    ))
    story.append(Spacer(1,0.4*cm))
    found   = res.get('found',{})
    missing = res.get('missing',[])
    if found:
        story.append(Paragraph('✓  Present Headers:', styles['ok']))
        rows = [['Header', 'Value']]
        for h, meta in found.items():
            rows.append([meta.get('name',h),
                         meta.get('value','')[:60]])
        story.append(Table(rows, colWidths=[5*cm, 11.5*cm],
                           style=header_table_style(colors.HexColor('#0a1a0a'))))
    if missing:
        story.append(Spacer(1,0.3*cm))
        story.append(Paragraph('✗  Missing Headers:', styles['danger']))
        rows = [['Header', 'Risk Level']]
        for m in missing:
            rows.append([m.get('name',m.get('header','')),
                         m.get('risk','').upper()])
        story.append(Table(rows, colWidths=[12*cm, 4.5*cm],
                           style=header_table_style(colors.HexColor('#1a0a0a'))))

def build_ssl_report(story, styles, res):
    section_title(story, styles, 'SSL Certificate')
    days  = res.get('days_left', 0)
    dc    = C_RED if res.get('expired') else C_AMBER if res.get('soon') else C_GREEN
    rows  = [
        ['Common Name',  res.get('cn','—')],
        ['Organization', res.get('org','—')],
        ['Issuer',       res.get('issuer','—')],
        ['Issuer CN',    res.get('issuer_cn','—')],
        ['Valid From',   res.get('not_before','—')],
        ['Expires',      res.get('not_after','—')],
        ['Days Remaining', f"{'EXPIRED' if res.get('expired') else str(days)+' days'}"],
        ['Wildcard',     'YES' if res.get('wildcard') else 'NO'],
        ['SANs Count',   str(len(res.get('san',[])))],
    ]
    story.append(kv_table(rows))
    if res.get('san'):
        story.append(Spacer(1,0.3*cm))
        story.append(Paragraph('Subject Alternative Names:', styles['label']))
        story.append(Paragraph(escape('  ·  '.join(res['san'][:8])), styles['mono']))

def build_threat_report(story, styles, res):
    summary = res.get('summary',{})
    section_title(story, styles, f"Threat Score: {summary.get('risk_score',0)}/100 — {summary.get('level','Unknown')}")
    flag_block(story, styles, [{'msg':f,'sev':'high'} for f in summary.get('flags',[])])
    story.append(Spacer(1,0.4*cm))
    sources = res.get('sources',{})
    for src_name, src_data in sources.items():
        if not src_data.get('available'): continue
        story.append(Paragraph(src_name.upper(), styles['label']))
        rows = [[k.replace('_',' ').title(), str(v)]
                for k,v in src_data.items()
                if k not in ('available',) and v is not None]
        if rows:
            story.append(kv_table(rows[:8]))
        story.append(Spacer(1,0.2*cm))
def build_phone_report(story, styles, res):
    info = res.get('info', {})
    conf = res.get('confidence', {})
    ai   = res.get('ai', {})

    section_title(story, styles,
        f"Phone Intelligence — Evidence coverage {conf.get('score',0)}%")

    # Confidence bar
    score = conf.get('score', 0)
    color = C_GREEN if score >= 70 else C_AMBER if score >= 40 else C_RED
    story.append(Table([
        [Paragraph(f"EVIDENCE COVERAGE: {score}% — {conf.get('level','Unknown')}", ParagraphStyle(
            'cf', fontName='Helvetica-Bold', fontSize=14, textColor=color))]
    ], colWidths=[16.5*cm], style=TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),C_CARD),
        ('LEFTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),
        ('BOTTOMPADDING',(0,0),(-1,-1),8),
        ('LINEBELOW',(0,0),(-1,-1),1,color),
    ])))
    story.append(Spacer(1, 0.4*cm))

    # Number details
    rows = [
        ['E164 Format',    info.get('e164','—')],
        ['International',  info.get('formatted','—')],
        ['Country',        f"{info.get('country_name','—')} ({info.get('country_iso','')})"],
        ['Region',         info.get('region','—')],
        ['Carrier',        info.get('carrier','—')],
        ['Line Type',      info.get('line_type','—')],
        ['Timezones',      ', '.join(info.get('timezones', []))],
        ['Scan Time',      f"{res.get('scan_time',0)}s"],
    ]
    story.append(kv_table(rows))
    story.append(Spacer(1, 0.4*cm))

    # AI Summary
    if ai.get('summary'):
        section_title(story, styles, 'Evidence Summary' if ai.get('method') == 'rules' else 'Assisted Evidence Summary', '◈')
        story.append(Paragraph(escape(str(ai['summary'])), styles['body']))
        story.append(Spacer(1, 0.3*cm))
        if ai.get('observations'):
            for obs in ai['observations']:
                story.append(Paragraph(f'• {escape(str(obs))}', styles['body']))

    # Names
    names = res.get('names', [])
    if names:
        story.append(Spacer(1, 0.4*cm))
        section_title(story, styles, f'Possible Names ({len(names)})', '👤')
        rows = [['Name', 'Source']]
        for name in names:
            rows.append([name, 'Web Search'])
        story.append(Table(rows, colWidths=[8*cm, 8.5*cm],
                           style=header_table_style()))

    # Web hits
    hits = res.get('web_hits', [])
    if hits:
        story.append(Spacer(1, 0.4*cm))
        section_title(story, styles, f'Web Results ({len(hits)})', '🌐')
        rows = [['Title', 'Engine', 'URL']]
        for h in hits[:8]:
            rows.append([
                h.get('title','')[:40],
                h.get('engine',''),
                h.get('url','')[:50]
            ])
        story.append(Table(rows, colWidths=[6*cm, 2.5*cm, 8*cm],
                           style=header_table_style()))

    # Next steps
    if ai.get('next_steps'):
        story.append(Spacer(1, 0.4*cm))
        section_title(story, styles, 'Recommended Next Steps', '→')
        for step in ai['next_steps']:
            story.append(Paragraph(f'→  {escape(str(step))}', styles['body']))

def build_analyze_report(story, styles, res, threat=None):
    if res.get('ip_info') and res['ip_info'].get('status')=='success':
        build_ip_report(story, styles, res['ip_info'])
        story.append(Spacer(1,0.4*cm))
    if res.get('domain_info') and not res.get('is_ip'):
        build_domain_report(story, styles, res['domain_info'])
        story.append(Spacer(1,0.4*cm))
    if res.get('ports'):
        build_ports_report(story, styles, res['ports'])
        story.append(Spacer(1,0.4*cm))
    if res.get('headers') and not res['headers'].get('error'):
        build_headers_report(story, styles, res['headers'])
        story.append(Spacer(1,0.4*cm))
    if res.get('ssl') and not res['ssl'].get('error'):
        build_ssl_report(story, styles, res['ssl'])
    if threat:
        story.append(Spacer(1,0.4*cm))
        section_title(story, styles, f"Threat Score: {threat.get('score',0)}/100")
        flag_block(story, styles, threat.get('flags',[]))

# ══════════════════════════════════════════════════════════
#  Main Generator
# ══════════════════════════════════════════════════════════
def generate_pdf(report):
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.8*cm, bottomMargin=2*cm,
        leftMargin=2*cm,  rightMargin=2*cm,
        title=f"CID Report #{report.get('id','')}",
        author='Cyber Intelligence Dashboard',
    )
    styles = get_styles()
    story  = []

    build_header(story, styles, report)

    rtype   = report.get('type','')
    results = report.get('results',{})
    summary = report.get('summary',{})

    if rtype == 'username':
        build_username_report(story, styles, results, summary)
    elif rtype == 'domain':
        build_domain_report(story, styles, results)
    elif rtype == 'ip_lookup':
        build_ip_report(story, styles, results)
    elif rtype == 'port_scan':
        build_ports_report(story, styles, results)
    elif rtype == 'headers':
        build_headers_report(story, styles, results)
    elif rtype == 'ssl':
        build_ssl_report(story, styles, results)
    elif rtype == 'threat':
        build_threat_report(story, styles, results)
    elif rtype == 'analyze':
        build_analyze_report(story, styles, results, summary)
    elif rtype == 'whois':
        section_title(story, styles, 'WHOIS Data')
        rows = [[k.replace('_',' ').title(), str(v) if not isinstance(v,list) else ', '.join(v[:3])]
                for k,v in results.items() if v and k != 'error']
        story.append(kv_table(rows))
    elif rtype == 'dns':
        section_title(story, styles, 'DNS Records')
        for rtype_dns, vals in (results.get('records') or {}).items():
            if vals:
                story.append(Paragraph(rtype_dns, styles['label']))
                story.append(Paragraph('\n'.join(vals), styles['mono']))
                story.append(Spacer(1,0.2*cm))
    elif rtype == 'phone':
        build_phone_report(story, styles, results)

    else:
        section_title(story, styles, 'Raw Data')
        import json
        story.append(Paragraph(
            json.dumps(results, ensure_ascii=False, indent=2)[:2000],
            styles['mono']))

    # Footer note
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width='100%', thickness=0.3, color=C_BORDER))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        'This report was generated by Cyber Intelligence Dashboard for educational '
        'and research purposes only. Unauthorized use of this information is prohibited.',
        styles['footer']
    ))

    doc.build(story, onFirstPage=build_footer, onLaterPages=build_footer)
    buf.seek(0)
    return buf.read()
