"""Prioritization explains evidence and uncertainty; bulk edits are atomic."""
from .models import Asset, Finding, RiskAssessment, Vulnerability
from . import services
from .util import now, parse_ts


def queue(db, query='', owner='', state='', limit=100, offset=0):
    rows = services.finding_rows(db, db.query(Finding, Vulnerability, Asset).join(
        Vulnerability, Vulnerability.cve_id == Finding.cve_id).join(Asset, Asset.id == Finding.asset_id).filter(
            Asset.merged_into.is_(None), Finding.status == 'open').all())
    assessments = services.latest_assessments(db, [r['id'] for r in rows])
    out = []
    for row in rows:
        w = row['workflow']
        if query.lower() not in f"{row['cve']} {row['asset']} {row['title']} {w.get('owner', '')}".lower():
            continue
        if owner and w.get('owner') != owner or state and w['state'] != state:
            continue
        reasons = []
        overdue = bool(w.get('due_date') and parse_ts(w['due_date']) < now())
        if overdue: reasons.append('Remediation deadline has passed')
        if row['kev']: reasons.append('CISA KEV lists known exploitation of this CVE')
        if not w.get('owner'): reasons.append('No remediation owner assigned')
        if row['freshness']['assessment_state'] == 'not_recently_assessed': reasons.append('No recent successful assessment; verify current state')
        if row['freshness']['conflicting_evidence']: reasons.append('Sources disagree; review conflicting evidence')
        ra = assessments.get(row['id'])
        if ra:
            reasons.extend(f"{f['label']}: {f['value']} (weight contribution {f['contribution']})" for f in ra.factors if f['contribution'] > 0)
        row['why_attention'] = reasons
        row['evidence_references'] = [{'type':'finding','id':row['id']}, {'type':'asset','id':row['asset_id']}]
        row['priority'] = [int(w['state'] not in ('accepted_risk','false_positive')), int(overdue), int(row['kev']), row['contextual_score'] or 0]
        out.append(row)
    out.sort(key=lambda r: tuple(r['priority']) + (-r['id'],), reverse=True)
    return {'total':len(out), 'items':out[offset:offset+limit], 'sort':'active work, overdue, KEV, contextual score',
            'limitation':'Prioritization uses observed evidence and inferred risk; neither confirms exploitation.'}


def search(db, query):
    from .models import Investigation, Observation
    q = query.strip().lower()
    if not q: return {'assets':[], 'findings':[], 'investigations':[]}
    assets = services.asset_rows(db, db.query(Asset).filter(Asset.merged_into.is_(None)).all())
    return {'assets':[a for a in assets if q in f"{a['name']} {a['owner']} {' '.join(a['ips'])}".lower()][:50],
            'findings':[r for r in services.finding_rows(db, db.query(Finding,Vulnerability,Asset).join(Vulnerability,Vulnerability.cve_id==Finding.cve_id).join(Asset,Asset.id==Finding.asset_id).filter(Asset.merged_into.is_(None)).all()) if q in f"{r['cve']} {r['asset']} {r['title']}".lower()][:50],
            'investigations':[services.investigation_row(i) for i in db.query(Investigation) if q in f"{i.title} {i.conclusion}".lower()][:50]}
