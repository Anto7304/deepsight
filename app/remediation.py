"""Analyst workflow and evidence-gated closure. Decisions never substitute for a scan."""
from copy import deepcopy
from datetime import timedelta
from urllib.parse import urlsplit

from .freshness import age_threshold, complete_assessment
from .models import Asset, Finding, Observation, RiskAssessment, Vulnerability
from .util import iso, now, parse_ts

STATES = {'new', 'confirmed', 'in_progress', 'pending_verification', 'accepted_risk', 'false_positive'}


def workflow(f):
    w = dict((f.evidence or {}).get('workflow') or {})
    w.setdefault('state', (f.evidence or {}).get('triage', {}).get('state', 'new'))
    if w.get('state') in ('accepted_risk', 'false_positive'):
        expiry = parse_ts(w.get('expiry'))
        if expiry is None or expiry <= now():
            w.update(state='new', exception_expired=True)
    if f.status in ('resolved', 'superseded'):
        w['state'] = f.status
    return w


def update(db, f, data, actor):
    w = workflow(f)
    state = data.get('state') or w['state']
    if state not in STATES or f.status in ('resolved', 'superseded'):
        raise ValueError('Findings close only through a successful verification scan; resolved findings reopen on new evidence.')
    if state in ('accepted_risk', 'false_positive') and state != w['state']:
        if not all(str(data.get(k) or '').strip() for k in ('reason', 'approver', 'expiry')):
            raise ValueError('A new exception decision requires its own reason, approver and expiry.')
    w.update({k: v for k, v in data.items() if v is not None})
    w['state'] = state
    if w.get('ticket_reference'):
        url = urlsplit(w['ticket_reference'])
        if url.scheme not in ('https', 'http') or not url.netloc or url.username or url.password:
            raise ValueError('Ticket reference must be an HTTP(S) link without credentials.')
    for field in ('due_date', 'expiry'):
        if w.get(field):
            value = parse_ts(w[field])
            if value is None:
                raise ValueError(f'{field} must be an ISO date or timestamp')
            w[field] = iso(value)
    if state in ('accepted_risk', 'false_positive'):
        if not all(str(w.get(k) or '').strip() for k in ('reason', 'approver', 'expiry')):
            raise ValueError('Accepted risk and false positive require reason, approver and expiry.')
        if parse_ts(w['expiry']) <= now():
            raise ValueError('Exception expiry must be in the future.')
    w.update(by=actor, at=iso(now()))
    hist = list((f.evidence or {}).get('workflow_history', []))
    hist.append(deepcopy(w))
    f.evidence = {**(f.evidence or {}), 'workflow': w, 'workflow_history': hist,
                  'triage': {'state': state, 'note': w.get('reason') or w.get('note'), 'by': actor, 'at': w['at']}}
    db.flush()
    return w


def what_if(db, f):
    from .engines import risk
    a = db.get(Asset, f.asset_id)
    active = db.query(Finding).filter(Finding.asset_id == a.id, Finding.status == 'open').all()
    sub = []
    for other in active:
        if other.id == f.id:
            continue
        ra = db.query(RiskAssessment).filter(RiskAssessment.finding_id == other.id).order_by(RiskAssessment.id.desc()).first()
        if ra:
            sub.append(ra.score)
    sub.sort(reverse=True)
    after = min(100, sub[0] + .15 * sum(sub[1:5])) if sub else 15 + 25 * risk._anomaly_boost(db, a.id)
    before = a.risk_score or 0
    return {'before': before, 'after': round(after, 1), 'risk_reduction': round(max(0, before-after), 1),
            'basis': 'inferred', 'limitation': 'What-if uses current weighted heuristic scores and unchanged context; not a predicted incident reduction.'}


def verify(db, f, observation_id, actor):
    from .engines import risk
    obs = db.get(Observation, observation_id)
    if f.status != 'open':
        raise ValueError('Only open findings can be verified.')
    if (not obs or obs.asset_id != f.asset_id or obs.status != 'processed' or not complete_assessment(obs)
            or obs.observed_at < now() - timedelta(hours=age_threshold(db)) or obs.observed_at <= f.last_seen):
        raise ValueError('Verification requires a newer, recent, successful complete assessment of this asset.')
    scope = obs.attributes['assessment'].get('finding_codes') or []
    if f.cve_id not in scope:
        raise ValueError('Verification scan does not explicitly cover this finding code.')
    present = {str(x.get('cve') or x.get('cve_id') or x.get('code')).upper()
               for x in obs.attributes['findings'] if isinstance(x, dict)}
    if f.cve_id in present:
        raise ValueError('Verification scan still reports this finding.')
    before = {'status': f.status, 'finding_evidence': deepcopy(f.evidence),
              'last_seen': iso(f.last_seen), 'asset_risk': db.get(Asset, f.asset_id).risk_score}
    f.status, f.resolved_at = 'resolved', obs.observed_at
    db.flush()
    result = risk.reassess_asset(db, f.asset_id, force=True)
    event = {'observation_id': obs.id, 'source_id': obs.source_id, 'verified_by': actor,
             'verified_at': iso(now()), 'basis': 'observed', 'before': before,
             'after': {'status': 'resolved', 'assessment': deepcopy(obs.attributes),
                       'asset_risk': result['score'], 'raw_ref': obs.raw_ref},
             'risk_reduced': round(max(0, before['asset_risk'] - result['score']), 1)}
    f.evidence = {**(f.evidence or {}), 'verification': event,
                  'verifications': [*(f.evidence or {}).get('verifications', []), event]}
    db.flush()
    return event


def metrics(db):
    rows = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.merged_into.is_(None)).all()
    fixed = [f for f in rows if f.status == 'resolved' and (f.evidence or {}).get('verification')]
    hours = [(f.resolved_at - f.first_seen).total_seconds()/3600 for f in fixed]
    open_rows = [f for f in rows if f.status == 'open']
    breaches = [f for f in rows if workflow(f).get('due_date') and parse_ts(workflow(f)['due_date']) < (f.resolved_at or now())]
    return {'verified_fixes': len(fixed), 'mean_time_to_fix_hours': round(sum(hours)/len(hours), 2) if hours else None,
            'sla_breaches': len(breaches), 'open_sla_breaches': sum(f.status != 'resolved' for f in breaches),
            'aging': [{'finding_id': f.id, 'hours': round((now()-f.first_seen).total_seconds()/3600, 2)} for f in open_rows],
            'risk_reduced_per_fix': [{'finding_id': f.id, 'points': f.evidence['verification']['risk_reduced']} for f in fixed],
            'limitation': 'Durations use finding observation timestamps; heuristic risk points are not business loss or attack probabilities.'}
