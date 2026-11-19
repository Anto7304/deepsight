"""Durable outbox with per-destination event deduplication and bounded retries."""
from datetime import timedelta
import httpx
from .models import Asset, Finding, RiskAssessment, Source, Vulnerability, WebhookDelivery
from .util import iso, now


def enqueue_alerts(db,asset_id):
    targets=db.query(Source).filter(Source.kind=='outbound_webhook',Source.enabled.is_(True)).all()
    if not targets:return
    for f,v in db.query(Finding,Vulnerability).join(Vulnerability,Vulnerability.cve_id==Finding.cve_id).filter(Finding.asset_id==asset_id,Finding.status=='open'):
        ra=db.query(RiskAssessment).filter(RiskAssessment.finding_id==f.id).order_by(RiskAssessment.id.desc()).first()
        if not v.kev and not (ra and ra.level=='critical'):continue
        event='kev' if v.kev else 'critical'
        for target in targets:
            key=f'{target.id}:finding:{f.id}:{event}'
            if db.query(WebhookDelivery).filter(WebhookDelivery.event_key==key).first():continue
            db.add(WebhookDelivery(event_key=key,source_id=target.id,payload={'product':'DEEPSIGHT','version':'1.1.0',
                'event':event,'finding_id':f.id,'asset_id':asset_id,'code':f.cve_id,'basis':f.basis,
                'contextual_risk':ra.score if ra else None,'confidence':ra.confidence if ra else None,
                'evidence':f.evidence,'generated_at':iso(now())}))
            db.flush()


def dispatch(db):
    from .connectors import _check_url
    done=failed=0
    for row in db.query(WebhookDelivery).filter(WebhookDelivery.status=='pending',WebhookDelivery.next_attempt<=now()).limit(50).all():
        src=db.get(Source,row.source_id)
        if not src or not src.enabled:continue
        row.attempts+=1
        try:
            url=(src.config or {}).get('url','');_check_url(url)
            response=httpx.post(url,json=row.payload,headers={'Idempotency-Key':row.event_key},timeout=10,follow_redirects=False)
            response.raise_for_status()
            row.status='delivered';row.delivered_at=now();row.error=None;done+=1
        except Exception as exc:
            row.error=f'{type(exc).__name__}: {exc}'[:1000]
            row.status='failed' if row.attempts>=5 else 'pending'
            row.next_attempt=now()+timedelta(seconds=min(3600,30*2**row.attempts));failed+=1
        db.commit()
    return {'delivered':done,'failed_attempts':failed}
