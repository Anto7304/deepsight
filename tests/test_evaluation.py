from datetime import timedelta
from app.main import init_db
from app.db import SessionLocal
from app.models import Anomaly, Asset, ModelRun, Setting, Finding, Vulnerability
from app.evaluation import evaluate, counts
from app.engines import ml, risk
from app.util import now


def test_metric_denominators_and_independent_feedback_runs():
    assert counts([1,0,0],[1,1,0])['precision']==.5
    assert counts([1,0,0],[1,1,0])['false_alert_rate']==.5
    assert counts([],[])['precision'] is None
    init_db()
    with SessionLocal() as db:
        a=Asset(name='eval-feedback');db.add(a);db.flush()
        feats=dict(zip(ml.ANOM_FEATURES,[8,5,1,1,1,2,4,0,1,15,1,1,15]))
        db.add(Anomaly(asset_id=a.id,status='false_positive',features=feats));db.commit()
        result=evaluate(db)
        assert result['identity']['independent']['n']==16
        assert result['anomaly']['independent']['n']==12
        assert result['anomaly']['analyst_feedback']['n']>=1
        assert result['anomaly']['combined']['n']>12
        assert db.query(ModelRun).filter(ModelRun.name=='anomaly-evaluation').first()
        # Each model reports only the error rate that is meaningful for it.
        for cohort in result['identity'].values():
            if isinstance(cohort,dict) and 'tp' in cohort:assert 'false_merge_rate' in cohort and 'false_alert_rate' not in cohort
        for cohort in result['anomaly'].values():
            if isinstance(cohort,dict) and 'tp' in cohort:assert 'false_alert_rate' in cohort and 'false_merge_rate' not in cohort


def test_epss_is_a_separate_labelled_factor_with_staleness():
    init_db()
    with SessionLocal() as db:
        a=Asset(name='epss-test',identity_confidence=1);v=Vulnerability(cve_id='CVE-2099-99003',cvss=8);db.add_all([a,v]);db.flush()
        f=Finding(asset_id=a.id,cve_id=v.cve_id,basis='observed',last_seen=now(),evidence={});db.add(f);db.flush()
        s=Setting(key='epss:'+v.cve_id,value={'epss':.91,'date':now().date().isoformat()});db.add(s);db.flush()
        r=risk.score_finding(db,a,f,v,{'blast':0,'recent':0,'anomaly':0})
        factor=next(x for x in r['factors'] if x['key']=='epss')
        assert factor['value']==.91 and factor['basis']=='ML-predicted'
        s.value={'epss':.91,'date':(now()-timedelta(days=40)).date().isoformat()};db.flush()
        old=risk.score_finding(db,a,f,v,{'blast':0,'recent':0,'anomaly':0})
        assert old['score']<r['score']
        db.rollback()
