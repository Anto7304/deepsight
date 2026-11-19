"""Independent fixed evaluation plus separately reported analyst-labelled cohorts."""
import json
from pathlib import Path
from .engines import identity, ml
from .models import Anomaly, Asset, IdentityDecision, Investigation, ModelRun, Observation, Setting
from .util import iso, now

ROOT = Path(__file__).resolve().parent.parent / 'eval'


def counts(labels, predictions, kind=None):
    tp=sum(y == 1 and p == 1 for y,p in zip(labels,predictions))
    fp=sum(y == 0 and p == 1 for y,p in zip(labels,predictions))
    fn=sum(y == 1 and p == 0 for y,p in zip(labels,predictions))
    tn=sum(y == 0 and p == 0 for y,p in zip(labels,predictions))
    div=lambda x,y: round(x/y,4) if y else None
    out={'n':len(labels),'tp':tp,'fp':fp,'fn':fn,'tn':tn,'accuracy':div(tp+tn,len(labels)),
         'precision':div(tp,tp+fp),'recall':div(tp,tp+fn),'false_merge_rate':div(fp,tp+fp),
         'false_alert_rate':div(fp,fp+tn)}
    # A merge-specific rate is meaningless for anomalies, and an alert rate is meaningless for identity pairs.
    if kind=='identity':out.pop('false_alert_rate')
    if kind=='anomaly':out.pop('false_merge_rate')
    return out


def pair_prediction(observed,candidate,obs_os=None,cand_os=None):
    cand={k:{'all':set(v),'active':set(v)} for k,v in candidate.items()}
    f,hard,_=identity.pair_features(observed,obs_os,cand,cand_os)
    p=ml.entity_model().proba(identity.vec(f))
    weak=f['n_kinds']>=2 and not f['hostname_digit_diff'] and not f['os_conflict'] and (f['hostname_exact'] or f['hostname_short'])
    return int(not hard and ((f['strong_any'] and p>=.85) or (not f['strong_any'] and weak and p>=.90)))


def capture_identity_label(db,decision,label,actor):
    obs=db.get(Observation,decision.observation_id)
    cand=db.get(Asset,decision.candidate_asset_id)
    if not obs or not cand:return
    ids=identity._asset_ident_map(db,[cand.id])[cand.id]
    value={'observed':obs.identifiers,'candidate':{k:sorted(v['all']) for k,v in ids.items()},
           'obs_os':obs.attributes.get('os_family'),'cand_os':cand.os_family,'label':label,
           'by':actor,'at':iso(now()),'decision_id':decision.id}
    key=f'identity_label:{decision.id}'
    row=db.get(Setting,key)
    if row:row.value=value
    else:db.add(Setting(key=key,value=value))


def evaluate(db):
    pairs=json.loads((ROOT/'identity.json').read_text())['pairs']
    events=json.loads((ROOT/'changes.json').read_text())['events']
    iy=[x['label'] for x in pairs]; ip=[pair_prediction(x['observed'],x['candidate']) for x in pairs]
    model=ml.anomaly_model()
    ay=[x['label'] for x in events]
    ap=[int(model.score(dict(zip(ml.ANOM_FEATURES,x['vector'])))[0]>=model.effective_threshold) for x in events]
    feedback=[s.value for s in db.query(Setting).filter(Setting.key.like('identity_label:%'))
              if db.get(IdentityDecision,s.value['decision_id']) and db.get(IdentityDecision,s.value['decision_id']).status in ('confirmed','rejected')]
    fy=[x['label'] for x in feedback];fp=[pair_prediction(x['observed'],x['candidate'],x.get('obs_os'),x.get('cand_os')) for x in feedback]
    an=db.query(Anomaly).filter(Anomaly.status.in_(['true_positive','false_positive'])).all()
    by=[int(a.status=='true_positive') for a in an];bp=[int(model.score(a.features)[0]>=model.effective_threshold) for a in an]
    results={}
    for name,y,p,fy2,fp2,version in [('identity',iy,ip,fy,fp,ml.entity_model().version),('anomaly',ay,ap,by,bp,model.version)]:
        baseline=counts(y,p,name);combined=counts(y+fy2,p+fp2,name)
        result={'independent':baseline,'analyst_feedback':counts(fy2,fp2,name),'combined':combined,
                'metric_delta':{k:round(combined[k]-baseline[k],4) if combined[k] is not None and baseline[k] is not None else None for k in ('precision','recall','accuracy')},
                'limitation':'Small curated fixtures; feedback is a selected cohort. No production generalization claim or automatic retraining. Anomaly labels mean warrants review, not malice.'}
        db.add(ModelRun(name=name+'-evaluation',version=version,metrics=result,status='evaluated',data_origin='independent+analyst-feedback',notes=result['limitation']))
        results[name]=result
    db.commit()
    return results


def effectiveness(db):
    from .remediation import metrics
    total=db.query(Asset).count();merged=db.query(Asset).filter(Asset.merged_into.isnot(None)).count()
    completed=db.query(Investigation).filter(Investigation.validated_at.isnot(None)).all()
    durations=[(i.validated_at-i.created_at).total_seconds()/3600 for i in completed]
    runs={}
    for name in ('identity','anomaly'):
        r=db.query(ModelRun).filter(ModelRun.name==name+'-evaluation').order_by(ModelRun.id.desc()).first()
        runs[name]=r.metrics if r else None
    return {'model_evaluations':runs,'duplicate_reduction':{'merged_records':merged,'total_records':total,'fraction':merged/total if total else None},
            'investigation_time':{'completed':len(durations),'mean_hours':sum(durations)/len(durations) if durations else None,'time_saved_vs_baseline':None},
            'remediation':metrics(db),'limitation':'Database-derived counts and durations. Time saved and production identification accuracy remain unmeasured.'}
