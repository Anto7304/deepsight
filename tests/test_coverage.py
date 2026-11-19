import json
from app.coverage import cpe_match, configuration_match, reconciliation, attack_paths
from app.connectors import REGISTRY
from app.main import init_db
from app.db import SessionLocal
from app.models import Asset, Observation, Source, Relationship, Finding, Vulnerability, WebhookDelivery
from app.engines import intel, risk
from app.notifications import enqueue_alerts, dispatch
from app.util import now


def test_nvd_cpe_bounds_and_compound_conditions():
    cpe='cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*'
    rule={'criteria':'cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*','versionStartIncluding':'2.0','versionEndExcluding':'3.0'}
    assert cpe_match(rule,[cpe])
    assert not cpe_match(rule,[cpe.replace(':2.1:',':3.0:')])
    node={'operator':'AND','nodes':[{'cpeMatch':[rule]},{'cpeMatch':[{'criteria':'cpe:2.3:o:example:os:1:*:*:*:*:*:*:*'}]}]}
    assert not configuration_match(node,[cpe])
    init_db()
    with SessionLocal() as db:
        a=Asset(name='cpe-test',config={'_cpes':[cpe]});db.add(a);db.commit()
        intel.import_nvd_json(db,{'vulnerabilities':[{'cve':{'id':'CVE-2099-99100','configurations':[{'nodes':[{'cpeMatch':[rule]}]}]}}]})
        found=intel.match_asset(db,a)
        assert found and found[0].basis=='inferred'


def test_trivy_grype_and_empty_assessment():
    trivy={'ArtifactName':'image:demo','Results':[{'Target':'os','Vulnerabilities':[{'VulnerabilityID':'CVE-2099-99200','PkgName':'x','InstalledVersion':'1','FixedVersion':'2'}]}]}
    grype={'source':{'target':{'userInput':'image:demo'}},'matches':[{'vulnerability':{'id':'CVE-2099-99200','fix':{'versions':['2']}},'artifact':{'name':'x','version':'1'}}]}
    for kind,data in [('trivy_json',trivy),('grype_json',grype)]:
        row=REGISTRY[kind].parse(json.dumps(data),'scan.json',{})[0]
        assert row['attributes']['findings'][0]['cve']=='CVE-2099-99200'
        assert row['attributes']['assessment']['complete']
    assert REGISTRY['trivy_json'].parse('{"ArtifactName":"clean","Results":[]}', 'scan.json',{})[0]['attributes']['findings']==[]


def test_cmdb_and_candidate_paths():
    init_db()
    with SessionLocal() as db:
        s=Source(name='cmdb-case',kind='csv_hosts',category='cmdb');a=Asset(name='cmdb-only',exposure='external');b=Asset(name='seen-only',criticality=5)
        db.add_all([s,a,b]);db.flush()
        db.add_all([Observation(asset_id=a.id,source_id=s.id,status='processed'),Observation(asset_id=b.id,status='processed'),Relationship(src_id=a.id,dst_id=b.id,type='connects_to',basis='inferred',confidence=.6)])
        db.flush();r=reconciliation(db)
        assert a.id in {x['id'] for x in r['in_cmdb_never_seen']}
        assert b.id in {x['id'] for x in r['seen_not_in_cmdb']}
        assert any(x['assets'][0]['id']==a.id for x in attack_paths(db)['paths'])
        db.rollback()


def test_webhook_dedupe_retry_and_delivery(monkeypatch):
    init_db()
    with SessionLocal() as db:
        s=Source(name='webhook-case',kind='outbound_webhook',config={'url':'https://example.test/hook'},enabled=True)
        a=Asset(name='webhook-case');v=Vulnerability(cve_id='CVE-2099-99300',kev=True,cvss=9.8);db.add_all([s,a,v]);db.flush()
        f=Finding(asset_id=a.id,cve_id=v.cve_id,status='open',basis='observed',last_seen=now());db.add(f);db.flush()
        risk.reassess_asset(db,a.id);enqueue_alerts(db,a.id);enqueue_alerts(db,a.id)
        assert db.query(WebhookDelivery).filter_by(source_id=s.id).count()==1
        monkeypatch.setattr('app.connectors._check_url',lambda url:None)
        def fail(*args,**kwargs):raise RuntimeError('network down')
        monkeypatch.setattr('app.notifications.httpx.post',fail)
        assert dispatch(db)['failed_attempts']==1
        row=db.query(WebhookDelivery).filter_by(source_id=s.id).first();assert row.status=='pending';row.next_attempt=now();db.flush()
        class R:
            def raise_for_status(self):pass
        monkeypatch.setattr('app.notifications.httpx.post',lambda *a,**k:R())
        assert dispatch(db)['delivered']==1 and row.status=='delivered'


def test_demo_cmdb_source_is_recognised_by_reconciliation():
    # Regression: the demo CMDB feed was categorised "infrastructure", so every demo asset showed as "seen, not in CMDB".
    from app.demo import SOURCES
    cmdb=[name for name,kind,category in SOURCES if name=='cmdb-inventory']
    assert cmdb and [c for n,k,c in SOURCES if n=='cmdb-inventory']==['cmdb']
