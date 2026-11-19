from datetime import timedelta
import pytest
from app import remediation
from app.db import SessionLocal
from app.main import init_db
from app.models import Asset, Finding, Observation, Vulnerability
from app.util import now, iso
from app.engines import risk, intel


def test_workflow_requires_exception_details_and_expires():
    init_db()
    with SessionLocal() as db:
        a=Asset(name='workflow');db.add(a);db.flush()
        f=Finding(asset_id=a.id, evidence={}, status='open');db.add(f);db.flush()
        for state in ('accepted_risk','false_positive'):
            with pytest.raises(ValueError): remediation.update(db,f,{'state':state},'analyst')
            w=remediation.update(db,f,{'state':state,'reason':'maintenance','approver':'A','expiry':iso(now()+timedelta(days=1)), 'owner':'Team', 'due_date':'2027-01-01', 'ticket_reference':'https://jira.example/browse/DS-1'},'analyst')
            assert w['owner']=='Team' and f.status=='open'
        with pytest.raises(ValueError): remediation.update(db,f,{'state':'resolved'},'analyst')
        with pytest.raises(ValueError): remediation.update(db,f,{'ticket_reference':'javascript:alert(1)'},'analyst')
        f.evidence={'workflow':{'state':'accepted_risk','expiry':iso(now()-timedelta(days=1))}}
        assert remediation.workflow(f)['exception_expired']
        db.rollback()


def test_only_newer_scoped_successful_scan_closes_and_records_delta():
    init_db()
    with SessionLocal() as db:
        a=Asset(name='verification', identity_confidence=1, exposure='external', criticality=5);db.add(a)
        v=Vulnerability(cve_id='CVE-2099-99001', cvss=9.8, kev=True);db.add(v);db.flush()
        f=Finding(asset_id=a.id,cve_id=v.cve_id,basis='observed',status='open',last_seen=now()-timedelta(hours=1),first_seen=now()-timedelta(days=2),evidence={});db.add(f);db.flush()
        risk.reassess_asset(db,a.id)
        assert remediation.what_if(db,f)['risk_reduction'] > 0
        o=Observation(asset_id=a.id,status='processed',observed_at=now(),attributes={'findings':[], 'assessment':{'kind':'vulnerability','status':'success','complete':True}});db.add(o);db.flush()
        with pytest.raises(ValueError): remediation.verify(db,f,o.id,'analyst')
        o.attributes={'findings':[], 'assessment':{'kind':'vulnerability','status':'success','complete':True,'finding_codes':[v.cve_id]}};db.flush()
        result=remediation.verify(db,f,o.id,'analyst')
        assert f.status=='resolved' and result['before']['status']=='open' and result['risk_reduced']>0
        assert remediation.metrics(db)['verified_fixes']>=1
        db.rollback()


def test_inventory_change_does_not_close_finding():
    init_db()
    with SessionLocal() as db:
        a=Asset(name='verification-required');db.add(a);db.flush()
        v=Vulnerability(cve_id='CVE-2099-99002',affected=[]);db.add(v);db.flush()
        f=Finding(asset_id=a.id,cve_id=v.cve_id,basis='inferred',status='open');db.add(f);db.flush()
        intel.match_asset(db,a)
        assert f.status=='open' and f.evidence['verification_required']
        db.rollback()
