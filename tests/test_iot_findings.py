import json
import pytest
from app.db import SessionLocal
from app.main import init_db
from app.models import Asset, Finding, Vulnerability
from app.engines import iot, risk
from app.normalize import validate_observation
from app.util import now

@pytest.mark.parametrize('port,extra,code',[(23,{},'TELNET'),(21,{},'FTP'),(1883,{},'MQTT'),(554,{'auth_required':False},'RTSP'),(9100,{},'PRINT'),(8291,{},'WINBOX')])
def test_protocol_findings_are_scored_without_cves(port,extra,code):
    init_db()
    with SessionLocal() as db:
        a=Asset(name='iot-rule',type='iot_device',exposure='external',identity_confidence=1);db.add(a);db.flush()
        attrs=validate_observation({'identifiers':{'serial':'rule-device'},'attributes':{'services':[{'port':port,**extra}]}})['attributes']
        found=iot.detect(db,a,attrs,999,now());db.flush()
        assert found[0].cve_id=='DS-IOT-'+code
        assert db.get(Vulnerability,found[0].cve_id).cvss is None
        assert risk.reassess_asset(db,a.id)['score']>15
        assert iot.detect(db,a,attrs,1000,now())==[]
        assert db.query(Finding).filter_by(asset_id=a.id).count()==1
        db.rollback()


def test_secure_or_unknown_rtsp_and_supported_firmware_not_flagged():
    init_db()
    with SessionLocal() as db:
        a=Asset(name='secure-iot',type='iot_device');db.add(a);db.flush()
        assert not iot.detect(db,a,{'services':[{'port':554},{'port':1883,'tls':True}], 'config':{'firmware_support':'supported'}},1,now())
        assert iot.detect(db,a,{'config':{'firmware_support':'end_of_life','lifecycle_source':'vendor inventory'}},1,now())[0].cve_id=='DS-IOT-EOL'
        db.rollback()


def test_lab_policy_scenarios_cover_all_rules():
    init_db()
    from app import pipeline
    from app.models import Source
    with SessionLocal() as db:
        s=Source(name='iot-rule-lab',kind='generic_json');db.add(s);db.commit()
        result=pipeline.ingest(db,s,json.load(open('lab/lab_inventory.json')))
        assert result['counts']['failed']==0
        codes={f.cve_id for f in db.query(Finding).filter(Finding.cve_id.like('DS-IOT-%'))}
        assert set(iot.RULES)<=codes
