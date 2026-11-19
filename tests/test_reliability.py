from datetime import timedelta
import importlib.util
from pathlib import Path
import threading
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.config import settings
from app.db import SessionLocal, Base
from app.main import init_db
from app.models import Asset, AssetIdentifier, BackgroundJob, CollectionRun, IdentityBlock, Observation, Setting, Source, SchemaVersion
from app import collector, jobs, retention
from app.engines.identity import find_candidates
from app.migrations import upgrade
from app.observability import health, prometheus
from app.security import RateLimiter, SecretDecryptionError, decrypt_secrets, encrypt_secrets


def test_durable_job_dedupe_claim_retry_recovery_and_independent_heartbeat(monkeypatch):
    init_db()
    with SessionLocal() as db:
        s=Source(name='durable-job',kind='tcp_discovery',config={});db.add(s);db.commit()
        job=jobs.enqueue(db,'collection',s.id)
        assert jobs.enqueue(db,'collection',s.id).id==job.id
        claimed=jobs.claim(db)
        assert claimed.id==job.id and claimed.status=='running'
        assert jobs.claim(db) is None
        worker=jobs.Worker(threading.Event());worker.current=job.id
        before=claimed.heartbeat
        worker.pulse();db.expire_all()
        assert db.get(BackgroundJob,job.id).heartbeat>=before
        claimed=db.get(BackgroundJob,job.id)
        claimed.heartbeat=now()-timedelta(seconds=100);db.commit()
        jobs.recover(db);db.refresh(claimed)
        assert claimed.status=='queued'
        claimed=jobs.claim(db)
        def fail(*a,**k):raise RuntimeError('fixture failure')
        monkeypatch.setattr(collector,'run_collection',fail)
        jobs.execute(db,claimed);db.refresh(claimed)
        assert claimed.status=='queued' and claimed.error
        claimed.available_at=now();db.commit();claimed=jobs.claim(db)
        jobs.execute(db,claimed);db.refresh(claimed)
        assert claimed.status=='failed' and claimed.active_key is None


def test_idempotent_file_import_and_archive_round_trip(monkeypatch,tmp_path):
    init_db()
    monkeypatch.setattr(settings,'data_dir',str(tmp_path))
    with SessionLocal() as db:
        s=Source(name='idempotent-source',kind='generic_json',verified=True);db.add(s);db.commit()
        content='[{"identifiers":{"device_id":"repeat-one"},"attributes":{"name":"repeat-one"}}]'
        first=collector.run_import(db,s.id,content,'scan.json')
        n=db.query(Observation).count()
        second=collector.run_import(db,s.id,content,'renamed.json')
        assert first.id==second.id and db.query(Observation).count()==n
        obs=db.query(Observation).filter_by(source_id=s.id).first();raw=obs.raw
        obs.collected_at=now()-timedelta(days=100);db.commit()
        assert retention.archive(db)['archived']>=1
        assert obs.raw is None and retention.read_raw(obs)==raw
        assert retention.archive(db)['archived']==0
        archive=tmp_path/obs.raw_ref
        archive.write_bytes(b'corrupt')
        with pytest.raises((ValueError,OSError,EOFError)):retention.read_raw(obs)


def test_existing_database_migration_preserves_rows_and_adds_blocks(tmp_path):
    e=create_engine('sqlite:///'+str(tmp_path/'legacy.db'))
    # Legacy tables have the same columns; newer tables start absent.
    for name in ('assets','asset_identifiers'):Base.metadata.tables[name].create(e)
    with Session(e) as db:
        a=Asset(name='legacy-device');db.add(a);db.flush()
        db.add(AssetIdentifier(asset_id=a.id,kind='hostname',value='legacy-device.old.example'));db.commit();aid=a.id
    upgrade(e);upgrade(e)
    with Session(e) as db:
        assert db.query(Asset).one().name=='legacy-device'
        assert db.query(AssetIdentifier).count()==1 and db.query(SchemaVersion).count()==2
        assert find_candidates(db,{'hostname':['legacy-device.new.example']})=={aid}


def test_limiter_evicts_and_bad_encryption_key_is_distinct(monkeypatch):
    tick=[100.0];monkeypatch.setattr('app.security.time.monotonic',lambda:tick[0])
    limiter=RateLimiter()
    assert limiter.allow('old',1) and not limiter.allow('old',1)
    tick[0]=200
    assert limiter.allow('new',1) and 'old' not in limiter.hits
    assert decrypt_secrets(encrypt_secrets({'a':'b'}))=={'a':'b'}
    with pytest.raises(SecretDecryptionError):decrypt_secrets('not-encrypted-with-this-key')


def test_tcp_cidr_restriction_and_health(monkeypatch):
    from app.connectors import REGISTRY,ConnectorError
    monkeypatch.setattr(settings,'tcp_allowed_cidrs',['192.0.2.0/24'])
    assert REGISTRY['tcp_discovery']._targets({'authorized':True,'targets':['192.0.2.7']})[0]==['192.0.2.7']
    with pytest.raises(ConnectorError):REGISTRY['tcp_discovery']._targets({'authorized':True,'targets':['198.51.100.1']})
    init_db()
    with SessionLocal() as db:
        assert health(db)['database']=='ok'
        monkeypatch.setattr(settings,'scheduler_enabled',True)
        row=db.get(Setting,'scheduler_heartbeat')
        if row:row.value=(now()-timedelta(hours=1)).isoformat()
        else:db.add(Setting(key='scheduler_heartbeat',value=(now()-timedelta(hours=1)).isoformat()))
        db.flush()
        assert health(db)['status']=='degraded'
        assert 'deepsight_jobs{status="failed"}' in prometheus(db)
        db.rollback()


def test_backup_restore_checks_data_and_rejects_nonempty_target(tmp_path):
    spec=importlib.util.spec_from_file_location('deepsight_backup','scripts/backup.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    source=create_engine('sqlite:///'+str(tmp_path/'source.db'));Base.metadata.create_all(source)
    with Session(source) as db:db.add(Asset(name='restore-marker',config={'nested':[1,2]}));db.commit()
    backup=tmp_path/'snapshot.json';mod.dump(source,backup)
    target=create_engine('sqlite:///'+str(tmp_path/'target.db'))
    result=mod.restore(backup,target)
    assert result['verified'] and result['rows']==1
    with pytest.raises(ValueError):mod.restore(backup,target)


def test_offline_swagger_assets():
    html=Path('app/static/docs.html').read_text()
    assert 'https://' not in html
    assert Path('app/static/vendor/swagger-ui-bundle.js').stat().st_size>100000
    assert Path('app/static/vendor/swagger-ui.css').stat().st_size>10000


from app.util import now
