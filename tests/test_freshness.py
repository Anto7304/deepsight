from datetime import timedelta
from app.db import SessionLocal
from app.main import init_db
from app.models import Asset, Observation, Source, Setting
from app.freshness import summaries
from app.util import now


def test_assessment_and_coverage_are_independent():
    init_db()
    with SessionLocal() as db:
        a = Asset(name='freshness-case', config={})
        s = Source(name='freshness-source', kind='manual')
        t = Source(name='freshness-expected', kind='manual')
        db.add_all([a, s, t]); db.flush()
        a.config = {'expected_source_ids': [s.id, t.id]}
        o = Observation(asset_id=a.id, source_id=s.id, observed_at=now(), status='processed', attributes={'os': 'Linux'})
        db.add(o); db.flush()
        f = summaries(db, [a])[a.id]
        assert f['assessment_state'] == 'not_recently_assessed'
        assert f['last_successful_observation']
        assert f['expected_sources_missing'][0]['id'] == t.id
        o.attributes = {'os': 'Linux', 'findings': [], 'assessment': {'kind': 'vulnerability', 'complete': True, 'status': 'success'}}
        db.flush()
        assert summaries(db, [a])[a.id]['assessment_state'] == 'no_vulnerability_detected'
        db.add(Observation(asset_id=a.id, source_id=t.id, observed_at=now(), status='processed', attributes={'os': 'Windows'})); db.flush()
        f = summaries(db, [a])[a.id]
        assert f['conflicting_evidence'][0]['field'] == 'os'
        assert not f['expected_sources_missing']
        o.observed_at = now() - timedelta(hours=200); db.flush()
        assert summaries(db, [a])[a.id]['assessment_state'] == 'not_recently_assessed'
        db.rollback()


def test_partial_failed_future_and_unverified_scans_do_not_claim_clean():
    init_db()
    with SessionLocal() as db:
        a = Asset(name='not-assessed'); db.add(a); db.flush()
        o = Observation(asset_id=a.id, observed_at=now(), status='processed', attributes={'findings': [], 'assessment': {'kind': 'vulnerability', 'complete': False, 'status': 'success'}})
        db.add(o); db.flush()
        assert summaries(db, [a])[a.id]['assessment_state'] == 'not_recently_assessed'
        o.attributes = {'findings': [], 'assessment': {'kind': 'vulnerability', 'complete': True, 'status': 'success'}}
        for flag in ('future_timestamp_clamped', 'unverified_source', 'invalid_timestamp'):
            o.quality = {'flags': [flag]}; db.flush()
            assert summaries(db, [a])[a.id]['assessment_state'] == 'not_recently_assessed'
        db.rollback()
