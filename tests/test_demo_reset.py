from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app import demo
from app.db import Base
from app.models import Asset, Setting


def test_demo_reset_clears_data_but_keeps_liveness_heartbeats(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/reset.db")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Asset(name="reset-me"), Setting(key="worker_heartbeat", value="2026-11-15T00:00:00Z"),
                    Setting(key="scheduler_heartbeat", value="2026-11-15T00:00:00Z"), Setting(key="assessment_age_hours", value=24)])
        db.commit()
        demo.wipe(db)
        assert db.query(Asset).count() == 0
        assert {s.key for s in db.query(Setting)} == {"worker_heartbeat", "scheduler_heartbeat"}
