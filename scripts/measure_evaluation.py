#!/usr/bin/env python3
"""Reproduce independent fixture results and a clearly labelled feedback sensitivity exercise."""
import json
import os
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory(prefix='deepsight-evaluation-') as d:
    os.environ.update(ASIVM_DATA_DIR=d,ASIVM_DATABASE_URL='sqlite:///'+d+'/eval.db',ASIVM_WORKER='false',ASIVM_SCHEDULER='false')
    from app.main import init_db
    from app.db import SessionLocal
    from app.models import Asset,Anomaly
    from app.engines import ml
    from app.evaluation import evaluate
    init_db()
    with SessionLocal() as db:
        before=evaluate(db)
        asset=Asset(name='controlled-feedback-fixture');db.add(asset);db.flush()
        db.add(Anomaly(asset_id=asset.id,status='false_positive',reviewer='QA fixture (simulated analyst)',features=dict(zip(ml.ANOM_FEATURES,[8,5,1,1,1,2,4,0,1,15,1,1,15]))));db.commit()
        after=evaluate(db)
        print(json.dumps({'independent':before,'with_simulated_feedback':after,'limitation':'Feedback sensitivity uses one simulated false-positive review, not customer analyst outcomes. No retraining or measured production improvement.'},indent=2))
