#!/usr/bin/env python3
"""Measure end-to-end ingestion and indexed identity candidates in an isolated temporary DB."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ap=argparse.ArgumentParser();ap.add_argument('--assets',type=int,required=True);args=ap.parse_args()
if args.assets<1:raise SystemExit('assets must be positive')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory(prefix='deepsight-load-') as directory:
    os.environ.update(ASIVM_DATA_DIR=directory,ASIVM_DATABASE_URL='sqlite:///'+directory+'/load.db',ASIVM_SCHEDULER='false',ASIVM_WORKER='false')
    from app.main import init_db
    from app.db import SessionLocal
    from app.models import Asset, Source
    from app import pipeline
    from app.engines import identity, ml
    init_db();ml.entity_model();ml.anomaly_model()
    with SessionLocal() as db:
        source=Source(name='synthetic-load',kind='generic_json');db.add(source);db.commit()
        raws=[{'identifiers':{'device_id':[f'load-device-{i}'],'hostname':[f'load-{i}.bench.example']},'attributes':{'type':'server','owner':'Synthetic benchmark'},'observed_at':'2026-11-15T00:00:00Z'} for i in range(args.assets)]
        # Current timestamp keeps the test valid on future dates.
        from app.util import iso,now
        for raw in raws:raw['observed_at']=iso(now())
        begin=time.perf_counter();result=pipeline.ingest(db,source,raws);duration=time.perf_counter()-begin
        begin=time.perf_counter();counts=[len(identity.find_candidates(db,{'hostname':[f'load-{i}.other.example']})) for i in range(min(args.assets,1000))];lookup=time.perf_counter()-begin
        print(json.dumps({'assets_requested':args.assets,'assets_stored':db.query(Asset).count(),'seconds':round(duration,3),'observations_per_second':round(args.assets/duration,3),'counts':result['counts'],'candidate_queries':len(counts),'candidate_lookup_seconds':round(lookup,3),'max_candidates':max(counts),'limitation':'Local SQLite, single process, synthetic identities, no network collectors, no findings or graph edges; not production capacity.'}))
