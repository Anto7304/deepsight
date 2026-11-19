#!/usr/bin/env python3
"""Record independent model evaluations in the configured database."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.main import init_db
from app.db import SessionLocal
from app.evaluation import evaluate
init_db()
with SessionLocal() as db:print(json.dumps(evaluate(db),indent=2))
