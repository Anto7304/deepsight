"""Archive raw evidence after the configured hot retention window; retain normalized history."""
import gzip
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from .config import settings
from .models import Observation
from .util import now


def archive(db):
    rows=db.query(Observation).filter(Observation.collected_at<now()-timedelta(days=settings.raw_retention_days)).all()
    count=0
    directory=Path(settings.data_dir)/'archive';directory.mkdir(parents=True,exist_ok=True)
    for o in rows:
        if o.raw is None:continue
        blob=json.dumps({'observation_id':o.id,'original_ref':o.raw_ref,'raw':o.raw},sort_keys=True,default=str).encode()
        digest=hashlib.sha256(blob).hexdigest()
        target=directory/(digest+'.json.gz')
        if not target.exists():
            temp=target.with_suffix('.tmp')
            with gzip.open(temp,'wb') as f:f.write(blob)
            temp.replace(target)
        o.raw_ref='archive/'+target.name;o.raw=None;count+=1
    db.commit()
    return {'archived':count,'raw_retention_days':settings.raw_retention_days,'normalized_history':'retained'}


def read_raw(o):
    if o.raw is not None:return o.raw
    if not o.raw_ref or not o.raw_ref.startswith('archive/'):return None
    root=(Path(settings.data_dir)/'archive').resolve();p=(Path(settings.data_dir)/o.raw_ref).resolve()
    if p.parent!=root:raise ValueError('Invalid evidence reference')
    with gzip.open(p,'rb') as f:blob=f.read()
    if hashlib.sha256(blob).hexdigest()!=p.name.split('.')[0]:raise ValueError('Evidence integrity check failed')
    return json.loads(blob)['raw']
