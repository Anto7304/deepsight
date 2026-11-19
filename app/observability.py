"""Health and metrics use database state, not the scheduler's last completed job."""
import json
import logging
from sqlalchemy import text
from .config import settings
from .models import BackgroundJob, CollectionRun, Observation, Setting
from .util import iso, now, parse_ts


class JsonFormatter(logging.Formatter):
    def format(self,record):
        return json.dumps({'time':iso(now()),'level':record.levelname,'logger':record.name,'message':record.getMessage(),
                           **({'exception':self.formatException(record.exc_info)} if record.exc_info else {})})


def health(db):
    try:db.execute(text('SELECT 1'))
    except Exception:return {'status':'degraded','database':'unavailable'}
    result={'status':'ok','database':'ok','time':iso(now())}
    for key,enabled in [('scheduler',settings.scheduler_enabled),('worker',settings.worker_enabled)]:
        row=db.get(Setting,key+'_heartbeat')
        age=(now()-parse_ts(row.value)).total_seconds() if row and row.value else None
        state='disabled' if not enabled else ('alive' if age is not None and age<60 else 'stale')
        result[key]={'status':state,'heartbeat_age_seconds':age}
        if state=='stale':result['status']='degraded'
    last=db.query(CollectionRun).order_by(CollectionRun.id.desc()).first()
    result['last_collection']={'id':last.id,'status':last.status,'started':iso(last.started),'finished':iso(last.finished)} if last else None
    result['queued_jobs']=db.query(BackgroundJob).filter(BackgroundJob.status=='queued').count()
    return result


def prometheus(db):
    lines=['# HELP deepsight_database_up Database query succeeded','# TYPE deepsight_database_up gauge','deepsight_database_up 1']
    for status in ('queued','running','completed','failed'):
        n=db.query(BackgroundJob).filter(BackgroundJob.status==status).count()
        lines.append(f'deepsight_jobs{{status="{status}"}} {n}')
    for status in ('processed','unresolved','failed','rejected','duplicate'):
        n=db.query(Observation).filter(Observation.status==status).count()
        lines.append(f'deepsight_observations{{status="{status}"}} {n}')
    return '\n'.join(lines)+'\n'
