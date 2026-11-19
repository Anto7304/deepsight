"""Durable single-worker queue. Independent heartbeat continues during long collections."""
import logging
import threading
from datetime import timedelta
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from .config import settings
from .db import SessionLocal
from .models import BackgroundJob, Setting, Source, CollectionRun
from .util import iso, now

log=logging.getLogger('deepsight.jobs')


def enqueue(db,kind,source_id=None,user='system'):
    key=f'{kind}:{source_id or 0}'
    existing=db.query(BackgroundJob).filter(BackgroundJob.active_key==key).first()
    if existing:return existing
    job=BackgroundJob(kind=kind,source_id=source_id,active_key=key,requested_by=user)
    try:
        with db.begin_nested():
            db.add(job);db.flush()
    except IntegrityError:
        return db.query(BackgroundJob).filter(BackgroundJob.active_key==key).one()
    if source_id:
        src=db.get(Source,source_id)
        if src:src.status='queued'
    db.commit()
    return job


def recover(db):
    stale=now()-timedelta(seconds=90)
    for job in db.query(BackgroundJob).filter(BackgroundJob.status=='running',BackgroundJob.heartbeat<stale):
        job.status='queued' if job.attempts<3 else 'failed'
        job.error='Worker heartbeat expired; retrying durable job' if job.attempts<3 else 'Worker retry limit exhausted'
        if job.status=='failed':job.active_key=None
        src=db.get(Source,job.source_id) if job.source_id else None
        if src:src.status='error'
        for run in db.query(CollectionRun).filter(CollectionRun.source_id==job.source_id,CollectionRun.status=='running'):
            run.status='error';run.finished=now();run.error='Interrupted worker; durable retry scheduled'
    db.commit()


def claim(db):
    job=db.query(BackgroundJob).filter(BackgroundJob.status=='queued',BackgroundJob.available_at<=now()).order_by(BackgroundJob.id).first()
    if not job:return None
    result=db.execute(update(BackgroundJob).where(BackgroundJob.id==job.id,BackgroundJob.status=='queued').values(status='running',heartbeat=now(),attempts=BackgroundJob.attempts+1))
    db.commit()
    if not result.rowcount:return None
    db.refresh(job)
    return job


def execute(db,job):
    from . import collector, notifications, retention
    from .engines import intel, state
    try:
        if job.kind=='collection':
            run=collector.run_collection(db,job.source_id,trigger='background',user=job.requested_by)
            if run.status!='ok':raise RuntimeError(run.error or f'Collection {run.status}')
            result={'run_id':run.id,'processed':run.processed}
        elif job.kind=='maintenance':
            result={'lifecycle':state.lifecycle_sweep(db,settings.inactive_after_hours),'retention':retention.archive(db)}
        elif job.kind=='webhooks':result=notifications.dispatch(db)
        elif job.kind=='kev':result=intel.sync_kev(db)
        else:raise ValueError('Unknown job kind')
        job.status='completed';job.result=result;job.active_key=None;job.finished_at=now();job.error=None
    except Exception as exc:
        db.rollback();job=db.get(BackgroundJob,job.id)
        job.error=f'{type(exc).__name__}: {exc}'[:1000]
        job.status='queued' if job.attempts<3 else 'failed'
        job.available_at=now()+timedelta(seconds=30*2**job.attempts)
        if job.status=='failed':job.active_key=None;job.finished_at=now()
        log.warning('job failed: id=%s kind=%s attempt=%s error=%s',job.id,job.kind,job.attempts,job.error)
    db.commit()


class Worker:
    def __init__(self,stop):self.stop=stop;self.current=None
    def pulse(self):
        with SessionLocal() as db:
            row=db.get(Setting,'worker_heartbeat')
            if row:row.value=iso(now())
            else:db.add(Setting(key='worker_heartbeat',value=iso(now())))
            if self.current:
                db.execute(update(BackgroundJob).where(BackgroundJob.id==self.current,BackgroundJob.status=='running').values(heartbeat=now()))
            db.commit()
    def heartbeat_loop(self):
        while not self.stop.is_set():
            try:self.pulse()
            except Exception:log.exception('worker heartbeat failed')
            self.stop.wait(5)
    def run(self):
        threading.Thread(target=self.heartbeat_loop,daemon=True,name='collection-heartbeat').start()
        while not self.stop.is_set():
            try:
                with SessionLocal() as db:
                    recover(db);job=claim(db)
                    if job:
                        self.current=job.id
                        try:execute(db,job)
                        finally:self.current=None
            except Exception:log.exception('worker loop failed')
            self.stop.wait(1)
