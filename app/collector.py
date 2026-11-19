"""Runs collections/imports for an integration, tracks status and history."""
import hashlib
import logging
import os
import re
import threading

from sqlalchemy.orm import Session

from . import pipeline
from .config import settings
from .connectors import REGISTRY, ConnectorError
from .models import CollectionRun, Source, Setting
from .security import audit, decrypt_secrets
from .util import now

log = logging.getLogger("asivm.collector")


def _finish(db, run, src, status, counts=None, error=None):
    run.finished, run.status, run.error = now(), status, error
    if counts:
        run.received = counts.get("received", 0)
        run.processed = counts.get("processed", 0) + counts.get("unresolved", 0)
        run.duplicates = counts.get("duplicates", 0)
        run.rejected = counts.get("rejected", 0) + counts.get("stale", 0)
        run.failed = counts.get("failed", 0)
        run.summary = counts
    src.last_attempt = run.finished
    if status == "ok":
        src.last_success, src.status, src.last_error, src.auth_status = run.finished, "ok", None, "ok"
    else:
        src.status, src.last_error = "error", error
        if error and "authentication" in error:
            src.auth_status = "failed"
    db.commit()


def run_collection(db: Session, source_id: int, trigger="manual", user="system"):
    src = db.get(Source, source_id)
    if not src:
        raise ConnectorError("integration not found")
    conn = REGISTRY.get(src.kind)
    if not conn:
        raise ConnectorError(f"unknown connector kind {src.kind}")
    if src.status == "running":
        raise ConnectorError("a collection is already running for this integration")
    run = CollectionRun(source_id=src.id, trigger=trigger)
    db.add(run)
    src.status, src.last_attempt = "running", now()
    db.commit()
    try:
        raws = conn.collect(src.config or {}, decrypt_secrets(src.secrets_enc))
        counts = pipeline.ingest(db, src, raws)["counts"]
        _finish(db, run, src, "ok" if counts.get("failed", 0) == 0 else "partial", counts)
        if run.status == "partial":
            src.status = "error"
            src.last_error = f"{counts['failed']} observation(s) failed processing"
            db.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("collection failed for %s: %s", src.name, e)
        db.rollback()
        src = db.get(Source, source_id)
        run = db.get(CollectionRun, run.id)
        _finish(db, run, src, "error", error=f"{type(e).__name__}: {e}"[:1000])
    audit(db, user, "collection.run", f"source:{src.id}", {"trigger": trigger, "status": run.status})
    return run


def save_evidence(source_id: int, filename: str, content: str) -> str:
    d = os.path.join(settings.data_dir, "evidence", str(source_id))
    os.makedirs(d, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", filename or "upload")[:80]
    h = hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest()[:10]
    path = os.path.join(d, f"{now().strftime('%Y%m%dT%H%M%S')}-{h}-{safe}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return os.path.relpath(path, settings.data_dir)


def _run_import(db: Session, source_id: int, content: str, filename: str, user="system"):
    src = db.get(Source, source_id)
    conn = REGISTRY.get(src.kind) if src else None
    if not conn or not conn.accepts_upload:
        raise ConnectorError("this integration does not accept file imports")
    run = CollectionRun(source_id=src.id, trigger="import")
    db.add(run)
    src.last_attempt = now()
    db.commit()
    try:
        ref = save_evidence(src.id, filename, content)
        raws = conn.parse(content, filename, src.config or {})
        for r in raws:
            r.pop("_launch", None)
        counts = pipeline.ingest(db, src, raws, raw_ref=ref)["counts"]
        _finish(db, run, src, "ok" if counts.get("failed", 0) == 0 else "partial", counts)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        src = db.get(Source, source_id)
        run = db.get(CollectionRun, run.id)
        _finish(db, run, src, "error", error=f"{type(e).__name__}: {e}"[:1000])
    audit(db, user, "integration.import", f"source:{src.id}", {"file": filename, "status": run.status})
    return run


_import_lock = threading.RLock()


def run_import(db: Session, source_id: int, content: str, filename: str, user="system"):
    digest = hashlib.sha256(f"{source_id}:".encode() + content.encode()).hexdigest()
    key = "import:" + digest[:56]
    with _import_lock:
        receipt = db.get(Setting, key)
        if receipt:
            previous = db.get(CollectionRun, receipt.value["run_id"])
            if previous and previous.status == "ok": return previous
        run = _run_import(db, source_id, content, filename, user)
        if run.status == "ok":
            if receipt: receipt.value = {"run_id": run.id, "sha256": digest}
            else: db.add(Setting(key=key, value={"run_id":run.id,"sha256":digest}))
            db.commit()
        return run
