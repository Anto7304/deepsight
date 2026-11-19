"""The continuous intelligence pipeline.

receive -> validate/normalize -> identity resolution -> state update (history) -> enrich
(vulnerability intelligence) -> anomaly analysis -> contextual risk -> available to UI/assistant.

Observations are persisted BEFORE processing so incoming information is never lost if processing
fails; failed observations can be re-processed safely (reprocess_failed).
"""
import hashlib
import json
import logging
import threading
import time
from collections import deque

from sqlalchemy.orm import Session

from .engines import anomaly as anomaly_engine
from .engines import identity, intel, risk, state, iot
from .models import Asset, AssetIdentifier, IdentityDecision, Observation, Source
from .normalize import STRONG_KINDS, _scrub, validate_observation
from .util import now

log = logging.getLogger("asivm.pipeline")
_lock = threading.RLock()
LATENCY = deque(maxlen=500)  # seconds per observation


def _hash(source_id, ids, attrs, observed_at):
    blob = json.dumps({"s": source_id, "i": ids, "a": attrs, "t": observed_at.isoformat()}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def receive(db: Session, source: Source | None, raws: list, raw_ref=None, commit=True):
    """Persist raw observations (status=received). Returns list[Observation]."""
    out = []
    verified = source.verified if source else True
    for raw in raws:
        if not isinstance(raw, dict):
            raw = {"identifiers": {}, "attributes": {"_unparsed": str(raw)[:500]}}
        if "\\u0000" in json.dumps(raw, default=str):  # PostgreSQL cannot store NUL characters
            raw = _scrub(raw)
        try:
            n = validate_observation(raw, verified)
        except Exception as e:  # noqa: BLE001 - never lose a batch over one malformed record
            log.warning("validation failed, keeping record as raw evidence: %s", e)
            ts = now()
            n = {"identifiers": {}, "attributes": {}, "observed_at": ts, "collected_at": ts, "category": "asset",
                 "flags": [f"validation_error:{type(e).__name__}"], "quality_score": 0.05, "stale": False}
            raw = {"identifiers": {}, "attributes": {"_unparsed": str(raw)[:500].replace("\x00", "")}}
        h = _hash(source.id if source else None, n["identifiers"], n["attributes"], n["observed_at"])
        obs = Observation(source_id=source.id if source else None, source_type=source.kind if source else "manual",
                          category=n["category"], identifiers=n["identifiers"], attributes=n["attributes"],
                          observed_at=n["observed_at"], collected_at=n["collected_at"], raw=raw,
                          raw_ref=(str(raw.get("raw_ref") or raw_ref or "")[:512].replace("\x00", "") or None), status="received",
                          quality={"flags": n["flags"], "stale": n["stale"]}, quality_score=n["quality_score"],
                          content_hash=h)
        db.add(obs)
        out.append(obs)
    db.flush()
    if commit:
        db.commit()
    return out


def _record_decision(db, obs, res, asset, status):
    d = IdentityDecision(observation_id=obs.id, asset_id=asset.id, candidate_asset_id=res.get("candidate_id"),
                         outcome=res["outcome"], status=status, confidence=res.get("confidence"),
                         evidence=res.get("evidence"), model_version=res.get("model_version"))
    db.add(d)
    return d


def process(db: Session, obs: Observation) -> dict:
    t0 = time.perf_counter()
    summary = {"observation_id": obs.id, "status": None}
    with _lock:
        try:
            flags = (obs.quality or {}).get("flags", [])
            # duplicate submission
            dup = db.query(Observation.id).filter(Observation.content_hash == obs.content_hash,
                                                  Observation.id != obs.id,
                                                  Observation.status.in_(["processed", "unresolved"])).first()
            if dup:
                obs.status, summary["status"] = "duplicate", "duplicate"
                obs.error = f"duplicate of observation {dup[0]}"
                db.commit()
                return summary
            ids = obs.identifiers or {}
            if not ids:
                obs.status, summary["status"] = "rejected", "rejected"
                obs.error = "no usable identifiers - retained as raw evidence only"
                db.commit()
                return summary
            if (obs.quality or {}).get("stale"):
                obs.status, summary["status"] = "stale", "stale"
                obs.error = "observation older than 30 days - stored but not applied to current state"
                db.commit()
                return summary
            norm = {"identifiers": ids, "attributes": obs.attributes or {}, "observed_at": obs.observed_at}
            osf = norm["attributes"].get("os_family")
            res = identity.resolve(db, ids, osf)

            if norm["attributes"].get("_only_if_known") and res["outcome"] != "confirmed":
                obs.status, summary["status"] = "rejected", "rejected"
                obs.error = "reachability-only observation for an unknown host - not creating an asset"
                db.commit()
                return summary
            is_new = False
            decision = None
            if res["outcome"] == "confirmed":
                asset = db.get(Asset, res["asset_id"])
                decision = _record_decision(db, obs, res, asset, "auto")
            else:
                is_new = True
                has_strong = any(k in ids for k in STRONG_KINDS)
                istatus = {"probable": "probable", "potentially_separate": "confirmed" if has_strong else "unresolved",
                           "unresolved": "unresolved", "new": "confirmed" if has_strong else "unresolved"}[res["outcome"]]
                conf = res["confidence"] if res["outcome"] == "probable" else (0.95 if has_strong else 0.4)
                asset = Asset(name=state.best_name(ids, norm["attributes"]), status="discovered",
                              identity_status=istatus, identity_confidence=conf, first_seen=obs.observed_at,
                              last_seen=obs.observed_at, os=norm["attributes"].get("os"), os_family=osf)
                db.add(asset)
                db.flush()
                if res["outcome"] in ("probable", "unresolved", "potentially_separate") and res.get("candidate_id"):
                    decision = _record_decision(db, obs, res, asset, "pending" if res["outcome"] == "probable" else "auto")
                elif res["outcome"] in ("new", "unresolved"):
                    decision = _record_decision(db, obs, {**res, "candidate_id": None}, asset, "auto")
            changes = state.apply_observation(db, asset, norm, obs.source_id, obs.id, is_new)
            identity.refresh_blocks(db, asset.id)
            # initial creation history
            if is_new:
                from .models import Change
                db.add(Change(asset_id=asset.id, ts=obs.observed_at, kind="asset_created",
                              summary=f"Asset discovered ({res['outcome']}; identity {asset.identity_status})",
                              detail={"observation": obs.id, "evidence": res.get("evidence")}, observation_id=obs.id))

            # enrichment
            new_findings = intel.apply_reported_findings(db, asset, norm["attributes"].get("findings"),
                                                         obs.source_id, obs.observed_at)
            new_findings += intel.match_asset(db, asset, obs.observed_at)
            new_findings += iot.detect(db, asset, norm["attributes"], obs.id, obs.observed_at)
            for f in new_findings:
                from .models import Change
                db.add(Change(asset_id=asset.id, ts=obs.observed_at, kind="finding_added",
                              summary=f"New finding {f.cve_id} ({f.basis})", detail={"cve": f.cve_id, "basis": f.basis,
                                                                                    "port": f.port}, observation_id=obs.id))
            db.flush()
            # anomaly analysis only for changes on pre-existing assets
            an = None if is_new else anomaly_engine.evaluate(db, asset, changes, obs.observed_at, obs.id)
            # Scanner evidence can upgrade or reopen an existing finding without
            # changing inventory or creating a new finding. Refresh its risk too.
            if changes or new_findings or norm["attributes"].get("findings") or is_new or an:
                risk.reassess_asset(db, asset.id, ts=obs.observed_at)
            from .notifications import enqueue_alerts
            enqueue_alerts(db, asset.id)
            obs.asset_id = asset.id
            obs.match_outcome = res["outcome"]
            obs.match_confidence = res.get("confidence")
            obs.status = "processed" if res["outcome"] in ("confirmed", "new") or (
                res["outcome"] == "potentially_separate") else "unresolved"
            obs.error = None
            db.commit()
            summary.update(status=obs.status, asset_id=asset.id, outcome=res["outcome"], changes=len(changes),
                           new_findings=len(new_findings), anomaly=an.id if an else None)
        except Exception as e:  # noqa: BLE001 - preserve the observation and record the failure
            db.rollback()
            log.exception("observation %s failed", obs.id)
            o = db.get(Observation, obs.id)
            if o:
                o.status, o.error = "failed", f"{type(e).__name__}: {e}"[:1000]
                db.commit()
            summary.update(status="failed", error=str(e))
    LATENCY.append(time.perf_counter() - t0)
    return summary


def ingest(db: Session, source: Source | None, raws: list, raw_ref=None) -> dict:
    obs_list = receive(db, source, raws, raw_ref)
    # process oldest-first so history is built chronologically
    obs_list.sort(key=lambda o: (o.observed_at, o.id))
    counts = {"received": len(obs_list), "processed": 0, "unresolved": 0, "duplicates": 0, "rejected": 0,
              "failed": 0, "stale": 0}
    results = []
    for o in obs_list:
        r = process(db, o)
        results.append(r)
        s = r["status"]
        key = {"duplicate": "duplicates"}.get(s, s)
        counts[key] = counts.get(key, 0) + 1
    return {"counts": counts, "results": results[:200]}


def reprocess_failed(db: Session, limit=500):
    n = ok = 0
    for o in db.query(Observation).filter(Observation.status == "failed").order_by(Observation.id).limit(limit).all():
        n += 1
        if process(db, o)["status"] != "failed":
            ok += 1
    return {"retried": n, "recovered": ok}
