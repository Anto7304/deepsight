"""Builds change-vectors from an observation's changes and scores them with the anomaly model."""
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import Anomaly, Asset, Change, EvalVector, Service
from ..normalize import ADMIN_PORTS, DB_PORTS
from ..util import now
from .ml import ANOM_FEATURES, anomaly_model

LEARNING = {"on": False}  # learning window: vectors are recorded as training data but no anomalies are raised
_SIGNIFICANT = {"service_added", "service_changed", "identifier_changed", "config_changed", "exposure_changed"}


def _port_freq(db: Session, port: int, asset_type: str):
    total = db.query(Asset).filter(Asset.type == asset_type, Asset.merged_into.is_(None)).count()
    if total == 0:
        return 0.0
    with_port = db.query(Service.asset_id).join(Asset, Asset.id == Service.asset_id).filter(
        Asset.type == asset_type, Service.port == port, Service.active.is_(True),
        Asset.merged_into.is_(None)).distinct().count()
    return with_port / total


def build_features(db: Session, asset: Asset, changes: list, ts):
    sig = [c for c in changes if c.kind in _SIGNIFICANT]
    if not sig:
        return None
    # a drift is rarely one observation: aggregate the asset's significant changes over the last 24h
    seen = {c.id for c in sig if c.id}
    for c in db.query(Change).filter(Change.asset_id == asset.id, Change.ts >= ts - timedelta(hours=24),
                                     Change.ts <= ts, Change.kind.in_(_SIGNIFICANT)).all():
        if c.id not in seen:
            sig.append(c)
    new_svc = [c for c in sig if c.kind == "service_added"]
    ports = [c.detail.get("port") for c in new_svc if c.detail.get("port")]
    rarity = 0.0
    for p in ports:
        # fleet frequency excluding this asset's own addition (smoothed)
        freq = max(0.0, _port_freq(db, p, asset.type) - 1.0 / max(1, db.query(Asset).filter(
            Asset.type == asset.type, Asset.merged_into.is_(None)).count()))
        rarity = max(rarity, 1.0 - freq)
    prev = db.query(Change).filter(Change.asset_id == asset.id, Change.ts < ts, Change.kind.in_(_SIGNIFICANT)).order_by(
        Change.ts.desc()).first()
    days = (ts - prev.ts).total_seconds() / 86400 if prev else 60
    c7 = db.query(Change).filter(Change.asset_id == asset.id, Change.ts >= ts - timedelta(days=7), Change.ts < ts,
                                 Change.kind.in_(_SIGNIFICANT)).count()
    svc_count = db.query(Service).filter(Service.asset_id == asset.id, Service.active.is_(True)).count()
    return {
        "n_new_services": float(len(new_svc)),
        "n_external_new": float(sum(1 for c in new_svc if c.detail.get("exposed"))),
        "max_port_rarity": round(rarity, 3),
        "admin_port": 1.0 if any(p in ADMIN_PORTS for p in ports) else 0.0,
        "db_port": 1.0 if any(p in DB_PORTS for p in ports) else 0.0,
        "n_ident_changes": float(sum(1 for c in sig if c.kind == "identifier_changed")),
        "n_config_changes": float(sum(1 for c in sig if c.kind in ("config_changed", "exposure_changed"))),
        "n_version_changes": float(sum(1 for c in sig if c.kind == "service_changed")),
        "criticality": (asset.criticality or 3) / 5.0,
        "changes_7d": float(min(20, c7)),
        "days_since_last_change": min(60.0, days) / 60.0,
        "off_hours": 1.0 if (ts.hour < 6 or ts.hour >= 22 or ts.weekday() >= 5) else 0.0,
        "service_count": float(min(40, svc_count)),
    }


def evaluate(db: Session, asset: Asset, changes: list, ts, obs_id: int):
    feats = build_features(db, asset, changes, ts)
    if feats is None:
        return None
    m = anomaly_model()
    score, contrib = m.score(feats)
    db.add(EvalVector(asset_id=asset.id, observation_id=obs_id, ts=ts, features=feats, score=score))
    thr = m.effective_threshold
    if LEARNING["on"] or score < thr:
        return None
    sig = [c.summary for c in changes if c.kind in _SIGNIFICANT][:3]
    prev = db.query(Anomaly).filter(Anomaly.asset_id == asset.id, Anomaly.status == "new",
                                    Anomaly.ts >= ts - timedelta(hours=24)).order_by(Anomaly.score.desc()).first()
    if prev:
        if score > prev.score:
            prev.score, prev.features, prev.contributors, prev.observation_id = round(score, 4), feats, contrib, obs_id
        return prev
    an = Anomaly(asset_id=asset.id, ts=ts, observation_id=obs_id, score=round(score, 4), threshold=round(thr, 4),
                 features=feats, contributors=contrib, model_version=m.version, status="new",
                 summary="Unusual change pattern: " + "; ".join(sig))
    db.add(an)
    db.flush()
    return an
