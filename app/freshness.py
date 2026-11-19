"""Observation coverage is separate from a successful vulnerability assessment."""
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import func

from .config import settings
from .models import Finding, Observation, Setting, Source
from .util import iso, now


def age_threshold(db):
    row = db.get(Setting, "assessment_age_hours")
    return float(row.value) if row else settings.assessment_age_hours


def complete_assessment(obs):
    a = (obs.attributes or {}).get("assessment")
    return (isinstance(a, dict) and a.get("kind") == "vulnerability"
            and a.get("status") == "success" and a.get("complete") is True
            and isinstance((obs.attributes or {}).get("findings"), list)
            and not any(str(f).startswith(("invalid_", "future_", "unverified_"))
                        for f in (obs.quality or {}).get("flags", [])))


def summaries(db, assets):
    if not assets:
        return {}
    ids = [a.id for a in assets]
    cutoff = now() - timedelta(hours=age_threshold(db))
    sources = {s.id: s for s in db.query(Source).all()}
    # Windowed latest evidence per source; no pairwise asset comparisons.
    ranked = db.query(Observation.id.label("id"), func.row_number().over(
        partition_by=(Observation.asset_id, Observation.source_id),
        order_by=(Observation.observed_at.desc(), Observation.id.desc())).label("rn")).filter(
            Observation.asset_id.in_(ids), Observation.status.in_(["processed", "unresolved"]),
            Observation.attributes["reachable"].as_boolean().is_not(False)).subquery()
    latest = defaultdict(list)
    for o in db.query(Observation).join(ranked, ranked.c.id == Observation.id).filter(ranked.c.rn == 1):
        if o.attributes.get("reachable") is not False:
            latest[o.asset_id].append(o)
    assessments = {}
    # A newer inventory-only record must not erase an earlier assessment.
    for o in db.query(Observation).filter(Observation.asset_id.in_(ids),
            Observation.status.in_(["processed", "unresolved"])).order_by(
                Observation.observed_at.desc(), Observation.id.desc()):
        if o.asset_id not in assessments and complete_assessment(o):
            assessments[o.asset_id] = o
    open_counts = dict(db.query(Finding.asset_id, func.count(Finding.id)).filter(
        Finding.asset_id.in_(ids), Finding.status == "open").group_by(Finding.asset_id))
    result = {}
    for a in assets:
        obs = latest[a.id]
        seen = {o.source_id for o in obs}
        expected = set((a.config or {}).get("expected_source_ids", []))
        expected.update(s.id for s in sources.values() if a.id in (s.config or {}).get("expected_asset_ids", []))
        missing = expected - {o.source_id for o in obs if o.observed_at >= cutoff}
        conflicts = []
        for field in ("os", "owner", "exposure", "firmware_version"):
            evidence = [{"source_id": o.source_id, "observation_id": o.id, "value": o.attributes[field],
                         "observed_at": iso(o.observed_at)} for o in obs
                        if o.observed_at >= cutoff and o.attributes.get(field) is not None]
            if len({str(e["value"]) for e in evidence}) > 1:
                conflicts.append({"field": field, "evidence": evidence})
        assessed = assessments.get(a.id)
        state = "not_recently_assessed" if not assessed or assessed.observed_at < cutoff else (
            "findings_detected" if open_counts.get(a.id) else "no_vulnerability_detected")
        result[a.id] = {
            "last_successful_observation": iso(max((o.observed_at for o in obs), default=None)),
            "assessment_state": state, "assessment_age_hours": age_threshold(db),
            "last_successful_assessment": iso(assessed.observed_at) if assessed else None,
            "assessment_observation_id": assessed.id if assessed else None,
            "sources_seen": [{"id": o.source_id, "name": sources[o.source_id].name if o.source_id in sources else "Manual",
                              "observed_at": iso(o.observed_at), "observation_id": o.id,
                              "recent": o.observed_at >= cutoff} for o in obs],
            "expected_sources_missing": [{"id": sid, "name": sources[sid].name if sid in sources else "Unknown source",
                                          "ever_seen": sid in seen} for sid in sorted(missing)],
            "conflicting_evidence": conflicts,
            "limitation": "No vulnerability detected applies only to the recorded successful assessment scope; it is not proof of safety.",
        }
    return result
