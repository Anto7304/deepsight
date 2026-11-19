"""Risk Intelligence: contextual, explainable risk assessment.

The score is a transparent weighted logistic combination of context signals. It is NOT a
calibrated probability of compromise (no validated outcomes exist to calibrate against) and is
labelled as such. CVSS (published severity) is kept separate from the contextual score.
"""
import math
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import Anomaly, Asset, Change, Finding, RiskAssessment, Service, Vulnerability, Setting
from ..util import now
from .graph import blast_radius_norm, build_graph

VERSION = "deepsight-contextual-risk-1.1.0-heuristic"
BIAS = -3.6
WEIGHTS = {"cvss": 2.0, "kev": 1.4, "exploit": 0.8, "exposed": 2.0, "criticality": 0.8, "blast_radius": 0.6,
           "recent_change": 0.4, "anomaly": 0.6, "weakness": 2.0, "epss": 0.8}
LABELS = {"cvss": "Published severity (CVSS)", "kev": "Known exploited (CISA KEV)", "exploit": "Exploit available",
          "exposed": "Externally exposed", "criticality": "Asset criticality", "blast_radius": "Dependent systems (blast radius)",
          "recent_change": "Recent change on asset", "anomaly": "Unreviewed anomaly on asset", "weakness": "Configuration weakness (policy severity, not CVSS)", "epss": "FIRST EPSS (external ML prediction; not confirmed)"}


def level_for(score: float) -> str:
    return "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low"


def _sigmoid(z):
    return 1 / (1 + math.exp(-z))


def evidence_confidence(asset: Asset, finding: Finding | None, quality_hint=1.0):
    ident = asset.identity_confidence or 0.4
    basis = 1.0 if (finding and finding.basis == "observed") else 0.7
    seen = finding.last_seen if finding else asset.last_seen
    days = max(0.0, (now() - seen).total_seconds() / 86400) if seen else 30
    fresh = math.exp(-days / 30.0)
    conf = ident * basis * fresh * quality_hint
    parts = {"identity_confidence": round(ident, 2), "finding_basis": "observed by scanner" if basis == 1.0 else
             "inferred from version match", "freshness": round(fresh, 2)}
    return round(min(1.0, conf), 3), parts


def _context(db: Session, asset: Asset, g, anomaly_boost: float):
    recent = db.query(Change).filter(Change.asset_id == asset.id, Change.ts >= now() - timedelta(days=7),
                                     Change.kind.in_(["service_added", "service_changed", "exposure_changed",
                                                      "identifier_changed", "config_changed"])).count()
    return {"blast": blast_radius_norm(db, asset.id, g), "recent": 1.0 if recent else 0.0, "anomaly": anomaly_boost}


def _anomaly_boost(db: Session, asset_id: int):
    a = db.query(Anomaly).filter(Anomaly.asset_id == asset_id, Anomaly.status == "new",
                                 Anomaly.ts >= now() - timedelta(days=14)).order_by(Anomaly.score.desc()).first()
    if not a:
        return 0.0
    return min(1.0, max(0.0, (a.score - 0.5) / 0.4))


def score_finding(db: Session, asset: Asset, f: Finding, v: Vulnerability, ctx: dict):
    svc = db.get(Service, f.service_id) if f.service_id else None
    exposed = 1.0 if ((svc and svc.exposed) or (not svc and asset.exposure == "external")) else 0.0
    cvss = v.cvss if v.cvss is not None else (0.0 if (f.evidence or {}).get("kind") == "configuration" else 5.0)
    ep = db.get(Setting, "epss:" + f.cve_id)
    from ..util import parse_ts
    ep_recent = ep and parse_ts(ep.value["date"]) >= now() - timedelta(days=30)
    x = {"epss": float(ep.value["epss"]) if ep_recent else 0.0, "cvss": cvss / 10.0, "kev": 1.0 if v.kev else 0.0, "exploit": 1.0 if v.exploit_available else 0.0,
         "exposed": exposed, "criticality": (asset.criticality or 3) / 5.0, "blast_radius": ctx["blast"],
         "recent_change": ctx["recent"], "anomaly": ctx["anomaly"],
         "weakness": (f.evidence or {}).get("weakness_severity", 0.0)}
    z = BIAS + sum(WEIGHTS[k] * x[k] for k in WEIGHTS)
    score = round(100 * _sigmoid(z), 1)
    factors = [{"key": k, "label": LABELS[k], "value": round(x[k], 2),
                "contribution": round(WEIGHTS[k] * x[k], 2),
                **({"basis": "ML-predicted", "source": "FIRST EPSS", "date": ep.value["date"] if ep else None,
                    "available": bool(ep_recent), "limitation": "Missing or stale EPSS is not evidence of low exploitation likelihood."} if k == "epss" else {})} for k in WEIGHTS]
    factors.sort(key=lambda d: -d["contribution"])
    conf, conf_parts = evidence_confidence(asset, f)
    level = level_for(score)
    needs_verification = conf < 0.45
    return {"score": score, "level": "verify" if needs_verification else level, "underlying_level": level,
            "cvss": v.cvss, "factors": factors, "confidence": conf, "confidence_parts": conf_parts,
            "kev": v.kev, "exposed": bool(exposed), "needs_verification": needs_verification}


def suggested_action(f: Finding, v: Vulnerability, r: dict):
    acts = []
    if r["needs_verification"]:
        acts.append("Verify before prioritizing: confirm asset identity and the installed version "
                    "(authenticated scan / package inventory).")
    if v.kev and r["exposed"]:
        acts.append("Known-exploited and externally reachable: treat as urgent; review logs for exploitation indicators.")
    elif v.kev:
        acts.append("Known-exploited vulnerability on an internal asset: prioritize remediation and check exposure paths.")
    if v.remediation:
        acts.append(f"Remediation guidance: {v.remediation}")
    if f.basis == "inferred":
        acts.append("This finding is inferred from product/version matching and is not a confirmed exploitable condition.")
    return acts


def reassess_asset(db: Session, asset_id: int, force=False, g=None, ts=None):
    asset = db.get(Asset, asset_id)
    if not asset or asset.merged_into:
        return None
    g = g or build_graph(db)
    boost = _anomaly_boost(db, asset_id)
    ctx = _context(db, asset, g, boost)
    findings = db.query(Finding).filter(Finding.asset_id == asset_id, Finding.status == "open").all()
    vmap = {v.cve_id: v for v in db.query(Vulnerability).filter(
        Vulnerability.cve_id.in_({f.cve_id for f in findings} or {""})).all()}
    results = []
    t = ts or now()
    for f in findings:
        v = vmap.get(f.cve_id)
        if not v:
            continue
        r = score_finding(db, asset, f, v, ctx)
        results.append((f, r))
        last = db.query(RiskAssessment).filter(RiskAssessment.asset_id == asset_id,
                                               RiskAssessment.finding_id == f.id).order_by(RiskAssessment.id.desc()).first()
        changed = ((not last) or abs(last.score - r["score"]) >= 1.0 or last.level != r["level"]
                   or abs((last.confidence or 0) - r["confidence"]) >= 0.001)
        if changed or force or (t - last.ts) > timedelta(hours=24):
            db.add(RiskAssessment(asset_id=asset_id, finding_id=f.id, ts=t, score=r["score"], level=r["level"],
                                  cvss=r["cvss"], factors=r["factors"], confidence=r["confidence"], version=VERSION,
                                  evidence={"cve": f.cve_id, "basis": f.basis, "confidence_parts": r["confidence_parts"]},
                                  summary=f"{f.cve_id}: contextual {r['score']:.0f} ({r['level']}), CVSS {r['cvss']}"))
    # asset-level aggregate
    scored = sorted((r["score"] for _, r in results), reverse=True)
    if scored:
        agg = min(100.0, scored[0] + 0.15 * sum(scored[1:5]))
        top_f, top_r = max(results, key=lambda fr: fr[1]["score"])
        confs = [r["confidence"] for _, r in results]
        conf = round(max(confs), 3)
        level = level_for(agg)
        if all(r["needs_verification"] for _, r in results):
            level = "verify"
        factors = top_r["factors"]
        summary = (f"{len(results)} open finding(s); driven by {top_f.cve_id} "
                   f"(CVSS {top_r['cvss']}, contextual {top_r['score']:.0f})")
        evidence = {"driving_finding": top_f.id, "open_findings": len(results)}
    else:
        base = 15.0 + 25.0 * boost
        agg, conf, level = round(base, 1), round(asset.identity_confidence or 0.4, 3), level_for(base)
        factors = [{"key": "anomaly", "label": LABELS["anomaly"], "value": round(boost, 2),
                    "contribution": round(WEIGHTS["anomaly"] * boost, 2)}]
        summary = "No open findings; baseline risk" + (" raised by an unreviewed anomaly" if boost else "")
        evidence = {"open_findings": 0}
    agg = round(agg, 1)
    last = db.query(RiskAssessment).filter(RiskAssessment.asset_id == asset_id,
                                           RiskAssessment.finding_id.is_(None)).order_by(RiskAssessment.id.desc()).first()
    if ((not last) or abs(last.score - agg) >= 1.0 or last.level != level
            or abs((last.confidence or 0) - conf) >= 0.001 or force or (t - last.ts) > timedelta(hours=24)):
        db.add(RiskAssessment(asset_id=asset_id, finding_id=None, ts=t, score=agg, level=level,
                              cvss=max([r["cvss"] or 0 for _, r in results], default=None), factors=factors,
                              confidence=conf, version=VERSION, evidence=evidence, summary=summary))
        if last and last.level != level or (last and abs(last.score - agg) >= 10):
            db.add(Change(asset_id=asset_id, ts=t, kind="risk_changed",
                          summary=f"Contextual risk {last.score:.0f} ({last.level}) -> {agg:.0f} ({level})",
                          detail={"from": last.score, "to": agg, "from_level": last.level, "to_level": level}))
    asset.risk_score, asset.risk_level, asset.risk_confidence = agg, level, conf
    db.flush()
    return {"score": agg, "level": level, "confidence": conf}


def reassess_all(db: Session, force=False):
    g = build_graph(db)
    n = 0
    for (aid,) in db.query(Asset.id).filter(Asset.merged_into.is_(None)).all():
        reassess_asset(db, aid, force=force, g=g)
        n += 1
    db.commit()
    return n
