"""Read-side services: serializers, overview metrics, reports, investigation timelines."""
import csv
import html
import io
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from .engines import graph as graph_engine
from .engines import risk
from . import freshness, remediation
from .models import (Anomaly, Asset, AssetIdentifier, Change, Finding, IdentityDecision, Investigation, Observation,
                     RiskAssessment, Service, Software, Source, Vulnerability)
from .util import iso, now

LIVE = Asset.merged_into.is_(None)


def live_assets(db: Session):
    return db.query(Asset).filter(LIVE)


# ------------------------------------------------------------------ serializers
def asset_rows(db: Session, assets):
    fresh = freshness.summaries(db, assets)
    ids = [a.id for a in assets]
    ips, nfind = {}, {}
    if ids:
        for aid, v in db.query(AssetIdentifier.asset_id, AssetIdentifier.value).filter(
                AssetIdentifier.asset_id.in_(ids), AssetIdentifier.kind == "ip", AssetIdentifier.active.is_(True)):
            ips.setdefault(aid, []).append(v)
        for aid, n in db.query(Finding.asset_id, func.count(Finding.id)).filter(
                Finding.asset_id.in_(ids), Finding.status == "open").group_by(Finding.asset_id):
            nfind[aid] = n
    return [{"id": a.id, "name": a.name, "type": a.type, "status": a.status, "identity_status": a.identity_status,
             "identity_confidence": a.identity_confidence, "criticality": a.criticality, "owner": a.owner, "os": a.os,
             "exposure": a.exposure, "primary_identifier": a.primary_identifier, "ips": sorted(ips.get(a.id, [])),
             "open_findings": nfind.get(a.id, 0), "risk_score": a.risk_score, "risk_level": a.risk_level,
             "risk_confidence": a.risk_confidence, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
             "tags": a.tags or [], "freshness": fresh[a.id]} for a in assets]


def latest_assessments(db: Session, finding_ids):
    if not finding_ids:
        return {}
    sub = db.query(func.max(RiskAssessment.id)).filter(RiskAssessment.finding_id.in_(finding_ids)).group_by(
        RiskAssessment.finding_id)
    return {r.finding_id: r for r in db.query(RiskAssessment).filter(RiskAssessment.id.in_(sub))}


def triage_of(f: Finding):
    return remediation.workflow(f)


def finding_rows(db: Session, rows):
    """rows: [(Finding, Vulnerability, Asset)]"""
    ras = latest_assessments(db, [f.id for f, _, _ in rows])
    inv = {}
    for i in db.query(Investigation).filter(Investigation.status != "closed"):
        for fid in i.finding_ids or []:
            inv.setdefault(fid, []).append(i.id)
    fresh = freshness.summaries(db, list({a.id: a for _, _, a in rows}.values()))
    out = []
    for f, v, a in rows:
        ra = ras.get(f.id)
        tri = triage_of(f)
        out.append({"id": f.id, "asset_id": a.id, "asset": a.name, "asset_criticality": a.criticality,
                    "exposure": a.exposure, "cve": v.cve_id, "code": v.cve_id,
                    "kind": "cve" if v.cve_id.startswith("CVE-") else "configuration", "title": (v.description or "")[:140], "cvss": v.cvss,
                    "severity": v.severity, "kev": v.kev, "exploit_available": v.exploit_available, "basis": f.basis,
                    "port": f.port, "status": f.status, "contextual_score": ra.score if ra else None,
                    "contextual_level": ra.level if ra else None, "confidence": ra.confidence if ra else None,
                    "first_seen": iso(f.first_seen), "last_seen": iso(f.last_seen),
                    "investigation_status": "investigating" if f.id in inv else tri.get("state", "new"),
                    "investigations": inv.get(f.id, []), "freshness": fresh[a.id],
                    "workflow": remediation.workflow(f), "remediation_status": remediation.workflow(f)["state"]})
    return out


def asset_detail(db: Session, a: Asset):
    from .engines import ml  # noqa: F401  (ensures models are loaded lazily elsewhere)
    srcs = {s.id: s.name for s in db.query(Source)}
    base = asset_rows(db, [a])[0]
    idents = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == a.id).order_by(
        AssetIdentifier.kind, AssetIdentifier.active.desc()).all()
    svcs = db.query(Service).filter(Service.asset_id == a.id).order_by(Service.active.desc(), Service.port).all()
    sw = db.query(Software).filter(Software.asset_id == a.id).order_by(Software.active.desc(), Software.product).all()
    frows = db.query(Finding, Vulnerability, Asset).join(Vulnerability, Vulnerability.cve_id == Finding.cve_id).join(
        Asset, Asset.id == Finding.asset_id).filter(Finding.asset_id == a.id).order_by(Finding.status, Finding.id.desc()).all()
    changes = db.query(Change).filter(Change.asset_id == a.id).order_by(Change.ts.desc(), Change.id.desc()).limit(150).all()
    obs = db.query(Observation).filter(Observation.asset_id == a.id).order_by(Observation.observed_at.desc()).limit(30).all()
    ras = db.query(RiskAssessment).filter(RiskAssessment.asset_id == a.id, RiskAssessment.finding_id.is_(None)).order_by(
        RiskAssessment.ts.desc()).limit(30).all()
    decisions = db.query(IdentityDecision).filter(
        (IdentityDecision.asset_id == a.id) | (IdentityDecision.candidate_asset_id == a.id)).order_by(
        IdentityDecision.id.desc()).limit(20).all()
    anoms = db.query(Anomaly).filter(Anomaly.asset_id == a.id).order_by(Anomaly.ts.desc()).limit(10).all()
    return {**base, "config": a.config or {}, "merged_into": a.merged_into,
            "identifiers": [{"kind": i.kind, "value": i.value, "active": i.active, "source": srcs.get(i.source_id),
                             "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen)} for i in idents],
            "services": [{"id": s.id, "port": s.port, "proto": s.proto, "name": s.name, "product": s.product,
                          "version": s.version, "exposed": s.exposed, "active": s.active, "source": srcs.get(s.source_id),
                          "first_seen": iso(s.first_seen), "last_seen": iso(s.last_seen)} for s in svcs],
            "software": [{"product": s.product, "version": s.version, "active": s.active, "first_seen": iso(s.first_seen)} for s in sw],
            "findings": finding_rows(db, frows),
            "relationships": graph_engine.neighbors(db, a.id),
            "history": [{"id": c.id, "ts": iso(c.ts), "kind": c.kind, "summary": c.summary, "detail": c.detail,
                         "observation_id": c.observation_id} for c in changes],
            "observations": [{"id": o.id, "source": srcs.get(o.source_id), "category": o.category,
                              "observed_at": iso(o.observed_at), "status": o.status, "match_outcome": o.match_outcome,
                              "match_confidence": o.match_confidence, "quality_score": o.quality_score,
                              "flags": (o.quality or {}).get("flags", [])} for o in obs],
            "risk_history": [{"id": r.id, "ts": iso(r.ts), "score": r.score, "level": r.level, "confidence": r.confidence,
                              "summary": r.summary, "factors": r.factors, "version": r.version} for r in ras],
            "identity_decisions": [identity_row(d) for d in decisions],
            "anomalies": [anomaly_row(x) for x in anoms],
            "impact": graph_engine.impact(db, a.id)}


def identity_row(d: IdentityDecision, names=None):
    return {"id": d.id, "observation_id": d.observation_id, "asset_id": d.asset_id, "candidate_asset_id": d.candidate_asset_id,
            "asset": names.get(d.asset_id) if names else None, "candidate": names.get(d.candidate_asset_id) if names else None,
            "outcome": d.outcome, "status": d.status, "confidence": d.confidence, "evidence": d.evidence,
            "model_version": d.model_version, "ts": iso(d.ts), "decided_by": d.decided_by, "decided_at": iso(d.decided_at)}


def anomaly_row(x: Anomaly, names=None):
    return {"id": x.id, "asset_id": x.asset_id, "asset": names.get(x.asset_id) if names else None, "ts": iso(x.ts),
            "score": x.score, "threshold": x.threshold, "summary": x.summary, "contributors": x.contributors,
            "features": x.features, "model_version": x.model_version, "status": x.status, "reviewer": x.reviewer,
            "review_note": x.review_note, "kind": "predicted",
            "limitation": "ML anomaly score = deviation from learned change patterns; not evidence of malicious activity."}


def names_map(db: Session):
    return {i: n for i, n in db.query(Asset.id, Asset.name)}


# ------------------------------------------------------------------ overview
def overview(db: Session):
    t = now()
    assets = live_assets(db).all()
    by_type, by_status, by_risk, by_exp = {}, {}, {}, {"external": 0, "internal": 0}
    for a in assets:
        by_type[a.type] = by_type.get(a.type, 0) + 1
        by_status[a.status] = by_status.get(a.status, 0) + 1
        by_risk[a.risk_level] = by_risk.get(a.risk_level, 0) + 1
        by_exp[a.exposure if a.exposure in by_exp else "internal"] += 1
    ids = {a.id for a in assets}
    open_f = db.query(Finding, Vulnerability).join(Vulnerability, Vulnerability.cve_id == Finding.cve_id).filter(
        Finding.status == "open", Finding.asset_id.in_(ids or {0})).all()
    ras = latest_assessments(db, [f.id for f, _ in open_f])
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    ctx = {"critical": 0, "high": 0, "medium": 0, "low": 0, "verify": 0}
    for f, v in open_f:
        sev[v.severity if v.severity in sev else "unknown"] += 1
        ra = ras.get(f.id)
        lv = "verify" if (ra and ra.confidence is not None and ra.confidence < 0.4) else (ra.level if ra else "low")
        ctx[lv if lv in ctx else "low"] += 1
    since = t - timedelta(hours=24)
    boring = {"asset_created", "risk_changed", "finding_added", "relationship_added"}
    changes24 = db.query(Change).filter(Change.ts >= since, ~Change.kind.in_(boring)).count()
    new24 = db.query(Change).filter(Change.ts >= since, Change.kind == "asset_created").count()
    # trends over 14 days
    days = [(t - timedelta(days=d)).date() for d in range(13, -1, -1)]
    all_f = db.query(Finding.first_seen, Finding.resolved_at).filter(Finding.asset_id.in_(ids or {0})).all()
    ch = db.query(func.date(Change.ts), func.count(Change.id)).filter(
        Change.ts >= t - timedelta(days=14), ~Change.kind.in_(boring | {"identifier_added"})).group_by(func.date(Change.ts)).all()
    chmap = {str(d): n for d, n in ch}
    trend = {"days": [d.isoformat() for d in days],
             "open_findings": [sum(1 for fs, rs in all_f if fs.date() <= d and (rs is None or rs.date() > d)) for d in days],
             "changes": [chmap.get(d.isoformat(), 0) for d in days]}
    # activity stream
    act = []
    boring_stream = {"identifier_added", "relationship_added"}
    for c, n in db.query(Change, Asset.name).join(Asset, Asset.id == Change.asset_id).filter(
            ~Change.kind.in_(boring_stream)).order_by(Change.ts.desc(), Change.id.desc()).limit(40):
        act.append({"ts": iso(c.ts), "type": c.kind, "asset_id": c.asset_id, "asset": n, "text": c.summary})
    for x, n in db.query(Anomaly, Asset.name).join(Asset, Asset.id == Anomaly.asset_id).order_by(Anomaly.ts.desc()).limit(10):
        act.append({"ts": iso(x.ts), "type": "anomaly", "asset_id": x.asset_id, "asset": n,
                    "text": f"Anomaly detected (score {x.score:.2f}): {x.summary}"})
    for i in db.query(Investigation).order_by(Investigation.updated_at.desc()).limit(5):
        act.append({"ts": iso(i.updated_at), "type": "investigation", "asset_id": None, "asset": None,
                    "text": f"Investigation #{i.id} '{i.title}' is {i.status}"})
    act.sort(key=lambda e: e["ts"], reverse=True)
    from . import assistant
    fresh = freshness.summaries(db, assets)
    return {
        "freshness": {"assessment_age_hours": freshness.age_threshold(db),
                      "not_recently_assessed": sum(x["assessment_state"] == "not_recently_assessed" for x in fresh.values()),
                      "no_vulnerability_detected": sum(x["assessment_state"] == "no_vulnerability_detected" for x in fresh.values()),
                      "assets_with_conflicts": sum(bool(x["conflicting_evidence"]) for x in fresh.values())},
        "generated_at": iso(t),
        "metrics": {
            "assets_total": len(assets),
            "assets_active": sum(1 for a in assets if a.status in ("active", "changed", "discovered")),
            "assets_unresolved": sum(1 for a in assets if a.identity_status in ("unresolved", "probable") or a.status == "unresolved"),
            "assets_external": by_exp["external"],
            "vulnerabilities": len({v.cve_id for _, v in open_f if v.cve_id.startswith("CVE-")}),
            "open_findings": len(open_f),
            "critical_high_findings": ctx["critical"] + ctx["high"],
            "changes_24h": changes24, "new_assets_24h": new24,
            "anomalies_open": db.query(Anomaly).filter(Anomaly.status == "new").count(),
            "investigations_open": db.query(Investigation).filter(Investigation.status != "closed").count(),
            "identity_pending": db.query(IdentityDecision).filter(IdentityDecision.status == "pending").count()},
        "assets_by_type": by_type, "assets_by_status": by_status, "assets_by_risk": by_risk,
        "findings_by_severity": sev, "findings_by_contextual_risk": ctx, "trend": trend,
        "activity": act[:30], "top_risks": assistant.top_risks(db, 6)}


# ------------------------------------------------------------------ investigations
def investigation_detail(db: Session, i: Investigation):
    names = names_map(db)
    aids = list(i.asset_ids or [])
    tl = []
    if aids:
        since = i.created_at - timedelta(days=3)
        for c in db.query(Change).filter(Change.asset_id.in_(aids), Change.ts >= since).order_by(Change.ts).limit(300):
            tl.append({"ts": iso(c.ts), "kind": "change", "asset": names.get(c.asset_id), "text": c.summary, "basis": "observed"})
        for x in db.query(Anomaly).filter(Anomaly.asset_id.in_(aids), Anomaly.ts >= since).order_by(Anomaly.ts):
            tl.append({"ts": iso(x.ts), "kind": "anomaly", "asset": names.get(x.asset_id), "text": x.summary, "basis": "predicted"})
    for n in i.notes or []:
        tl.append({"ts": n.get("ts"), "kind": "note", "asset": None, "text": f"{n.get('user')}: {n.get('text')}", "basis": "analyst"})
    tl.sort(key=lambda e: e["ts"] or "")
    frows = []
    if i.finding_ids:
        frows = finding_rows(db, db.query(Finding, Vulnerability, Asset).join(
            Vulnerability, Vulnerability.cve_id == Finding.cve_id).join(Asset, Asset.id == Finding.asset_id).filter(
            Finding.id.in_(i.finding_ids)).all())
    arows = asset_rows(db, db.query(Asset).filter(Asset.id.in_(aids or [0])).all())
    an = [anomaly_row(x, names) for x in db.query(Anomaly).filter(Anomaly.id.in_(i.anomaly_ids or [0]))]
    return {**investigation_row(i), "assets": arows, "findings": frows, "anomalies": an, "timeline": tl,
            "notes": i.notes or [], "validation_history": i.validation_history or []}


def investigation_row(i: Investigation):
    return {"id": i.id, "title": i.title, "status": i.status, "created_by": i.created_by, "created_at": iso(i.created_at),
            "updated_at": iso(i.updated_at), "asset_ids": i.asset_ids or [], "finding_ids": i.finding_ids or [],
            "anomaly_ids": i.anomaly_ids or [], "conclusion": i.conclusion, "outcome": i.outcome,
            "validated_by": i.validated_by, "validated_at": iso(i.validated_at)}


# ------------------------------------------------------------------ reports
REPORTS = {
    "inventory": "Infrastructure inventory", "identity": "Asset identity reconciliation",
    "vulnerability": "Vulnerability assessment", "risk": "Contextual risk summary",
    "changes": "Infrastructure changes (14 days)", "anomalies": "Anomaly investigation",
    "posture": "Security posture overview", "investigations": "Investigation findings"}
_LIMITS = {
    "inventory": ["Inventory reflects what connected sources reported; unmanaged assets that no source observes are absent.",
                  "Assets with identity status 'probable' or 'unresolved' may be duplicates pending analyst review."],
    "identity": ["Match confidences come from a model trained on synthetic data plus rules; treat as decision support."],
    "vulnerability": ["'inferred' findings come from product/version matching and are not confirmed exploitable.",
                      "Vulnerability data is a seed catalog plus any NVD/KEV synchronisation performed; verify before acting."],
    "risk": ["Contextual risk is an uncalibrated, explainable weighted score - NOT a probability of compromise.",
             "Rows with low confidence should be verified before prioritisation."],
    "changes": ["Changes are derived from differences between successive observations."],
    "anomalies": ["Anomaly scores indicate deviation from learned patterns, not proof of malicious activity."],
    "posture": ["Counts reflect currently open findings on non-merged assets."],
    "investigations": ["Conclusions are analyst-authored; 'validated' means reviewed by a user with validation rights."]}


def build_report(db: Session, kind: str):
    if kind not in REPORTS:
        raise KeyError(kind)
    t = now()
    cols, rows, scope, sources = [], [], "", ["DEEPSIGHT platform database"]
    names = names_map(db)
    if kind == "inventory":
        cols = ["name", "type", "status", "identity_status", "identity_confidence", "criticality", "exposure", "os", "ips", "open_findings", "risk_level", "last_seen"]
        rows = [[(", ".join(r[c]) if c == "ips" else r[c]) for c in cols] for r in asset_rows(db, live_assets(db).order_by(Asset.name).all())]
        scope = "All non-merged assets"
    elif kind == "identity":
        cols = ["decision", "asset", "candidate", "outcome", "status", "confidence", "decided_by", "evidence"]
        rows = [[d.id, names.get(d.asset_id), names.get(d.candidate_asset_id), d.outcome, d.status, d.confidence,
                 d.decided_by, "; ".join(map(str, d.evidence or []))]
                for d in db.query(IdentityDecision).filter(IdentityDecision.outcome != "confirmed", IdentityDecision.outcome != "new").order_by(IdentityDecision.id.desc()).limit(500)]
        scope = "Probable / unresolved / potentially separate identity decisions"
    elif kind in ("vulnerability", "risk"):
        frs = finding_rows(db, db.query(Finding, Vulnerability, Asset).join(Vulnerability, Vulnerability.cve_id == Finding.cve_id).join(
            Asset, Asset.id == Finding.asset_id).filter(Finding.status == "open", LIVE).all())
        frs.sort(key=lambda r: -(r["contextual_score"] or 0))
        cols = ["asset", "cve", "cvss", "kev", "exploit_available", "basis", "exposure", "contextual_score", "contextual_level", "confidence", "first_seen"]
        rows = [[r[c] for c in cols] for r in frs]
        scope = "Open findings, ordered by contextual risk"
        sources.append("Vulnerability catalog (seed/NVD/KEV)")
    elif kind == "changes":
        cols = ["ts", "asset", "kind", "summary"]
        rows = [[iso(c.ts), names.get(c.asset_id), c.kind, c.summary] for c in db.query(Change).filter(
            Change.ts >= t - timedelta(days=14), ~Change.kind.in_(["identifier_added", "relationship_added"])).order_by(Change.ts.desc()).limit(2000)]
        scope = "Last 14 days"
    elif kind == "anomalies":
        cols = ["ts", "asset", "score", "threshold", "status", "summary", "model_version"]
        rows = [[iso(x.ts), names.get(x.asset_id), x.score, x.threshold, x.status, x.summary, x.model_version]
                for x in db.query(Anomaly).order_by(Anomaly.ts.desc()).limit(1000)]
        scope = "All anomalies"
        sources.append("Anomaly model (Isolation Forest)")
    elif kind == "posture":
        o = overview(db)
        cols = ["metric", "value"]
        rows = [[k.replace("_", " "), v] for k, v in o["metrics"].items()]
        rows += [[f"findings by CVSS severity: {k}", v] for k, v in o["findings_by_severity"].items()]
        rows += [[f"findings by contextual risk: {k}", v] for k, v in o["findings_by_contextual_risk"].items()]
        scope = "Organisation-wide"
    elif kind == "investigations":
        cols = ["id", "title", "status", "outcome", "created_by", "validated_by", "assets", "conclusion"]
        rows = [[i.id, i.title, i.status, i.outcome, i.created_by, i.validated_by,
                 ", ".join(names.get(a, str(a)) for a in i.asset_ids or []), i.conclusion]
                for i in db.query(Investigation).order_by(Investigation.id.desc())]
        scope = "All investigations"
    return {"kind": kind, "title": REPORTS[kind], "generated_at": iso(t), "scope": scope, "sources": sources,
            "limitations": _LIMITS[kind], "columns": cols, "rows": rows}


def report_csv(rep):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([f"# {rep['title']}", f"generated {rep['generated_at']}", rep["scope"]])
    for lim in rep["limitations"]:
        w.writerow([f"# limitation: {lim}"])
    w.writerow(rep["columns"])
    for r in rep["rows"]:
        # neutralise spreadsheet formula injection from externally sourced values
        w.writerow([("'" + str(c)) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in r])
    return buf.getvalue()


def report_html(rep):
    e = html.escape
    head = "".join(f"<th>{e(c)}</th>" for c in rep["columns"])
    body = "".join("<tr>" + "".join(f"<td>{e('' if c is None else str(c))}</td>" for c in r) + "</tr>" for r in rep["rows"])
    lim = "".join(f"<li>{e(x)}</li>" for x in rep["limitations"])
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{e(rep['title'])}</title><style>"
            "body{font:14px system-ui;margin:2rem;color:#111}table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:12px}th{background:#eef}"
            f"</style></head><body><h1>{e(rep['title'])}</h1><p>Generated {e(rep['generated_at'])} &middot; Scope: {e(rep['scope'])}"
            f" &middot; Sources: {e(', '.join(rep['sources']))}</p><h3>Limitations</h3><ul>{lim}</ul>"
            f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></body></html>")
