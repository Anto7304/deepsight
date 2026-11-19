"""REST API (all routes under /api). Authentication is JWT bearer; authorization is role based."""
import json
from datetime import timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session

from . import assistant as assistant_mod
from . import collector, pipeline, services
from .config import settings
from .connectors import REGISTRY, ConnectorError
from .connectors import describe as describe_connectors
from .db import SessionLocal, get_db
from .engines import graph as graph_engine
from .engines import identity, intel, ml, risk, state
from .models import (Anomaly, Asset, AssetIdentifier, AuditLog, Change, CollectionRun, EvalVector, Finding,
                     IdentityDecision, Investigation, ModelRun, Observation, Relationship, RiskAssessment, Service,
                     Setting, Source, User, Vulnerability)
from .security import (ADMIN, ANALYST, ANY, ROLE_DESCRIPTIONS, ROLES, VALIDATOR, audit, current_user, encrypt_secrets,
                       hash_password, limiter, make_token, require, verify_password)
from .util import iso, now

router = APIRouter(prefix="/api")




def paginate(q, page, size):
    total = q.count()
    return total, q.offset((page - 1) * size).limit(size)


# ------------------------------------------------------------------ health / auth
@router.get("/health")
def health(db: Session = Depends(get_db)):
    from .observability import health
    from fastapi.responses import JSONResponse
    result = health(db)
    return JSONResponse(result, status_code=200 if result["status"] == "ok" else 503)


class Login(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


@router.post("/auth/login")
def login(body: Login, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "?"
    if not limiter.allow(f"login:{ip}:{body.username.lower()}", settings.login_rate_limit_per_min):
        raise HTTPException(429, "Too many login attempts; wait a minute")
    u = db.query(User).filter(User.username == body.username).first()
    if not u or not u.active or not verify_password(body.password, u.pw_hash):
        audit(db, body.username, "auth.login_failed", "", {}, request)
        raise HTTPException(401, "Invalid credentials")
    u.last_login = now()
    db.commit()
    audit(db, u, "auth.login", f"user:{u.id}", {}, request)
    return {"token": make_token(u), "user": {"username": u.username, "role": u.role}}


@router.get("/auth/me")
def me(u: User = Depends(current_user)):
    return {"username": u.username, "role": u.role, "roles": {r: ROLE_DESCRIPTIONS[r] for r in ROLES}}


@router.get("/roles")
def roles(_: User = Depends(current_user)):
    return [{"role": r, "description": ROLE_DESCRIPTIONS[r]} for r in ROLES]


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["administrator", "analyst", "manager", "readonly"] = "readonly"


class UserPatch(BaseModel):
    role: Optional[Literal["administrator", "analyst", "manager", "readonly"]] = None
    active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=12, max_length=256)


@router.get("/users")
def users(db: Session = Depends(get_db), _: User = Depends(require(*ADMIN))):
    return [{"id": u.id, "username": u.username, "role": u.role, "active": u.active, "last_login": iso(u.last_login),
             "created_at": iso(u.created_at)} for u in db.query(User).order_by(User.id)]


@router.post("/users", status_code=201)
def create_user(body: UserIn, request: Request, db: Session = Depends(get_db), admin: User = Depends(require(*ADMIN))):
    if db.query(User).filter(func.lower(User.username) == body.username.lower()).first():
        raise HTTPException(409, "username already exists")
    u = User(username=body.username, pw_hash=hash_password(body.password), role=body.role)
    db.add(u)
    db.commit()
    audit(db, admin, "user.create", f"user:{u.id}", {"role": u.role}, request)
    return {"id": u.id, "username": u.username, "role": u.role}


@router.patch("/users/{uid}")
def patch_user(uid: int, body: UserPatch, request: Request, db: Session = Depends(get_db),
               admin: User = Depends(require(*ADMIN))):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "not found")
    if u.id == admin.id and (body.active is False or (body.role and body.role != "administrator")):
        raise HTTPException(400, "you cannot demote or disable your own account")
    if body.role:
        u.role = body.role
    if body.active is not None:
        u.active = body.active
    if body.password:
        u.pw_hash = hash_password(body.password)
    db.commit()
    audit(db, admin, "user.update", f"user:{u.id}", {"role": u.role, "active": u.active, "password_changed": bool(body.password)}, request)
    return {"ok": True}


# ------------------------------------------------------------------ assets
@router.get("/assets")
def list_assets(q: str = "", type: str = "", status: str = "", exposure: str = "", identity: str = "", risk: str = "",
                sort: str = "risk_score", order: str = "desc", page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                db: Session = Depends(get_db), _: User = Depends(current_user)):
    qq = services.live_assets(db)
    if q:
        like = f"%{q.lower()}%"
        ids = db.query(AssetIdentifier.asset_id).filter(AssetIdentifier.value.like(like))
        qq = qq.filter(or_(func.lower(Asset.name).like(like), func.lower(Asset.owner).like(like), Asset.id.in_(ids)))
    for col, val in ((Asset.type, type), (Asset.status, status), (Asset.exposure, exposure),
                     (Asset.identity_status, identity), (Asset.risk_level, risk)):
        if val:
            qq = qq.filter(col == val)
    col = {"name": Asset.name, "type": Asset.type, "risk_score": Asset.risk_score, "criticality": Asset.criticality,
           "last_seen": Asset.last_seen, "status": Asset.status}.get(sort, Asset.risk_score)
    qq = qq.order_by(col.desc() if order == "desc" else col.asc(), Asset.id)
    total, page_q = paginate(qq, page, size)
    return {"total": total, "page": page, "items": services.asset_rows(db, page_q.all())}


def _asset(db, aid) -> Asset:
    a = db.get(Asset, aid)
    if not a:
        raise HTTPException(404, "asset not found")
    return a


@router.get("/assets/{aid}")
def get_asset(aid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    return services.asset_detail(db, _asset(db, aid))


@router.get("/assets/{aid}/impact")
def asset_impact(aid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    _asset(db, aid)
    return graph_engine.impact(db, aid)


@router.get("/assets/{aid}/{part}")
def asset_part(aid: int, part: Literal["identifiers", "history", "relationships", "observations", "risk", "services",
                                       "findings"], db: Session = Depends(get_db), _: User = Depends(current_user)):
    d = services.asset_detail(db, _asset(db, aid))
    return d["risk_history" if part == "risk" else part]


class AssetPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    criticality: Optional[int] = Field(default=None, ge=1, le=5)
    owner: Optional[str] = Field(default=None, max_length=128)
    status: Optional[Literal["retired", "active"]] = None
    tags: Optional[list[str]] = None


@router.patch("/assets/{aid}")
def patch_asset(aid: int, body: AssetPatch, request: Request, db: Session = Depends(get_db),
                u: User = Depends(require(*ANALYST))):
    a = _asset(db, aid)
    before = {"criticality": a.criticality, "owner": a.owner, "status": a.status, "name": a.name}
    if body.name:
        a.name = body.name
    if body.criticality:
        a.criticality, a.criticality_source = body.criticality, "analyst"
    if body.owner is not None:
        a.owner = body.owner
    if body.status:
        a.status = body.status
    if body.tags is not None:
        a.tags = body.tags[:30]
    db.add(Change(asset_id=a.id, ts=now(), kind="analyst_edit", summary=f"Asset edited by {u.username}",
                  detail={"before": before, "after": body.model_dump(exclude_none=True)}))
    db.flush()
    risk.reassess_asset(db, a.id, force=True)
    db.commit()
    audit(db, u, "asset.update", f"asset:{a.id}", body.model_dump(exclude_none=True), request)
    return services.asset_rows(db, [a])[0]


# ------------------------------------------------------------------ observations / identity
@router.get("/observations")
def list_observations(status: str = "", source_id: int = 0, asset_id: int = 0, page: int = Query(1, ge=1),
                      size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(Observation)
    if status:
        q = q.filter(Observation.status == status)
    if source_id:
        q = q.filter(Observation.source_id == source_id)
    if asset_id:
        q = q.filter(Observation.asset_id == asset_id)
    total, pq = paginate(q.order_by(Observation.id.desc()), page, size)
    srcs = {s.id: s.name for s in db.query(Source)}
    return {"total": total, "items": [{"id": o.id, "source": srcs.get(o.source_id), "category": o.category,
                                       "observed_at": iso(o.observed_at), "status": o.status, "asset_id": o.asset_id,
                                       "match_outcome": o.match_outcome, "match_confidence": o.match_confidence,
                                       "quality_score": o.quality_score, "flags": (o.quality or {}).get("flags", []),
                                       "identifiers": o.identifiers, "error": o.error} for o in pq.all()]}


@router.get("/observations/{oid}")
def get_observation(oid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    o = db.get(Observation, oid)
    if not o:
        raise HTTPException(404, "not found")
    s = db.get(Source, o.source_id) if o.source_id else None
    dec = db.query(IdentityDecision).filter(IdentityDecision.observation_id == o.id).all()
    from .retention import read_raw
    return {"id": o.id, "source": s.name if s else "manual", "category": o.category, "identifiers": o.identifiers,
            "attributes": o.attributes, "raw": read_raw(o), "raw_ref": o.raw_ref, "observed_at": iso(o.observed_at),
            "collected_at": iso(o.collected_at), "status": o.status, "error": o.error, "quality": o.quality,
            "quality_score": o.quality_score, "asset_id": o.asset_id, "match_outcome": o.match_outcome,
            "match_confidence": o.match_confidence, "identity_decisions": [services.identity_row(d) for d in dec],
            "basis": "observed"}


class ObsIn(BaseModel):
    identifiers: dict
    attributes: dict = Field(default_factory=dict)
    observed_at: Optional[str] = None
    category: str = "asset"


class ObsBatch(BaseModel):
    observations: list[ObsIn] = Field(min_length=1, max_length=500)


def _manual_source(db):
    s = db.query(Source).filter(Source.name == "manual-submission").first()
    if not s:
        s = Source(name="manual-submission", kind="generic_json", category="manual", enabled=True, verified=True,
                   config={}, status="ok", auth_status="ok")
        db.add(s)
        db.commit()
    return s


@router.post("/observations", status_code=202)
def submit_observations(body: ObsBatch, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    src = _manual_source(db)
    res = pipeline.ingest(db, src, [o.model_dump() for o in body.observations], raw_ref=f"manual:{u.username}")
    audit(db, u, "observation.submit", f"source:{src.id}", res["counts"], request)
    return res


@router.post("/observations/reprocess")
def reprocess(db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    return pipeline.reprocess_failed(db)


@router.get("/identity/decisions")
def identity_decisions(status: str = "pending", page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                       db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(IdentityDecision)
    if status == "pending":
        q = q.filter(IdentityDecision.status == "pending")
    elif status == "review":
        q = q.filter(IdentityDecision.outcome.in_(["probable", "unresolved", "potentially_separate"]))
    elif status != "all":
        q = q.filter(IdentityDecision.status == status)
    total, pq = paginate(q.order_by(IdentityDecision.id.desc()), page, size)
    names = services.names_map(db)
    return {"total": total, "items": [services.identity_row(d, names) for d in pq.all()]}


class DecisionIn(BaseModel):
    note: Optional[str] = Field(default=None, max_length=500)


def _decision(db, did) -> IdentityDecision:
    d = db.get(IdentityDecision, did)
    if not d:
        raise HTTPException(404, "decision not found")
    return d


@router.post("/identity/decisions/{did}/confirm")
def confirm_decision(did: int, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    d = _decision(db, did)
    if d.status != "pending" or not d.candidate_asset_id:
        raise HTTPException(409, "decision is not pending")
    from .evaluation import capture_identity_label
    capture_identity_label(db, d, 1, u.username)
    try:
        identity.merge_assets(db, d.candidate_asset_id, d.asset_id, d, u.username)
    except ValueError as e:
        raise HTTPException(409, str(e))
    d.status, d.decided_by, d.decided_at = "confirmed", u.username, now()
    db.flush()
    state.refresh_identity(db, db.get(Asset, d.candidate_asset_id))
    intel.match_asset(db, db.get(Asset, d.candidate_asset_id))
    risk.reassess_asset(db, d.candidate_asset_id, force=True)
    db.commit()
    audit(db, u, "identity.confirm", f"decision:{d.id}", {"merged": d.asset_id, "into": d.candidate_asset_id}, request)
    return services.identity_row(d)


@router.post("/identity/decisions/{did}/reject")
def reject_decision(did: int, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    d = _decision(db, did)
    if d.status != "pending":
        raise HTTPException(409, "decision is not pending")
    from .evaluation import capture_identity_label
    capture_identity_label(db, d, 0, u.username)
    d.status, d.decided_by, d.decided_at = "rejected", u.username, now()
    a = db.get(Asset, d.asset_id)
    if a and a.identity_status in ("probable", "unresolved"):
        a.identity_status, a.identity_confidence = "confirmed", max(a.identity_confidence or 0, 0.8)
        db.add(Change(asset_id=a.id, ts=now(), kind="identity_decision", summary=f"Analyst {u.username} confirmed this is a separate asset",
                      detail={"decision": d.id}))
    db.commit()
    audit(db, u, "identity.reject", f"decision:{d.id}", {}, request)
    return services.identity_row(d)


@router.post("/identity/decisions/{did}/revert")
def revert_decision(did: int, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    d = _decision(db, did)
    try:
        if d.status == "confirmed" and d.merge_snapshot:
            identity.revert_merge(db, d, u.username)
            risk.reassess_asset(db, d.candidate_asset_id, force=True)
            risk.reassess_asset(db, d.asset_id, force=True)
        elif d.status == "rejected":
            d.status = "pending"
            a = db.get(Asset, d.asset_id)
            if a:
                a.identity_status, a.identity_confidence = "probable", d.confidence or 0.5
        else:
            raise HTTPException(409, "nothing to revert for this decision")
    except ValueError as e:
        raise HTTPException(409, str(e))
    db.commit()
    audit(db, u, "identity.revert", f"decision:{d.id}", {}, request)
    return services.identity_row(d)


# ------------------------------------------------------------------ findings / vulnerabilities
@router.get("/findings")
def list_findings(status: str = "open", level: str = "", asset_id: int = 0, cve: str = "", kev: Optional[bool] = None,
                  exposure: str = "", basis: str = "", triage: str = "", sort: str = "contextual", page: int = Query(1, ge=1),
                  size: int = Query(50, ge=1, le=200), q: str = "", db: Session = Depends(get_db), _: User = Depends(current_user)):
    search = q.strip().lower()
    q = db.query(Finding, Vulnerability, Asset).join(Vulnerability, Vulnerability.cve_id == Finding.cve_id).join(
        Asset, Asset.id == Finding.asset_id).filter(services.LIVE)
    if status != "all":
        q = q.filter(Finding.status == status)
    if asset_id:
        q = q.filter(Finding.asset_id == asset_id)
    if cve:
        q = q.filter(Finding.cve_id.like(f"%{cve.upper()}%"))
    if kev is not None:
        q = q.filter(Vulnerability.kev.is_(kev))
    if exposure:
        q = q.filter(Asset.exposure == exposure)
    if basis:
        q = q.filter(Finding.basis == basis)
    rows = services.finding_rows(db, q.all())
    if search:
        rows = [r for r in rows if search in f"{r['cve']} {r['asset']} {r.get('title') or ''}".lower()]
    if level:
        levels = {part.strip() for part in level.split(",")}
        rows = [r for r in rows if r["contextual_level"] in levels]
    if triage:
        rows = [r for r in rows if r["investigation_status"] == triage]
    keyf = {"contextual": lambda r: -(r["contextual_score"] or 0), "cvss": lambda r: -(r["cvss"] or 0),
            "first_seen": lambda r: r["first_seen"] or "", "asset": lambda r: r["asset"]}.get(sort, lambda r: 0)
    rows.sort(key=keyf)
    total = len(rows)
    return {"total": total, "items": rows[(page - 1) * size: page * size]}


@router.get("/findings/{fid}")
def get_finding(fid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    row = db.query(Finding, Vulnerability, Asset).join(Vulnerability, Vulnerability.cve_id == Finding.cve_id).join(
        Asset, Asset.id == Finding.asset_id).filter(Finding.id == fid).first()
    if not row:
        raise HTTPException(404, "finding not found")
    f, v, a = row
    base = services.finding_rows(db, [row])[0]
    ras = db.query(RiskAssessment).filter(RiskAssessment.finding_id == fid).order_by(RiskAssessment.ts.desc()).limit(20).all()
    cur = ras[0] if ras else None
    svc = db.get(Service, f.service_id) if f.service_id else None
    return {**base, "description": v.description, "remediation": v.remediation, "techniques": v.techniques,
            "references": v.references, "published": iso(v.published), "enriched": v.enriched,
            "vuln_source": v.source, "kev_added": v.kev_added, "evidence": f.evidence, "triage": services.triage_of(f),
            "service": {"port": svc.port, "product": svc.product, "version": svc.version, "exposed": svc.exposed} if svc else None,
            "assessment": {"score": cur.score, "level": cur.level, "confidence": cur.confidence, "factors": cur.factors,
                           "version": cur.version, "ts": iso(cur.ts), "evidence": cur.evidence} if cur else None,
            "assessment_history": [{"ts": iso(r.ts), "score": r.score, "level": r.level} for r in ras],
            "suggested_actions": risk.suggested_action(f, v, {
                "needs_verification": bool(cur and (cur.confidence or 0) < 0.45),
                "exposed": bool((svc and svc.exposed) or (not svc and a.exposure == "external"))}),
            "published_severity_vs_context": "Published CVSS and DEEPSIGHT contextual risk are separate measures.",
            "asset_summary": services.asset_rows(db, [a])[0]}


class TriageIn(BaseModel):
    state: Optional[Literal["new", "confirmed", "in_progress", "pending_verification", "accepted_risk", "false_positive"]] = None
    note: Optional[str] = Field(default=None, max_length=500)
    owner: Optional[str] = Field(default=None, max_length=128)
    due_date: Optional[str] = Field(default=None, max_length=40)
    remediation_guidance: Optional[str] = Field(default=None, max_length=4000)
    ticket_reference: Optional[str] = Field(default=None, max_length=1000)
    reason: Optional[str] = Field(default=None, max_length=2000)
    approver: Optional[str] = Field(default=None, max_length=128)
    expiry: Optional[str] = Field(default=None, max_length=40)


@router.patch("/findings/{fid}")
def triage_finding(fid: int, body: TriageIn, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    from . import remediation
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "finding not found")
    try:
        result = remediation.update(db, f, body.model_dump(exclude_unset=True), u.username)
    except (ValueError, TypeError) as e:
        raise HTTPException(422, str(e)) from e
    db.commit()
    audit(db, u, "finding.triage", f"finding:{fid}", body.model_dump(), request)
    return result


class VerificationIn(BaseModel):
    observation_id: int = Field(gt=0)


@router.post("/findings/{fid}/verify")
def verify_finding(fid: int, body: VerificationIn, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    from . import remediation
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "finding not found")
    try:
        result = remediation.verify(db, f, body.observation_id, u.username)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    db.commit()
    audit(db, u, "finding.verified", f"finding:{fid}", {"observation_id": body.observation_id})
    return result


@router.get("/findings/{fid}/what-if")
def finding_what_if(fid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    from . import remediation
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "finding not found")
    return remediation.what_if(db, f)


@router.get("/remediation/metrics")
def remediation_metrics(db: Session = Depends(get_db), _: User = Depends(current_user)):
    from . import remediation
    return remediation.metrics(db)


@router.get("/vulnerabilities")
def list_vulns(q: str = "", kev: Optional[bool] = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
               db: Session = Depends(get_db), _: User = Depends(current_user)):
    qq = db.query(Vulnerability)
    if q:
        qq = qq.filter(or_(Vulnerability.cve_id.like(f"%{q.upper()}%"), func.lower(Vulnerability.description).like(f"%{q.lower()}%")))
    if kev is not None:
        qq = qq.filter(Vulnerability.kev.is_(kev))
    affected = dict(db.query(Finding.cve_id, func.count(Finding.id)).filter(Finding.status == "open").group_by(Finding.cve_id).all())
    total, pq = paginate(qq.order_by(Vulnerability.kev.desc(), Vulnerability.cvss.desc()), page, size)
    return {"total": total, "items": [{"cve": v.cve_id, "cvss": v.cvss, "severity": v.severity, "kev": v.kev,
                                       "exploit_available": v.exploit_available, "description": v.description,
                                       "source": v.source, "enriched": v.enriched, "affected_findings": affected.get(v.cve_id, 0)}
                                      for v in pq.all()]}


@router.get("/vulnerabilities/{cve}")
def get_vuln(cve: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    v = db.get(Vulnerability, cve.upper())
    if not v:
        raise HTTPException(404, "not in catalog")
    return {"cve": v.cve_id, "cvss": v.cvss, "severity": v.severity, "kev": v.kev, "kev_added": v.kev_added,
            "exploit_available": v.exploit_available, "description": v.description, "affected": v.affected,
            "techniques": v.techniques, "references": v.references, "remediation": v.remediation, "source": v.source,
            "enriched": v.enriched, "published": iso(v.published)}


# ------------------------------------------------------------------ intelligence (ML, anomalies, risk, feeds)
@router.get("/intelligence")
def intelligence(db: Session = Depends(get_db), _: User = Depends(current_user)):
    last = db.get(Setting, "kev_sync")
    return {"models": ml.model_status(db),
            "catalog": {"vulnerabilities": db.query(Vulnerability).count(),
                        "kev": db.query(Vulnerability).filter(Vulnerability.kev.is_(True)).count(),
                        "unenriched": db.query(Vulnerability).filter(Vulnerability.enriched.is_(False)).count(),
                        "last_kev_sync": last.value if last else None},
            "anomalies": {"new": db.query(Anomaly).filter(Anomaly.status == "new").count(),
                          "true_positive": db.query(Anomaly).filter(Anomaly.status == "true_positive").count(),
                          "false_positive": db.query(Anomaly).filter(Anomaly.status == "false_positive").count()},
            "identity": {"pending": db.query(IdentityDecision).filter(IdentityDecision.status == "pending").count()},
            "risk_model": {"version": risk.VERSION, "weights": risk.WEIGHTS, "labels": risk.LABELS,
                           "caveat": "Uncalibrated explainable score; not a probability of compromise."}}


@router.post("/intelligence/kev-sync")
def kev_sync(db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    try:
        res = intel.sync_kev(db)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"KEV feed unavailable from this deployment: {type(e).__name__}: {e}"[:300])
    s = db.get(Setting, "kev_sync")
    val = {"at": iso(now()), **res}
    if s:
        s.value = val
    else:
        db.add(Setting(key="kev_sync", value=val))
    risk.reassess_all(db, force=True)
    audit(db, u, "intel.kev_sync", "", res)
    return res


@router.post("/intelligence/nvd/{cve}")
def nvd_sync(cve: str, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    try:
        res = intel.sync_nvd_cve(db, cve.upper())
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"NVD unavailable from this deployment: {type(e).__name__}: {e}"[:300])
    return res


@router.post("/intelligence/rematch")
def rematch(db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    n = intel.rematch_all(db)
    risk.reassess_all(db, force=True)
    return {"new_findings": n}


@router.get("/anomalies")
def list_anomalies(status: str = "", page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
                   db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(Anomaly)
    if status:
        q = q.filter(Anomaly.status == status)
    total, pq = paginate(q.order_by(Anomaly.ts.desc()), page, size)
    names = services.names_map(db)
    return {"total": total, "items": [services.anomaly_row(x, names) for x in pq.all()]}


class AnomalyPatch(BaseModel):
    status: Literal["new", "reviewed", "true_positive", "false_positive"]
    note: Optional[str] = Field(default=None, max_length=500)


@router.patch("/anomalies/{xid}")
def review_anomaly(xid: int, body: AnomalyPatch, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    x = db.get(Anomaly, xid)
    if not x:
        raise HTTPException(404, "not found")
    x.status, x.review_note, x.reviewer, x.reviewed_at = body.status, body.note, u.username, now()
    risk.reassess_asset(db, x.asset_id, force=True)
    db.commit()
    audit(db, u, "anomaly.review", f"anomaly:{xid}", body.model_dump(), request)
    return services.anomaly_row(x)


@router.get("/risk-assessments")
def list_risk(asset_id: int = 0, finding_id: int = 0, limit: int = Query(50, ge=1, le=500),
              db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(RiskAssessment)
    if asset_id:
        q = q.filter(RiskAssessment.asset_id == asset_id)
    if finding_id:
        q = q.filter(RiskAssessment.finding_id == finding_id)
    return [{"id": r.id, "asset_id": r.asset_id, "finding_id": r.finding_id, "ts": iso(r.ts), "score": r.score,
             "level": r.level, "cvss": r.cvss, "confidence": r.confidence, "factors": r.factors, "version": r.version,
             "summary": r.summary} for r in q.order_by(RiskAssessment.id.desc()).limit(limit)]


@router.get("/ml/models")
def ml_models(db: Session = Depends(get_db), _: User = Depends(current_user)):
    runs = db.query(ModelRun).order_by(ModelRun.id.desc()).limit(30).all()
    return {"active": ml.model_status(db), "history": [{"name": r.name, "version": r.version, "trained_at": iso(r.trained_at),
                                                         "status": r.status, "data_origin": r.data_origin, "metrics": r.metrics} for r in runs],
            "training_vectors_collected": db.query(EvalVector).count()}


@router.post("/ml/retrain/anomaly")
def retrain_anomaly(u: User = Depends(require(*ADMIN))):
    return ml.retrain_anomaly()


@router.get("/changes")
def list_changes(hours: int = Query(24, ge=1, le=24 * 90), asset_id: int = 0, kind: str = "", limit: int = Query(200, ge=1, le=1000),
                 db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(Change, Asset.name).join(Asset, Asset.id == Change.asset_id).filter(Change.ts >= now() - timedelta(hours=hours))
    if asset_id:
        q = q.filter(Change.asset_id == asset_id)
    if kind:
        q = q.filter(Change.kind == kind)
    return [{"id": c.id, "ts": iso(c.ts), "asset_id": c.asset_id, "asset": n, "kind": c.kind, "summary": c.summary}
            for c, n in q.order_by(Change.ts.desc(), Change.id.desc()).limit(limit)]


# ------------------------------------------------------------------ infrastructure graph
@router.get("/graph")
def graph(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return graph_engine.graph_payload(db)


class RelIn(BaseModel):
    src_id: int
    dst_id: int
    type: Literal["hosts", "depends_on", "connects_to", "runs_on", "belongs_to"]


@router.post("/relationships", status_code=201)
def add_relationship(body: RelIn, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    _asset(db, body.src_id), _asset(db, body.dst_id)
    ch = []
    r = state.upsert_relationship(db, body.src_id, body.dst_id, body.type, "observed", None, 1.0, now(),
                                  {"asserted_by": u.username}, ch, None)
    if not r:
        raise HTTPException(400, "invalid relationship")
    risk.reassess_all(db, force=True)
    audit(db, u, "relationship.create", f"asset:{body.src_id}", body.model_dump(), request)
    return {"ok": True}


@router.delete("/relationships/{rid}")
def close_relationship(rid: int, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    r = db.get(Relationship, rid)
    if not r:
        raise HTTPException(404, "not found")
    r.valid_to = now()
    db.commit()
    audit(db, u, "relationship.close", f"relationship:{rid}", {}, request)
    return {"ok": True}


# ------------------------------------------------------------------ investigations
class InvIn(BaseModel):
    title: str = Field(min_length=3, max_length=256)
    asset_ids: list[int] = Field(default_factory=list, max_length=50)
    finding_ids: list[int] = Field(default_factory=list, max_length=100)
    anomaly_ids: list[int] = Field(default_factory=list, max_length=100)
    note: Optional[str] = Field(default=None, max_length=2000)


class InvPatch(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=256)
    status: Optional[Literal["open", "in_progress", "closed"]] = None
    asset_ids: Optional[list[int]] = None
    finding_ids: Optional[list[int]] = None
    anomaly_ids: Optional[list[int]] = None
    conclusion: Optional[str] = Field(default=None, max_length=4000)


def _inv(db, iid) -> Investigation:
    i = db.get(Investigation, iid)
    if not i:
        raise HTTPException(404, "investigation not found")
    return i


def _check_refs(db, asset_ids=None, finding_ids=None, anomaly_ids=None):
    """Reject references to records that do not exist (instead of storing dangling ids)."""
    for label, model, ids in (("asset", Asset, asset_ids), ("finding", Finding, finding_ids), ("anomaly", Anomaly, anomaly_ids)):
        ids = set(ids or [])
        if not ids:
            continue
        if any(not 0 < x < 2**31 for x in ids):
            raise HTTPException(404, f"{label} not found: {sorted(x for x in ids if not 0 < x < 2**31)}")
        found = {r[0] for r in db.query(model.id).filter(model.id.in_(ids))}
        if ids - found:
            raise HTTPException(404, f"{label} not found: {sorted(ids - found)}")


@router.get("/investigations")
def list_investigations(status: str = "", db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(Investigation)
    if status:
        q = q.filter(Investigation.status == status)
    return [services.investigation_row(i) for i in q.order_by(Investigation.updated_at.desc())]


@router.post("/investigations", status_code=201)
def create_investigation(body: InvIn, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    _check_refs(db, body.asset_ids, body.finding_ids, body.anomaly_ids)
    i = Investigation(title=body.title, created_by=u.username, asset_ids=body.asset_ids, finding_ids=body.finding_ids,
                      anomaly_ids=body.anomaly_ids, notes=[], validation_history=[])
    if body.note:
        i.notes = [{"ts": iso(now()), "user": u.username, "text": body.note}]
    # include assets of linked findings/anomalies
    extra = {f.asset_id for f in db.query(Finding).filter(Finding.id.in_(body.finding_ids or [0]))} | {
        x.asset_id for x in db.query(Anomaly).filter(Anomaly.id.in_(body.anomaly_ids or [0]))}
    i.asset_ids = sorted(set(body.asset_ids) | extra)
    db.add(i)
    db.commit()
    audit(db, u, "investigation.create", f"investigation:{i.id}", {"title": i.title}, request)
    return services.investigation_detail(db, i)


@router.get("/investigations/{iid}")
def get_investigation(iid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    return services.investigation_detail(db, _inv(db, iid))


@router.patch("/investigations/{iid}")
def patch_investigation(iid: int, body: InvPatch, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    i = _inv(db, iid)
    _check_refs(db, body.asset_ids, body.finding_ids, body.anomaly_ids)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(i, k, sorted(set(v)) if k.endswith("_ids") else v)
    db.commit()
    audit(db, u, "investigation.update", f"investigation:{i.id}", body.model_dump(exclude_none=True), request)
    return services.investigation_detail(db, i)


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


@router.post("/investigations/{iid}/notes")
def add_note(iid: int, body: NoteIn, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    i = _inv(db, iid)
    i.notes = [*(i.notes or []), {"ts": iso(now()), "user": u.username, "text": body.text}]
    db.commit()
    return services.investigation_detail(db, i)


class ValidateIn(BaseModel):
    outcome: Literal["true_positive", "false_positive", "benign", "unknown"]
    conclusion: str = Field(min_length=3, max_length=4000)


@router.post("/investigations/{iid}/validate")
def validate_investigation(iid: int, body: ValidateIn, request: Request, db: Session = Depends(get_db),
                           u: User = Depends(require(*VALIDATOR))):
    i = _inv(db, iid)
    i.outcome, i.conclusion, i.status = body.outcome, body.conclusion, "closed"
    i.validated_by, i.validated_at = u.username, now()
    i.validation_history = [*(i.validation_history or []), {"ts": iso(now()), "user": u.username, "outcome": body.outcome,
                                                            "conclusion": body.conclusion}]
    # feedback loop: validated outcome labels linked anomalies (training signal / evaluation data)
    label = {"true_positive": "true_positive", "false_positive": "false_positive"}.get(body.outcome)
    if label:
        for x in db.query(Anomaly).filter(Anomaly.id.in_(i.anomaly_ids or [0]), Anomaly.status == "new"):
            x.status, x.reviewer, x.reviewed_at, x.review_note = label, u.username, now(), f"validated via investigation #{i.id}"
    db.commit()
    audit(db, u, "investigation.validate", f"investigation:{i.id}", body.model_dump(), request)
    return services.investigation_detail(db, i)


# ------------------------------------------------------------------ integrations
class SourceIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    kind: str
    category: Optional[str] = Field(default=None, max_length=32)
    config: dict = Field(default_factory=dict)
    secrets: dict = Field(default_factory=dict)
    enabled: bool = True
    verified: bool = True
    frequency_minutes: int = Field(default=0, ge=0, le=10080)


class SourcePatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    config: Optional[dict] = None
    secrets: Optional[dict] = None
    enabled: Optional[bool] = None
    verified: Optional[bool] = None
    frequency_minutes: Optional[int] = Field(default=None, ge=0, le=10080)


def source_row(s: Source):
    c = REGISTRY.get(s.kind)
    return {"id": s.id, "name": s.name, "kind": s.kind, "kind_label": c.label if c else s.kind, "category": s.category,
            "enabled": s.enabled, "verified": s.verified, "frequency_minutes": s.frequency_minutes, "status": s.status,
            "auth_status": s.auth_status, "last_success": iso(s.last_success), "last_attempt": iso(s.last_attempt),
            "last_error": s.last_error, "has_secrets": bool(s.secrets_enc), "schedulable": bool(c and c.schedulable),
            "accepts_upload": bool(c and c.accepts_upload), "config": s.config or {}}


@router.get("/connectors")
def connectors(_: User = Depends(current_user)):
    return describe_connectors()


@router.get("/integrations")
def list_integrations(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [source_row(s) for s in db.query(Source).order_by(Source.name)]


@router.post("/integrations", status_code=201)
def create_integration(body: SourceIn, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    c = REGISTRY.get(body.kind)
    if not c:
        raise HTTPException(400, f"unknown connector kind {body.kind}")
    if db.query(Source).filter(Source.name == body.name).first():
        raise HTTPException(409, "an integration with this name exists")
    if body.frequency_minutes and not c.schedulable:
        raise HTTPException(400, "this connector is import-only; frequency must be 0")
    s = Source(name=body.name, kind=body.kind, category=body.category or c.category, config=body.config,
               secrets_enc=encrypt_secrets(body.secrets) if body.secrets else None, enabled=body.enabled,
               verified=body.verified, frequency_minutes=body.frequency_minutes)
    db.add(s)
    db.commit()
    audit(db, u, "integration.create", f"source:{s.id}", {"name": s.name, "kind": s.kind}, request)
    return source_row(s)


def _source(db, sid) -> Source:
    s = db.get(Source, sid)
    if not s:
        raise HTTPException(404, "integration not found")
    return s


@router.patch("/integrations/{sid}")
def patch_integration(sid: int, body: SourcePatch, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    s = _source(db, sid)
    d = body.model_dump(exclude_none=True)
    if "secrets" in d:
        s.secrets_enc = encrypt_secrets(d.pop("secrets")) if body.secrets else None
    for k, v in d.items():
        setattr(s, k, v)
    db.commit()
    audit(db, u, "integration.update", f"source:{s.id}", {k: v for k, v in d.items() if k != "secrets"}, request)
    return source_row(s)


@router.delete("/integrations/{sid}")
def delete_integration(sid: int, request: Request, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    s = _source(db, sid)
    s.enabled = False
    db.commit()
    audit(db, u, "integration.disable", f"source:{s.id}", {}, request)
    return {"ok": True, "note": "Integration disabled; its observations are retained as evidence."}


@router.post("/integrations/{sid}/test")
def test_integration(sid: int, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    from .security import decrypt_secrets
    s = _source(db, sid)
    c = REGISTRY[s.kind]
    try:
        res = c.test(s.config or {}, decrypt_secrets(s.secrets_enc))
        s.auth_status = "ok"
        db.commit()
        return res
    except Exception as e:  # noqa: BLE001
        s.auth_status = "failed" if "authentication" in str(e) else s.auth_status
        db.commit()
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"[:400]}


@router.post("/integrations/{sid}/collect", status_code=202)
def collect_integration(sid: int, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    from .jobs import enqueue
    src = _source(db, sid)
    conn = REGISTRY.get(src.kind)
    if not src.enabled: raise HTTPException(409, "integration is disabled")
    if not conn or not conn.schedulable: raise HTTPException(400, "this integration is import-only")
    job = enqueue(db, "collection", sid, u.username)
    return {"status": job.status, "job_id": job.id}


class ImportIn(BaseModel):
    filename: str = Field(max_length=200)
    content: str = Field(max_length=20_000_000)


@router.post("/integrations/{sid}/import")
def import_integration(sid: int, body: ImportIn, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    _source(db, sid)
    try:
        run = collector.run_import(db, sid, body.content, body.filename, user=u.username)
    except ConnectorError as e:
        raise HTTPException(400, str(e))
    return run_row(run)


def run_row(r: CollectionRun):
    return {"id": r.id, "started": iso(r.started), "finished": iso(r.finished), "status": r.status, "trigger": r.trigger,
            "received": r.received, "processed": r.processed, "duplicates": r.duplicates, "rejected": r.rejected,
            "failed": r.failed, "error": r.error}


@router.get("/integrations/{sid}/runs")
def integration_runs(sid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    _source(db, sid)
    return [run_row(r) for r in db.query(CollectionRun).filter(CollectionRun.source_id == sid).order_by(CollectionRun.id.desc()).limit(50)]


@router.get("/integrations/{sid}/status")
def integration_status(sid: int, db: Session = Depends(get_db), _: User = Depends(current_user)):
    return source_row(_source(db, sid))


# ------------------------------------------------------------------ assistant
class AskIn(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
    context: Optional[dict] = None
    history: list[dict] = Field(default_factory=list, max_length=12)


@router.post("/assistant/query")
def assistant_query(body: AskIn, request: Request, db: Session = Depends(get_db), u: User = Depends(current_user)):
    if not limiter.allow(f"ask:{u.username}", 30):
        raise HTTPException(429, "assistant rate limit reached")
    ctx = {k: v for k, v in (body.context or {}).items() if k in ("page", "asset_id", "finding_id", "investigation_id") and isinstance(v, (int, str))}
    res = assistant_mod.answer(db, body.question, ctx, [h for h in body.history if isinstance(h, dict)][-8:])
    res["suggestions"] = assistant_mod.suggestions(db, ctx)
    audit(db, u, "assistant.query", "", {"q": body.question[:200], "mode": res.get("mode")}, request)
    return res


@router.get("/assistant/suggestions")
def assistant_suggestions(asset_id: int = 0, db: Session = Depends(get_db), _: User = Depends(current_user)):
    return assistant_mod.suggestions(db, {"asset_id": asset_id} if asset_id else None)


# ------------------------------------------------------------------ overview / reports
@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return services.overview(db)


@router.get("/reports")
def list_reports(_: User = Depends(current_user)):
    return [{"kind": k, "title": v} for k, v in services.REPORTS.items()]


@router.get("/reports/{kind}")
def get_report(kind: str, format: Literal["json", "csv", "html"] = "json", db: Session = Depends(get_db), u: User = Depends(current_user)):
    try:
        rep = services.build_report(db, kind)
    except KeyError:
        raise HTTPException(404, "unknown report")
    audit(db, u, "report.generate", kind, {"format": format})
    if format == "csv":
        return Response(services.report_csv(rep), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="deepsight-{kind}.csv"'})
    if format == "html":
        return Response(services.report_html(rep), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="deepsight-{kind}.html"'})
    return rep


# ------------------------------------------------------------------ administration / system
@router.get("/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000), user: str = "", action: str = "", db: Session = Depends(get_db),
              _: User = Depends(require(*ADMIN))):
    q = db.query(AuditLog)
    if user:
        q = q.filter(AuditLog.user == user)
    if action:
        q = q.filter(AuditLog.action.like(f"{action}%"))
    return [{"id": a.id, "ts": iso(a.ts), "user": a.user, "action": a.action, "resource": a.resource, "detail": a.detail, "ip": a.ip}
            for a in q.order_by(AuditLog.id.desc()).limit(limit)]


@router.get("/system/status")
def system_status(request: Request, db: Session = Depends(get_db), _: User = Depends(require("administrator", "manager"))):
    lat = sorted(pipeline.LATENCY)
    pct = (lambda p: round(lat[min(len(lat) - 1, int(len(lat) * p))] * 1000, 1)) if lat else (lambda p: None)
    since = now() - timedelta(hours=24)
    runs = db.query(CollectionRun).filter(CollectionRun.started >= since, CollectionRun.status != "running").all()
    ok = sum(1 for r in runs if r.status == "ok")
    by_status = dict(db.query(Observation.status, func.count(Observation.id)).group_by(Observation.status).all())
    sched = db.get(Setting, "scheduler_heartbeat")
    return {"api": "ok", "database": "ok", "database_engine": "postgresql" if "postgres" in settings.database_url else "sqlite",
            "collection_success_rate_24h": round(ok / len(runs), 3) if runs else None, "collections_24h": len(runs),
            "observations_by_status": by_status, "failed_observations": by_status.get("failed", 0),
            "processing_latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "samples": len(lat)},
            "model_errors": sum(m["errors"] or 0 for m in ml.model_status(db)),
            "scheduler_heartbeat": sched.value if sched else None, "assistant_mode": "llm" if settings.anthropic_api_key else "evidence",
            "integrations": {"total": db.query(Source).count(),
                             "unhealthy": db.query(Source).filter(Source.enabled.is_(True), Source.status == "error").count()},
            "ephemeral_secret_key": settings.ephemeral_secret}


@router.post("/system/lifecycle-sweep")
def lifecycle(db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    return state.lifecycle_sweep(db, settings.inactive_after_hours)


@router.post("/system/reassess")
def reassess(db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    return {"assets": risk.reassess_all(db, force=True)}




class FreshnessSetting(BaseModel):
    hours: float = Field(gt=0, le=8760)


@router.get("/settings/assessment-age")
def assessment_age(db: Session = Depends(get_db), _: User = Depends(current_user)):
    from .freshness import age_threshold
    return {"hours": age_threshold(db)}


@router.put("/settings/assessment-age")
def set_assessment_age(body: FreshnessSetting, db: Session = Depends(get_db), u: User = Depends(require(*ADMIN))):
    row = db.get(Setting, "assessment_age_hours")
    if row:
        row.value = body.hours
    else:
        db.add(Setting(key="assessment_age_hours", value=body.hours))
    db.commit()
    audit(db, u, "settings.assessment_age", detail={"hours": body.hours})
    return {"hours": body.hours}


@router.get("/work-queue")
def work_queue(q: str = "", owner: str = "", state: str = "", limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(get_db), _: User = Depends(current_user)):
    from .workqueue import queue
    return queue(db, q, owner, state, limit, offset)


@router.get("/search")
def global_search(q: str = Query(min_length=1, max_length=256), db: Session = Depends(get_db), _: User = Depends(current_user)):
    from .workqueue import search
    return search(db, q)


class SavedFilterIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    filters: dict[str, str]


def _filter_key(username):
    import hashlib
    return "saved_filters:" + hashlib.sha256(username.encode()).hexdigest()[:32]


@router.get("/saved-filters")
def saved_filters(db: Session = Depends(get_db), u: User = Depends(current_user)):
    row = db.get(Setting, _filter_key(u.username))
    return row.value if row else {}


@router.put("/saved-filters")
def save_filter(body: SavedFilterIn, db: Session = Depends(get_db), u: User = Depends(current_user)):
    if not set(body.filters) <= {"q", "owner", "state"}:
        raise HTTPException(422, "Supported filters: q, owner, state")
    key = _filter_key(u.username)
    row = db.get(Setting, key)
    values = dict(row.value) if row else {}
    values[body.name] = body.filters
    if len(values) > 50:
        raise HTTPException(422, "Saved filter limit reached")
    if row: row.value = values
    else: db.add(Setting(key=key, value=values))
    db.commit()
    return values


@router.delete("/saved-filters/{name}")
def delete_filter(name: str, db: Session = Depends(get_db), u: User = Depends(current_user)):
    row = db.get(Setting, _filter_key(u.username))
    if row:
        row.value = {k:v for k,v in row.value.items() if k != name}
        db.commit()
    return {"deleted": name}


class BulkTriageIn(BaseModel):
    finding_ids: list[int] = Field(min_length=1, max_length=200)
    workflow: TriageIn


@router.post("/bulk-triage")
def bulk_triage(body: BulkTriageIn, db: Session = Depends(get_db), u: User = Depends(require(*ANALYST))):
    from . import remediation
    ids = sorted(set(body.finding_ids))
    rows = db.query(Finding).filter(Finding.id.in_(ids)).all()
    if len(rows) != len(ids): raise HTTPException(404, "At least one finding was not found; nothing changed")
    try:
        for f in rows: remediation.update(db, f, body.workflow.model_dump(exclude_unset=True), u.username)
    except (ValueError, TypeError) as e:
        db.rollback()
        raise HTTPException(422, str(e)) from e
    db.commit()
    audit(db, u, "finding.bulk_triage", detail={"finding_ids":ids})
    return {"updated":len(rows)}


@router.post("/ml/evaluate")
def evaluate_models(db: Session = Depends(get_db), _: User = Depends(require(*ANALYST))):
    from .evaluation import evaluate
    return evaluate(db)


@router.get("/effectiveness")
def effectiveness(db: Session = Depends(get_db), _: User = Depends(current_user)):
    from .evaluation import effectiveness
    return effectiveness(db)


class EPSSRecord(BaseModel):
    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    epss: float = Field(ge=0, le=1)
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


@router.post("/intelligence/epss")
def import_epss(body: list[EPSSRecord], db: Session = Depends(get_db), _: User = Depends(require(*ADMIN))):
    from .util import parse_ts
    for item in body:
        if parse_ts(item.date) > now(): raise HTTPException(422, "EPSS date cannot be in the future")
        key = "epss:" + item.cve
        row = db.get(Setting, key)
        if row: row.value = item.model_dump()
        else: db.add(Setting(key=key, value=item.model_dump()))
    db.commit()
    risk.reassess_all(db)
    return {"imported": len(body), "basis": "ML-predicted by FIRST EPSS; not confirmed exploitation"}


@router.post("/intelligence/nvd-import")
def nvd_import(body: dict, db: Session = Depends(get_db), _: User = Depends(require(*ADMIN))):
    result = intel.import_nvd_json(db, body)
    result["new_findings"] = intel.rematch_all(db)
    risk.reassess_all(db)
    return result


@router.get("/coverage/cmdb")
def cmdb_reconciliation(db: Session = Depends(get_db), _: User = Depends(current_user)):
    from .coverage import reconciliation
    return reconciliation(db)


@router.get("/coverage/attack-paths")
def attack_paths(db: Session = Depends(get_db), _: User = Depends(current_user)):
    from .coverage import attack_paths
    return attack_paths(db)


@router.post("/webhooks/dispatch")
def dispatch_webhooks(db: Session = Depends(get_db), _: User = Depends(require(*ADMIN))):
    from .notifications import dispatch
    return dispatch(db)


@router.get("/webhooks/deliveries")
def webhook_deliveries(db: Session = Depends(get_db), _: User = Depends(require(*ADMIN))):
    from .models import WebhookDelivery
    return [{"id":r.id,"event_key":r.event_key,"status":r.status,"attempts":r.attempts,"error":r.error} for r in db.query(WebhookDelivery).order_by(WebhookDelivery.id.desc()).limit(100)]


@router.get("/jobs")
def background_jobs(db: Session = Depends(get_db), _: User = Depends(require(*ADMIN))):
    from .models import BackgroundJob
    return [{"id":j.id,"kind":j.kind,"status":j.status,"attempts":j.attempts,"heartbeat":iso(j.heartbeat),"error":j.error} for j in db.query(BackgroundJob).order_by(BackgroundJob.id.desc()).limit(100)]


@router.get("/metrics", response_class=Response)
def prometheus_metrics(db: Session = Depends(get_db), _: User = Depends(current_user)):
    from .observability import prometheus
    return Response(prometheus(db), media_type="text/plain; version=0.0.4")
