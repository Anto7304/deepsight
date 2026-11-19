"""Asset Intelligence: evidence-based, traceable and reversible identity resolution.

Outcomes: confirmed | probable | unresolved | potentially_separate | new.
Similar identifiers alone never trigger a merge: confirmation needs a strong identifier
(MAC / cloud id / device id / serial) or >=2 independent weak evidence kinds with high
model confidence, and a hard conflict on a single-valued strong identifier blocks matching.
"""
import ipaddress
import re
from difflib import SequenceMatcher

from sqlalchemy.orm import Session

from ..models import (Anomaly, Asset, AssetIdentifier, Change, Finding, IdentityDecision, Observation,
                      Relationship, RiskAssessment, Service, Software, IdentityBlock)
from ..normalize import STRONG_KINDS
from ..util import now

HARD_KINDS = ("cloud_id", "device_id", "serial")  # single-valued: difference => different asset
FEATURES = ["mac_match", "cloud_match", "device_match", "serial_match", "strong_any", "hostname_exact",
            "hostname_short", "hostname_sim", "hostname_digit_diff", "hostname_conflict", "ip_match_active",
            "ip_match_hist", "same_subnet", "os_match", "os_conflict", "mac_disjoint", "n_kinds"]


def _short(h):
    return h.split(".")[0]


def _digit_diff(a, b):
    return a != b and re.sub(r"\d+", "#", a) == re.sub(r"\d+", "#", b)


def _subnet(ip):
    try:
        o = ipaddress.ip_address(ip)
        if o.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except ValueError:
        return None


def pair_features(obs_ids: dict, obs_os: str | None, cand: dict, cand_os: str | None):
    """cand = {kind: {"all": set, "active": set}}. Returns (features dict, hard_conflicts[], evidence[])."""
    o = {k: set(v) for k, v in obs_ids.items()}
    c_all = {k: set(v["all"]) for k, v in cand.items()}
    c_act = {k: set(v["active"]) for k, v in cand.items()}
    ev, hard = [], []

    def inter(kind):
        return o.get(kind, set()) & c_all.get(kind, set())

    f = {name: 0.0 for name in FEATURES}
    for kind, feat in (("mac", "mac_match"), ("cloud_id", "cloud_match"), ("device_id", "device_match"),
                       ("serial", "serial_match")):
        m = inter(kind)
        if m:
            f[feat] = 1.0
            ev.append(f"{kind} match: {', '.join(sorted(m))}")
    f["strong_any"] = 1.0 if any(f[x] for x in ("mac_match", "cloud_match", "device_match", "serial_match")) else 0.0

    for kind in HARD_KINDS:
        if o.get(kind) and c_all.get(kind) and not inter(kind):
            hard.append(f"{kind} differs ({', '.join(sorted(o[kind]))} vs {', '.join(sorted(c_all[kind]))})")
    if o.get("mac") and c_all.get("mac") and not inter("mac"):
        f["mac_disjoint"] = 1.0
        ev.append("MACs present on both sides but disjoint (possible multi-NIC or different device)")

    oh, ch = o.get("hostname", set()), c_all.get("hostname", set())
    if oh and ch:
        if oh & ch:
            f["hostname_exact"] = 1.0
            ev.append(f"hostname exact: {', '.join(sorted(oh & ch))}")
        elif {_short(x) for x in oh} & {_short(x) for x in ch}:
            f["hostname_short"] = 1.0
            ev.append("hostname matches on short name (different domain suffix)")
        best = max(SequenceMatcher(None, a, b).ratio() for a in oh for b in ch)
        f["hostname_sim"] = round(best, 3)
        if any(_digit_diff(_short(a), _short(b)) for a in oh for b in ch):
            f["hostname_digit_diff"] = 1.0
            ev.append("hostnames differ only by digits (likely sibling hosts, not the same host)")
        if not f["hostname_exact"] and not f["hostname_short"] and best < 0.7:
            f["hostname_conflict"] = 1.0
            ev.append("hostnames present on both sides and dissimilar")

    oi = o.get("ip", set())
    if oi & c_act.get("ip", set()):
        f["ip_match_active"] = 1.0
        ev.append(f"IP currently assigned to asset: {', '.join(sorted(oi & c_act['ip']))}")
    elif oi & c_all.get("ip", set()):
        f["ip_match_hist"] = 1.0
        ev.append(f"IP historically associated with asset: {', '.join(sorted(oi & c_all['ip']))}")
    elif oi and c_all.get("ip") and {_subnet(i) for i in oi} & {_subnet(i) for i in c_all["ip"]}:
        f["same_subnet"] = 1.0

    if obs_os and cand_os:
        if obs_os == cand_os:
            f["os_match"] = 1.0
        else:
            f["os_conflict"] = 1.0
            ev.append(f"OS family differs ({obs_os} vs {cand_os})")
    kinds = sum(1 for k in ("strong_any", "hostname_exact", "hostname_short", "ip_match_active", "ip_match_hist")
                if f[k])
    f["n_kinds"] = float(kinds)
    return f, hard, ev


def vec(f: dict):
    return [f[k] for k in FEATURES]


def _asset_ident_map(db: Session, asset_ids):
    out = {a: {} for a in asset_ids}
    if not asset_ids:
        return out
    for r in db.query(AssetIdentifier).filter(AssetIdentifier.asset_id.in_(asset_ids)).all():
        d = out[r.asset_id].setdefault(r.kind, {"all": set(), "active": set()})
        d["all"].add(r.value)
        if r.active:
            d["active"].add(r.value)
    return out


def find_candidates(db: Session, ids: dict) -> set:
    cands = set()
    for kind, values in ids.items():
        if not values:
            continue
        rows = db.query(AssetIdentifier.asset_id).filter(AssetIdentifier.kind == kind,
                                                         AssetIdentifier.value.in_(values)).all()
        cands |= {r[0] for r in rows}
    short_names = {_short(h) for h in ids.get("hostname", [])}
    if short_names:
        cands |= {r[0] for r in db.query(IdentityBlock.asset_id).filter(IdentityBlock.kind == "hostname_short", IdentityBlock.value.in_(short_names))}
    if cands:
        live = {a.id for a in db.query(Asset.id).filter(Asset.id.in_(cands), Asset.merged_into.is_(None)).all()}
        cands &= live
    return cands


def _rejected_pairs(db: Session):
    rows = db.query(IdentityDecision.asset_id, IdentityDecision.candidate_asset_id).filter(
        IdentityDecision.status.in_(["rejected", "reverted"]), IdentityDecision.candidate_asset_id.isnot(None)).all()
    s = set()
    for a, b in rows:
        s.add(frozenset((a, b)))
    return s


def _pending_links(db: Session):
    rows = db.query(IdentityDecision.asset_id, IdentityDecision.candidate_asset_id).filter(
        IdentityDecision.status == "pending", IdentityDecision.candidate_asset_id.isnot(None)).all()
    return {frozenset((a, b)) for a, b in rows}


def resolve(db: Session, ids: dict, os_family: str | None):
    """Return dict: outcome, asset_id (existing or None), candidate_id, confidence, evidence[], model_version."""
    from .ml import entity_model
    em = entity_model()
    cands = find_candidates(db, ids)
    base = {"outcome": "new", "asset_id": None, "candidate_id": None, "confidence": 0.0, "evidence": [],
            "model_version": em.version}
    if not cands:
        base["evidence"] = ["no existing asset shares any identifier"]
        return base
    cmap = _asset_ident_map(db, list(cands))
    oss = {a.id: a.os_family for a in db.query(Asset).filter(Asset.id.in_(cands)).all()}
    rejected = _rejected_pairs(db)
    scored, separate = [], []
    for aid in cands:
        f, hard, ev = pair_features(ids, os_family, cmap[aid], oss.get(aid))
        if hard:
            if f["hostname_exact"] or f["ip_match_active"] or f["ip_match_hist"]:
                separate.append({"asset_id": aid, "evidence": ev + ["hard conflict: " + h for h in hard]})
            continue
        p = em.proba(vec(f))
        scored.append({"asset_id": aid, "p": p, "f": f, "ev": ev})
    scored.sort(key=lambda x: -x["p"])
    pend = _pending_links(db)

    if not scored:
        base["evidence"] = ["no non-conflicting candidate"]
        if separate:
            base.update(outcome="potentially_separate", candidate_id=separate[0]["asset_id"],
                        evidence=separate[0]["evidence"], confidence=0.0)
        return base

    best = scored[0]
    if len(scored) > 1:
        second = scored[1]
        close = second["p"] >= 0.5 and best["p"] - second["p"] <= 0.10
        pair_ab = frozenset((best["asset_id"], second["asset_id"]))
        if close and pair_ab not in pend and pair_ab not in rejected:
            return {"outcome": "probable", "asset_id": None, "candidate_id": best["asset_id"],
                    "confidence": round(best["p"], 3),
                    "evidence": best["ev"] + [f"ambiguous: asset {second['asset_id']} scores "
                                              f"{second['p']:.2f} vs {best['p']:.2f}"],
                    "model_version": em.version}
    f, p = best["f"], best["p"]
    strong = f["strong_any"] >= 1
    weak_ok = (f["n_kinds"] >= 2 and f["hostname_digit_diff"] == 0 and f["os_conflict"] == 0
               and (f["hostname_exact"] or f["hostname_short"]))
    if strong and p >= 0.85:
        outcome = "confirmed"
    elif (not strong) and weak_ok and p >= 0.90:
        outcome = "confirmed"
    elif p >= 0.5:
        outcome = "probable"
    else:
        outcome = "unresolved"
    return {"outcome": outcome, "asset_id": best["asset_id"] if outcome == "confirmed" else None,
            "candidate_id": best["asset_id"], "confidence": round(p, 3), "evidence": best["ev"],
            "model_version": em.version, "scored": scored}


# ----------------------------------------------------------------------------------------
# Merge / revert (analyst-driven identity decisions)

def _ids_of(q):
    return [r.id for r in q]


def _fill_config(existing, incoming):
    """Keep established values while carrying missing inventory metadata into a merge."""
    from copy import deepcopy
    result = deepcopy(existing or {})
    for key, value in (incoming or {}).items():
        if key not in result or result[key] is None or result[key] == "":
            result[key] = deepcopy(value)
        elif isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _fill_config(result[key], value)
    return result


def merge_assets(db: Session, keep_id: int, drop_id: int, decision: IdentityDecision, user: str):
    from copy import deepcopy
    keep, drop = db.get(Asset, keep_id), db.get(Asset, drop_id)
    if not keep or not drop or keep.id == drop.id or drop.merged_into:
        raise ValueError("invalid merge")
    snap = {"drop_state": {"status": drop.status, "identity_status": drop.identity_status,
                           "identity_confidence": drop.identity_confidence},
            "keep_state": {"identity_status": keep.identity_status, "identity_confidence": keep.identity_confidence,
                           "status": keep.status}}
    profile_fields = ("owner", "os", "os_family", "type", "config", "tags", "criticality", "criticality_source")
    snap["keep_profile"] = {field: deepcopy(getattr(keep, field)) for field in profile_fields}
    for field in ("owner", "os", "os_family"):
        if not getattr(keep, field) and getattr(drop, field):
            setattr(keep, field, getattr(drop, field))
    if keep.type in (None, "unknown") and drop.type not in (None, "unknown"):
        keep.type = drop.type
    keep.config = _fill_config(keep.config, drop.config)
    keep.tags = list(dict.fromkeys([*(keep.tags or []), *(drop.tags or [])]))[:30]
    if keep.criticality_source in (None, "default") and drop.criticality_source in ("source", "analyst"):
        keep.criticality, keep.criticality_source = drop.criticality, drop.criticality_source
    snap["merged_profile"] = {field: deepcopy(getattr(keep, field)) for field in profile_fields}
    models = {"identifiers": AssetIdentifier, "observations": Observation, "services": Service,
              "software": Software, "findings": Finding, "changes": Change, "anomalies": Anomaly,
              "risk": RiskAssessment}
    for key, M in models.items():
        rows = db.query(M).filter(M.asset_id == drop_id).all()
        snap[key] = [r.id for r in rows]
        for r in rows:
            r.asset_id = keep_id
    rel_src = db.query(Relationship).filter(Relationship.src_id == drop_id).all()
    rel_dst = db.query(Relationship).filter(Relationship.dst_id == drop_id).all()
    snap["rel_src"], snap["rel_dst"] = [r.id for r in rel_src], [r.id for r in rel_dst]
    for r in rel_src:
        r.src_id = keep_id
    for r in rel_dst:
        r.dst_id = keep_id
    # de-duplicate services / findings that now collide
    seen = {(s.port, s.proto) for s in db.query(Service).filter(
        Service.asset_id == keep_id, Service.active.is_(True), ~Service.id.in_(snap["services"] or [0])).all()}
    deact_s = []
    for sid in snap["services"]:
        s = db.get(Service, sid)
        if s.active and (s.port, s.proto) in seen:
            s.active = False
            deact_s.append(sid)
        elif s.active:
            seen.add((s.port, s.proto))
    snap["deactivated_services"] = deact_s
    fseen = {f.cve_id for f in db.query(Finding).filter(
        Finding.asset_id == keep_id, Finding.status == "open", ~Finding.id.in_(snap["findings"] or [0])).all()}
    deact_f = []
    for fid in snap["findings"]:
        f = db.get(Finding, fid)
        if f.status == "open" and f.cve_id in fseen:
            f.status = "superseded"
            f.resolved_at = None
            f.evidence = {**(f.evidence or {}), "merged_duplicate": True}
            deact_f.append(fid)
        elif f.status == "open":
            fseen.add(f.cve_id)
    snap["deactivated_findings"] = deact_f
    drop.merged_into = keep_id
    drop.status = "merged"
    keep.first_seen = min(keep.first_seen, drop.first_seen)
    keep.last_seen = max(keep.last_seen, drop.last_seen)
    if keep.identity_status in ("unresolved", "probable"):
        keep.identity_status = "confirmed"
    keep.identity_confidence = max(keep.identity_confidence or 0, decision.confidence or 0)
    db.add(Change(asset_id=keep_id, ts=now(), kind="identity_merged",
                  summary=f"Asset {drop_id} merged into this asset by {user}",
                  detail={"dropped": drop_id, "decision": decision.id}))
    decision.merge_snapshot = snap
    db.flush()
    refresh_blocks(db, keep_id)
    refresh_blocks(db, drop_id)
    return snap


def revert_merge(db: Session, decision: IdentityDecision, user: str):
    from copy import deepcopy
    snap = decision.merge_snapshot
    if not snap:
        raise ValueError("decision has no merge snapshot")
    keep_id, drop_id = decision.candidate_asset_id, decision.asset_id
    drop, keep = db.get(Asset, drop_id), db.get(Asset, keep_id)
    if not drop or drop.merged_into != keep_id:
        raise ValueError("assets are no longer in merged state")
    models = {"identifiers": AssetIdentifier, "observations": Observation, "services": Service,
              "software": Software, "findings": Finding, "changes": Change, "anomalies": Anomaly,
              "risk": RiskAssessment}
    for key, M in models.items():
        for rid in snap.get(key, []):
            r = db.get(M, rid)
            if r:
                r.asset_id = drop_id
    for rid in snap.get("rel_src", []):
        r = db.get(Relationship, rid)
        if r:
            r.src_id = drop_id
    for rid in snap.get("rel_dst", []):
        r = db.get(Relationship, rid)
        if r:
            r.dst_id = drop_id
    for sid in snap.get("deactivated_services", []):
        s = db.get(Service, sid)
        if s:
            s.active = True
    for fid in snap.get("deactivated_findings", []):
        f = db.get(Finding, fid)
        if f:
            f.status, f.resolved_at = "open", None
            ev = dict(f.evidence or {})
            ev.pop("merged_duplicate", None)
            f.evidence = ev
    drop.merged_into = None
    ds = snap["drop_state"]
    drop.status, drop.identity_status, drop.identity_confidence = ds["status"], ds["identity_status"], \
        ds["identity_confidence"]
    ks = snap["keep_state"]
    keep.identity_status, keep.identity_confidence = ks["identity_status"], ks["identity_confidence"]
    for field, before in snap.get("keep_profile", {}).items():
        # Do not discard profile edits or newer observations recorded after the merge.
        merged = snap.get("merged_profile", {}).get(field)
        if before != merged and getattr(keep, field) == merged:
            setattr(keep, field, deepcopy(before))
    db.add(Change(asset_id=keep_id, ts=now(), kind="identity_unmerged",
                  summary=f"Merge of asset {drop_id} reverted by {user}", detail={"restored": drop_id}))
    decision.status = "reverted"
    decision.decided_by, decision.decided_at = user, now()
    db.flush()
    refresh_blocks(db, keep_id)
    refresh_blocks(db, drop_id)


def refresh_blocks(db,asset_id):
    values={v.split('.')[0] for (v,) in db.query(AssetIdentifier.value).filter(AssetIdentifier.asset_id==asset_id,AssetIdentifier.kind=='hostname')}
    existing={r.value:r for r in db.query(IdentityBlock).filter(IdentityBlock.asset_id==asset_id)}
    for value in values-existing.keys():db.add(IdentityBlock(asset_id=asset_id,kind='hostname_short',value=value))
    for value in existing.keys()-values:db.delete(existing[value])
    db.flush()
