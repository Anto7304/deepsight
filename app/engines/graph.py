"""Relationship intelligence on a graph-capable model (relationships table + NetworkX traversal)."""
import networkx as nx
from sqlalchemy.orm import Session

from ..models import Asset, Finding, Relationship, Service

# edge direction: src --type--> dst
DEPENDENCY_TYPES = {"depends_on", "connects_to", "runs_on", "belongs_to"}


def build_graph(db: Session, active_only=True) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    q = db.query(Relationship)
    if active_only:
        q = q.filter(Relationship.valid_to.is_(None))
    for r in q.all():
        g.add_edge(r.src_id, r.dst_id, key=r.id, type=r.type, basis=r.basis, confidence=r.confidence)
    return g


def _bfs(g, start, forward: bool, types, max_depth=4):
    seen, frontier, depth = {}, [start], 0
    if start not in g:  # asset with no relationships is not a graph node
        return seen
    while frontier and depth < max_depth:
        depth += 1
        nxt = []
        for n in frontier:
            edges = g.out_edges(n, data=True) if forward else g.in_edges(n, data=True)
            for u, v, d in edges:
                other = v if forward else u
                if d["type"] in types and other != start and other not in seen:
                    seen[other] = {"depth": depth, "via": d["type"], "basis": d["basis"], "confidence": d["confidence"]}
                    nxt.append(other)
        frontier = nxt
    return seen


def impact(db: Session, asset_id: int, g=None):
    """If this asset were compromised/disrupted, what is connected to it?"""
    g = g or build_graph(db)
    hosted = _bfs(g, asset_id, True, {"hosts"})
    dependents = _bfs(g, asset_id, False, DEPENDENCY_TYPES)           # things that depend on this
    reachable = _bfs(g, asset_id, True, DEPENDENCY_TYPES)             # things this one depends on/talks to
    ids = set(hosted) | set(dependents) | set(reachable)
    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(ids or {0}), Asset.merged_into.is_(None)).all()}
    vulns = {}
    for aid, cnt in db.query(Finding.asset_id, Finding.id).filter(Finding.asset_id.in_(ids or {0}),
                                                                   Finding.status == "open").all():
        vulns[aid] = vulns.get(aid, 0) + 1

    def pack(d):
        out = []
        for aid, meta in sorted(d.items(), key=lambda kv: kv[1]["depth"]):
            a = assets.get(aid)
            if a:
                out.append({"asset_id": aid, "name": a.name, "type": a.type, "criticality": a.criticality,
                            "risk_level": a.risk_level, "open_findings": vulns.get(aid, 0), **meta})
        return out

    return {"asset_id": asset_id, "hosted_on_this": pack(hosted), "dependents": pack(dependents),
            "reachable_dependencies": pack(reachable)}


def blast_radius_norm(db: Session, asset_id: int, g=None) -> float:
    """0..1 measure of how much criticality depends on this asset (dependents + hosted)."""
    g = g or build_graph(db)
    if asset_id not in g:
        return 0.0
    hosted = _bfs(g, asset_id, True, {"hosts"})
    dep = _bfs(g, asset_id, False, DEPENDENCY_TYPES)
    ids = set(hosted) | set(dep)
    if not ids:
        return 0.0
    crit = sum(c for (c,) in db.query(Asset.criticality).filter(Asset.id.in_(ids)).all())
    return min(1.0, crit / 15.0)  # saturates when ~5 mid-criticality assets depend on it


def neighbors(db: Session, asset_id: int):
    rels = db.query(Relationship).filter((Relationship.src_id == asset_id) | (Relationship.dst_id == asset_id)).order_by(
        Relationship.valid_from.desc()).all()
    ids = {r.src_id for r in rels} | {r.dst_id for r in rels}
    names = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(ids or {0})).all()}
    out = []
    for r in rels:
        other = r.dst_id if r.src_id == asset_id else r.src_id
        o = names.get(other)
        out.append({"id": r.id, "direction": "out" if r.src_id == asset_id else "in", "type": r.type,
                    "other_id": other, "other_name": o.name if o else str(other), "other_type": o.type if o else None,
                    "basis": r.basis, "confidence": r.confidence, "valid_from": r.valid_from.isoformat() + "Z",
                    "valid_to": r.valid_to.isoformat() + "Z" if r.valid_to else None,
                    "active": r.valid_to is None})
    return out


def graph_payload(db: Session, limit=400):
    g_assets = db.query(Asset).filter(Asset.merged_into.is_(None)).order_by(Asset.risk_score.desc()).limit(limit).all()
    ids = {a.id for a in g_assets}
    rels = db.query(Relationship).filter(Relationship.valid_to.is_(None), Relationship.src_id.in_(ids),
                                         Relationship.dst_id.in_(ids)).all()
    return {"nodes": [{"id": a.id, "name": a.name, "type": a.type, "risk_level": a.risk_level,
                       "risk_score": a.risk_score, "status": a.status, "exposure": a.exposure} for a in g_assets],
            "edges": [{"id": r.id, "source": r.src_id, "target": r.dst_id, "type": r.type, "basis": r.basis,
                       "confidence": r.confidence} for r in rels]}
