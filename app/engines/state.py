"""Applies a normalized observation to an asset: identifiers, services, software, config,
relationships and lifecycle - recording every difference as a historical Change."""
from sqlalchemy.orm import Session

from ..models import Asset, AssetIdentifier, Change, Relationship, Service, Software
from ..normalize import STRONG_KINDS, ip_is_public
from ..util import now

ASSET_TYPES = {"server", "workstation", "network_device", "cloud_resource", "virtual_machine", "container",
               "application", "iot_device", "unknown"}
REL_TYPES = {"hosts", "depends_on", "connects_to", "runs_on", "belongs_to"}


def _loopback(bind):
    return bool(bind) and (bind.startswith("127.") or bind in ("::1", "localhost"))


def _add_change(db, asset_id, ts, kind, summary, detail, obs_id, out):
    c = Change(asset_id=asset_id, ts=ts, kind=kind, summary=summary[:500], detail=detail, observation_id=obs_id)
    db.add(c)
    out.append(c)
    return c


def best_name(ids: dict, attrs: dict):
    if attrs.get("name"):
        return str(attrs["name"])[:200]
    if ids.get("hostname"):
        return sorted(ids["hostname"], key=len)[0].split(".")[0]
    if ids.get("ip"):
        return ids["ip"][0]
    for k in ("cloud_id", "device_id", "serial", "mac"):
        if ids.get(k):
            return ids[k][0]
    return "unnamed"


def refresh_identity(db: Session, asset: Asset):
    rows = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == asset.id).all()
    has_strong = any(r.kind in STRONG_KINDS for r in rows)
    if has_strong and asset.identity_status in ("unresolved", "inferred"):
        asset.identity_status = "confirmed"
        asset.identity_confidence = max(asset.identity_confidence or 0, 0.9)
    host = [r.value for r in rows if r.kind == "hostname" and r.active]
    ips = [r.value for r in rows if r.kind == "ip" and r.active]
    cloud = [r.value for r in rows if r.kind == "cloud_id"]
    asset.primary_identifier = (cloud[0] if cloud else host[0] if host else ips[0] if ips else
                                (rows[0].value if rows else None))
    if host and (not asset.name or asset.name in ips or asset.name == "unnamed"):
        asset.name = host[0].split(".")[0]
    return rows


def recompute_exposure(db: Session, asset: Asset):
    ips = [r.value for r in db.query(AssetIdentifier).filter(
        AssetIdentifier.asset_id == asset.id, AssetIdentifier.kind == "ip", AssetIdentifier.active.is_(True)).all()]
    public = any(ip_is_public(i) for i in ips)
    svc_exposed = db.query(Service).filter(Service.asset_id == asset.id, Service.active.is_(True),
                                           Service.exposed.is_(True)).count() > 0
    asset.exposure = "external" if (public or svc_exposed) else "internal"
    return public


def infer_type(attrs, services, osf):
    t = attrs.get("type")
    if t in ASSET_TYPES:
        return t
    if attrs.get("container"):
        return "container"
    if osf == "network":
        return "network_device"
    if osf == "mobile":
        return "iot_device"
    if services:
        return "server"
    if osf in ("windows", "macos"):
        return "workstation"
    return "unknown"


def find_asset_by_ids(db: Session, ids: dict):
    """Find-only lookup used for relationship targets: strong identifiers first, then exact ip/hostname."""
    score = {}
    for kind, values in ids.items():
        if not values:
            continue
        rows = db.query(AssetIdentifier.asset_id).filter(AssetIdentifier.kind == kind,
                                                         AssetIdentifier.value.in_(values)).all()
        w = 3 if kind in STRONG_KINDS else 1
        for (aid,) in rows:
            score[aid] = score.get(aid, 0) + w
    if not score:
        return None
    live = {a.id for a in db.query(Asset.id).filter(Asset.id.in_(list(score)), Asset.merged_into.is_(None)).all()}
    score = {k: v for k, v in score.items() if k in live}
    if not score:
        return None
    best = max(score.values())
    top = [k for k, v in score.items() if v == best]
    return top[0] if len(top) == 1 else None


def placeholder_asset(db: Session, ids: dict, ts, type_hint=None):
    a = Asset(name=best_name(ids, {}), type=type_hint if type_hint in ASSET_TYPES else "unknown",
              status="discovered", identity_status="inferred", identity_confidence=0.3, first_seen=ts, last_seen=ts)
    db.add(a)
    db.flush()
    for kind, vals in ids.items():
        for v in vals:
            db.add(AssetIdentifier(asset_id=a.id, kind=kind, value=v, first_seen=ts, last_seen=ts))
    db.flush()
    refresh_identity(db, a)
    return a


def upsert_relationship(db, src_id, dst_id, rtype, basis, source_id, conf, ts, evidence, changes, obs_id):
    if src_id == dst_id or rtype not in REL_TYPES:
        return None
    r = db.query(Relationship).filter(Relationship.src_id == src_id, Relationship.dst_id == dst_id,
                                      Relationship.type == rtype, Relationship.valid_to.is_(None)).first()
    if r:
        r.last_seen = max(r.last_seen or ts, ts)
        r.confidence = max(r.confidence or 0, conf)
        if basis == "observed":
            r.basis = "observed"
        return r
    r = Relationship(src_id=src_id, dst_id=dst_id, type=rtype, basis=basis, source_id=source_id, confidence=conf,
                     valid_from=ts, last_seen=ts, evidence=evidence)
    db.add(r)
    dst = db.get(Asset, dst_id)
    _add_change(db, src_id, ts, "relationship_added",
                f"{rtype.replace('_', ' ')} {dst.name if dst else dst_id} ({basis}, confidence {conf:.2f})",
                {"type": rtype, "dst": dst_id, "basis": basis}, obs_id, changes)
    return r


def apply_observation(db: Session, asset: Asset, norm: dict, source_id, obs_id: int, is_new: bool):
    """Mutates asset state from the observation; returns list[Change] (excluding creation)."""
    ids, attrs, ts = norm["identifiers"], norm["attributes"], norm["observed_at"]
    changes: list[Change] = []
    record = (lambda *a, **k: None) if is_new else (lambda kind, summary, detail: _add_change(
        db, asset.id, ts, kind, summary, detail, obs_id, changes))

    # ---- identifiers
    existing = db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == asset.id).all()
    by = {(r.kind, r.value): r for r in existing}
    for kind, vals in ids.items():
        for v in vals:
            r = by.get((kind, v))
            if r:
                r.last_seen = max(r.last_seen or ts, ts)
                r.active = True
                continue
            replaced = []
            if kind == "ip" and len(vals) == 1 and source_id is not None:
                replaced = [x for x in existing if x.kind == "ip" and x.active and x.source_id == source_id
                            and x.value != v]
                for x in replaced:
                    x.active = False
                    record("identifier_changed", f"IP changed {x.value} -> {v}",
                           {"kind": "ip", "from": x.value, "to": v})
            row = AssetIdentifier(asset_id=asset.id, kind=kind, value=v, source_id=source_id, first_seen=ts,
                                  last_seen=ts, active=True)
            db.add(row)
            by[(kind, v)] = row
            existing.append(row)
            if not replaced:
                record("identifier_added", f"New {kind} identifier {v}", {"kind": kind, "value": v})
    db.flush()
    public = recompute_exposure(db, asset)

    # ---- attributes
    osf = attrs.get("os_family")
    cfg = dict(asset.config or {})
    if attrs.get("os"):
        os_text = str(attrs["os"])[:128]
        # different sources describe the same OS differently: a change is only a change for the SAME source
        by_src = dict(cfg.get("_os_by_source") or {})
        prev = by_src.get(str(source_id))
        if prev and prev != os_text:
            record("config_changed", f"OS changed {prev} -> {os_text}", {"key": "os", "from": prev, "to": os_text})
        by_src[str(source_id)] = os_text
        cfg["_os_by_source"] = by_src
        asset.os, asset.os_family = os_text, osf
    if attrs.get("owner"):
        asset.owner = str(attrs["owner"])[:128]
    if attrs.get("criticality") and asset.criticality_source != "analyst":
        try:
            asset.criticality = max(1, min(5, int(attrs["criticality"])))
            asset.criticality_source = "source"
        except (TypeError, ValueError):
            pass
    if attrs.get("tags"):
        asset.tags = sorted(set(asset.tags or []) | {str(t) for t in attrs["tags"]})
    for k, val in list((attrs.get("config") or {}).items())[:50]:
        if cfg.get(k) != val:
            if k in cfg:
                record("config_changed", f"Config '{k}' changed", {"key": k, "from": cfg.get(k), "to": val})
            cfg[k] = val
    if "software" in attrs:
        cfg["_cpes"] = sorted({c for s in attrs["software"] for c in s.get("cpes", [])})
    asset.config = cfg

    # ---- services (state diff)
    if "services" in attrs:
        seen_keys = set()
        open_ports = set(attrs.get("internet_exposed_ports") or [])
        svcs = db.query(Service).filter(Service.asset_id == asset.id).all()
        smap = {(s.port, s.proto): s for s in svcs if s.active}
        first_pop = not svcs  # first time any service is recorded for this asset = initial discovery, not a change
        rec_add = (lambda *a, **k: None) if first_pop else record
        for sv in attrs["services"]:
            key = (sv["port"], sv["proto"])
            seen_keys.add(key)
            exposed = (not _loopback(sv["bind"])) and (
                sv["exposure"] == "external" or (public and sv["exposure"] != "internal") or sv["port"] in open_ports)
            cur = smap.get(key)
            # Exposure is sticky: only observations that carry exposure evidence (explicit flag, firewall
            # port list, public IP) may change it - an internal scan says nothing about internet reachability.
            if cur and sv["exposure"] is None and not public and "internet_exposed_ports" not in attrs:
                exposed = cur.exposed
            if cur:
                cur.last_seen = max(cur.last_seen or ts, ts)
                if (sv["product"] and sv["product"] != cur.product) or (sv["version"] and sv["version"] != cur.version):
                    record("service_changed",
                           f"Service {sv['proto']}/{sv['port']} changed "
                           f"{(cur.product or cur.name or '?')} {cur.version or ''} -> "
                           f"{(sv['product'] or sv['name'] or '?')} {sv['version'] or ''}".replace("  ", " "),
                           {"port": sv["port"], "from": {"product": cur.product, "version": cur.version},
                            "to": {"product": sv["product"], "version": sv["version"]}})
                    cur.product, cur.version = sv["product"] or cur.product, sv["version"] or cur.version
                if exposed != cur.exposed:
                    record("exposure_changed", f"Service {sv['proto']}/{sv['port']} is now "
                           f"{'externally exposed' if exposed else 'not externally exposed'}",
                           {"port": sv["port"], "exposed": exposed})
                    cur.exposed = exposed
                cur.name = sv["name"] or cur.name
                cur.bind = sv["bind"] or cur.bind
            else:
                db.add(Service(asset_id=asset.id, port=sv["port"], proto=sv["proto"], name=sv["name"],
                               product=sv["product"], version=sv["version"], bind=sv["bind"], exposed=exposed,
                               source_id=source_id, first_seen=ts, last_seen=ts))
                label = " ".join(x for x in (sv["product"] or sv["name"], sv["version"]) if x)
                rec_add("service_added",
                       f"New service {sv['proto']}/{sv['port']}{' (' + label + ')' if label else ''}"
                       f"{' exposed externally' if exposed else ''}",
                       {"port": sv["port"], "proto": sv["proto"], "name": sv["name"], "product": sv["product"],
                        "version": sv["version"], "exposed": exposed})
        if first_pop and attrs["services"] and not is_new:
            record("services_discovered", f"{len(attrs['services'])} service(s) discovered on first scan",
                   {"ports": [x["port"] for x in attrs["services"]]})
        if attrs.get("services_snapshot"):
            for key, s in smap.items():
                if key not in seen_keys and s.source_id == source_id:
                    s.active = False
                    record("service_removed", f"Service {s.proto}/{s.port} no longer observed",
                           {"port": s.port, "proto": s.proto})
        db.flush()
        recompute_exposure(db, asset)

    # ---- software inventory
    if "software" in attrs:
        have = {s.product.lower(): s for s in db.query(Software).filter(
            Software.asset_id == asset.id, Software.active.is_(True)).all()}
        for sw in attrs["software"]:
            cur = have.get(sw["product"].lower())
            if cur:
                cur.last_seen = max(cur.last_seen or ts, ts)
                if sw["version"] and sw["version"] != cur.version:
                    record("software_changed", f"{sw['product']} {cur.version} -> {sw['version']}",
                           {"product": sw["product"], "from": cur.version, "to": sw["version"]})
                    cur.version = sw["version"]
            else:
                db.add(Software(asset_id=asset.id, product=sw["product"], version=sw["version"],
                                source_id=source_id, first_seen=ts, last_seen=ts))
                record("software_added", f"Software {sw['product']} {sw['version'] or ''}".strip(),
                       {"product": sw["product"], "version": sw["version"]})

    # ---- type
    if asset.type in (None, "unknown") or is_new:
        svc_exist = db.query(Service).filter(Service.asset_id == asset.id).count() > 0
        t = infer_type(attrs, svc_exist, asset.os_family)
        if t != "unknown" or asset.type is None:
            asset.type = t

    # ---- relationships
    for rel in attrs.get("relations") or []:
        _apply_relation(db, asset, rel, source_id, ts, changes, obs_id, attrs)
    for conn in attrs.get("connections") or []:
        peer = conn.get("peer") if isinstance(conn, dict) else None
        if not peer:
            continue
        from ..normalize import normalize_identifiers
        pids, _ = normalize_identifiers(peer)
        if not pids:
            continue
        dst = find_asset_by_ids(db, pids)
        if dst is None:
            continue
        out = conn.get("direction", "out") == "out"
        s, d = (asset.id, dst) if out else (dst, asset.id)
        upsert_relationship(db, s, d, "connects_to", "inferred", source_id, 0.6, ts,
                            {"port": conn.get("port"), "from_connection_telemetry": True}, changes, obs_id)

    # ---- reachability / lifecycle
    reachable = attrs.get("reachable", True)
    prev_status = asset.status
    if reachable is False:
        asset.status = "unreachable"
    elif is_new:
        asset.status = "discovered"
    else:
        asset.status = "changed" if changes else "active"
    if prev_status != asset.status and not is_new and (
            asset.status == "unreachable" or prev_status in ("unreachable", "inactive")):
        record("status_changed", f"Lifecycle {prev_status} -> {asset.status}", {"from": prev_status, "to": asset.status})
    if reachable is not False:
        asset.last_seen = max(asset.last_seen or ts, ts)
    refresh_identity(db, asset)
    db.flush()
    return changes


def _apply_relation(db, asset, rel, source_id, ts, changes, obs_id, attrs):
    if not isinstance(rel, dict) or not rel.get("target"):
        return
    tid = find_asset_by_ids(db, rel["target"])
    if tid is None:
        ph = placeholder_asset(db, rel["target"], ts, rel.get("target_type"))
        tid = ph.id
    out = rel.get("direction", "out") == "out"
    s, d = (asset.id, tid) if out else (tid, asset.id)
    upsert_relationship(db, s, d, rel.get("type", "connects_to"), "observed", source_id,
                        float(rel.get("confidence", 1.0)), ts, {"reported_by_source": source_id}, changes, obs_id)


def lifecycle_sweep(db: Session, inactive_after_hours: int = 48):
    """Mark assets not observed recently as inactive; close stale inferred relationships."""
    from datetime import timedelta
    t = now()
    cutoff = t - timedelta(hours=inactive_after_hours)
    n = 0
    for a in db.query(Asset).filter(Asset.merged_into.is_(None), Asset.status.in_(["active", "changed", "discovered"]),
                                    Asset.last_seen < cutoff).all():
        db.add(Change(asset_id=a.id, ts=t, kind="status_changed",
                      summary=f"Lifecycle {a.status} -> inactive (not observed for {inactive_after_hours}h)",
                      detail={"from": a.status, "to": "inactive"}))
        a.status = "inactive"
        n += 1
    stale = t - timedelta(days=7)
    m = 0
    for r in db.query(Relationship).filter(Relationship.valid_to.is_(None), Relationship.basis == "inferred",
                                           Relationship.last_seen < stale).all():
        r.valid_to = t
        m += 1
    db.commit()
    return {"inactivated": n, "relationships_closed": m}
