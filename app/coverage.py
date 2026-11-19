"""NVD CPE applicability and infrastructure coverage reconciliation."""
import fnmatch
import re
from collections import deque
from .models import Asset, Finding, Observation, Relationship, Source, Vulnerability
from .util import iso, now


def cpe_match(rule, inventory):
    from .engines.intel import version_in
    parts=re.split(r"(?<!\\):", rule.get('criteria',''))
    if len(parts)!=13 or parts[:2]!=['cpe','2.3']:return False
    for cpe in inventory:
        observed=re.split(r"(?<!\\):",cpe)
        if len(observed)!=13:continue
        if not all(p=='*' or (v not in ('*','-') and fnmatch.fnmatchcase(v.lower(),p.lower())) or p==v
                   for i,(p,v) in enumerate(zip(parts[2:],observed[2:]),2) if i!=5):continue
        version=observed[5]
        if parts[5]!='*' and parts[5]!=version:continue
        bounds={key:rule[k] for k,key in [('versionStartIncluding','min_inclusive'),('versionEndExcluding','max_exclusive'),('versionEndIncluding','max_inclusive')] if k in rule}
        if bounds and not version_in(bounds,version):continue
        if 'versionStartExcluding' in rule:
            from .engines.intel import _cmp, parse_version
            if parse_version(version) is None or _cmp(parse_version(version),parse_version(rule['versionStartExcluding']))<=0:continue
        return True
    return False


def _configuration_state(node, inventory):
    if node.get('negate'):
        return False, False
    children = [_configuration_state(n, inventory) for n in node.get('nodes', [])]
    children += [(cpe_match(r, inventory), r.get('vulnerable', True) and cpe_match(r, inventory))
                 for r in node.get('cpeMatch', [])]
    if not children:
        return False, False
    if node.get('operator', 'OR') == 'AND':
        applicable = all(x[0] for x in children)
        return applicable, applicable and any(x[1] for x in children)
    return any(x[0] for x in children), any(x[0] and x[1] for x in children)


def configuration_match(node, inventory):
    applicable, vulnerable = _configuration_state(node, inventory)
    return applicable and vulnerable


def match_nvd(db,asset,ts):
    cpes=(asset.config or {}).get('_cpes',[])
    if not cpes:return []
    created=[]
    for v in db.query(Vulnerability).filter(Vulnerability.source=='nvd'):
        configs=[x['nvd_config'] for x in v.affected or [] if 'nvd_config' in x]
        if not any(configuration_match(c,cpes) for c in configs):continue
        f=db.query(Finding).filter(Finding.asset_id==asset.id,Finding.cve_id==v.cve_id).first()
        if not f:
            f=Finding(asset_id=asset.id,cve_id=v.cve_id,basis='inferred',status='open',first_seen=ts,evidence={})
            db.add(f);created.append(f)
        f.last_seen, f.status, f.resolved_at=ts,'open',None
        f.evidence={**(f.evidence or {}),'match':'nvd_cpe','cpes':cpes,'configurations':configs,
                    'limitation':'CPE applicability inference; not confirmed exploitability. Negated configurations are conservatively excluded.'}
        db.flush()
    return created


def reconciliation(db):
    cmdb_ids={s.id for s in db.query(Source) if s.category=='cmdb' or (s.config or {}).get('is_cmdb') is True}
    declared=set();seen=set()
    for aid,sid in db.query(Observation.asset_id,Observation.source_id).filter(Observation.status.in_(['processed','unresolved']),Observation.asset_id.isnot(None)).distinct():
        (declared if sid in cmdb_ids else seen).add(aid)
    assets={a.id:a for a in db.query(Asset).filter(Asset.merged_into.is_(None))}
    pack=lambda ids:[{'id':i,'name':assets[i].name,'owner':assets[i].owner} for i in sorted(ids) if i in assets]
    return {'in_cmdb_never_seen':pack(declared-seen),'seen_not_in_cmdb':pack(seen-declared),
            'no_owner':pack({i for i,a in assets.items() if not a.owner}),
            'cmdb_source_ids':sorted(cmdb_ids),'limitation':'Never seen means no successful non-CMDB observation retained in this database.'}


def attack_paths(db,max_depth=5,limit=100):
    assets={a.id:a for a in db.query(Asset).filter(Asset.merged_into.is_(None))}
    adj={}
    for r in db.query(Relationship).filter(Relationship.valid_to.is_(None),Relationship.type.in_(['connects_to','depends_on','hosts','runs_on'])):
        if r.src_id in assets and r.dst_id in assets:adj.setdefault(r.src_id,[]).append(r)
    paths=[]
    for start,a in assets.items():
        if a.exposure!='external':continue
        todo=deque([(start,[start],[])])
        visited={start}
        while todo and len(paths)<limit:
            node,nodes,edges=todo.popleft()
            if node!=start and (assets[node].criticality or 0)>=4:
                paths.append({'assets':[{'id':i,'name':assets[i].name} for i in nodes],
                              'edges':[{'id':e.id,'type':e.type,'basis':e.basis,'confidence':e.confidence} for e in edges],
                              'basis':'inferred','confidence':min((e.confidence for e in edges),default=0)})
            if len(edges)>=max_depth:continue
            for edge in adj.get(node,[]):
                if edge.dst_id not in visited:
                    visited.add(edge.dst_id);todo.append((edge.dst_id,nodes+[edge.dst_id],edges+[edge]))
    return {'paths':paths,'limit':limit,'max_depth':max_depth,'limitation':'Candidate paths through recorded directed dependencies; network reachability and exploit chains are not validated. One shortest path per destination per entry asset.'}
