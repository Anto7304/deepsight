"""Security Intelligence: vulnerability catalog, version matching, KEV/NVD enrichment, findings."""
import logging
import re

import httpx
from sqlalchemy.orm import Session

from ..models import Asset, Finding, Service, Software, Vulnerability
from ..util import now, parse_ts

log = logging.getLogger("asivm.intel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Small SEED catalog so the platform is useful offline. Authoritative data must come from the
# NVD / CISA KEV synchronisers (or imports); verify seed entries against those sources.
SEED_VULNS = [
    {"cve_id": "CVE-2021-44228", "cvss": 10.0, "kev": True, "exploit_available": True,
     "description": "Apache Log4j2 JNDI lookup remote code execution (Log4Shell).",
     "affected": [{"product": "log4j-core", "aliases": ["apache log4j", "log4j", "log4j2", "log4j-core"],
                   "min_inclusive": "2.0", "max_exclusive": "2.15.0"}],
     "techniques": ["T1190"], "remediation": "Upgrade log4j-core to 2.17.1 or later (Java 8+); remove JndiLookup if not upgradable."},
    {"cve_id": "CVE-2021-41773", "cvss": 7.5, "kev": True, "exploit_available": True,
     "description": "Apache HTTP Server 2.4.49 path traversal / file disclosure.",
     "affected": [{"product": "apache http server", "aliases": ["httpd", "apache", "apache httpd"],
                   "versions": ["2.4.49"]}],
     "techniques": ["T1190"], "remediation": "Upgrade Apache HTTP Server to 2.4.51 or later."},
    {"cve_id": "CVE-2014-0160", "cvss": 7.5, "kev": True, "exploit_available": True,
     "description": "OpenSSL TLS heartbeat read overflow (Heartbleed).",
     "affected": [{"product": "openssl", "aliases": ["openssl"], "min_inclusive": "1.0.1", "max_exclusive": "1.0.1g"}],
     "techniques": ["T1190"], "remediation": "Upgrade OpenSSL to 1.0.1g or later and rotate keys/certificates."},
    {"cve_id": "CVE-2017-0144", "cvss": 8.1, "kev": True, "exploit_available": True,
     "description": "Microsoft SMBv1 remote code execution (EternalBlue).",
     "affected": [{"product": "smbv1", "aliases": ["smbv1", "microsoft-ds smbv1", "smb1"], "versions": ["*"]}],
     "techniques": ["T1210"], "remediation": "Apply MS17-010 and disable SMBv1."},
    {"cve_id": "CVE-2019-0708", "cvss": 9.8, "kev": True, "exploit_available": True,
     "description": "Remote Desktop Services remote code execution (BlueKeep).",
     "affected": [{"product": "remote desktop services", "aliases": ["rdp", "ms-wbt-server", "terminal services"],
                   "versions": ["legacy"]}],
     "techniques": ["T1210"], "remediation": "Apply May 2019 security update, enable NLA, do not expose RDP."},
    {"cve_id": "CVE-2023-4863", "cvss": 8.8, "kev": True, "exploit_available": True,
     "description": "libwebp heap buffer overflow in WebP image handling.",
     "affected": [{"product": "libwebp", "aliases": ["libwebp"], "max_exclusive": "1.3.2"}],
     "techniques": ["T1203"], "remediation": "Upgrade libwebp to 1.3.2 or later and rebuild dependent applications."},
    {"cve_id": "CVE-2018-15473", "cvss": 5.3, "kev": False, "exploit_available": True,
     "description": "OpenSSH user enumeration via malformed authentication packets.",
     "affected": [{"product": "openssh", "aliases": ["openssh", "ssh"], "max_exclusive": "7.7"}],
     "techniques": ["T1087"], "remediation": "Upgrade OpenSSH to 7.7 or later."},
    {"cve_id": "CVE-2024-6387", "cvss": 8.1, "kev": False, "exploit_available": False,
     "description": "OpenSSH sshd signal handler race condition (regreSSHion).",
     "affected": [{"product": "openssh", "aliases": ["openssh", "ssh"], "min_inclusive": "8.5", "max_exclusive": "9.8"}],
     "techniques": ["T1190"], "remediation": "Upgrade OpenSSH to 9.8 or later or mitigate with LoginGraceTime 0."},
    {"cve_id": "CVE-2020-1938", "cvss": 9.8, "kev": True, "exploit_available": True,
     "description": "Apache Tomcat AJP connector file read / inclusion (Ghostcat).",
     "affected": [{"product": "apache tomcat", "aliases": ["tomcat", "apache-tomcat", "apache jserv", "ajp13"],
                   "min_inclusive": "9.0.0", "max_exclusive": "9.0.31"},
                  {"product": "apache tomcat", "aliases": ["tomcat", "apache-tomcat", "apache jserv", "ajp13"],
                   "min_inclusive": "8.5.0", "max_exclusive": "8.5.51"},
                  {"product": "apache tomcat", "aliases": ["tomcat", "apache-tomcat", "apache jserv", "ajp13"],
                   "min_inclusive": "7.0.0", "max_exclusive": "7.0.100"}],
     "techniques": ["T1190"], "remediation": "Upgrade Tomcat (9.0.31+, 8.5.51+, 7.0.100+) and disable or firewall the AJP connector."},
    {"cve_id": "CVE-2022-22965", "cvss": 9.8, "kev": True, "exploit_available": True,
     "description": "Spring Framework data binding remote code execution (Spring4Shell).",
     "affected": [{"product": "spring-webmvc", "aliases": ["spring-beans", "spring-framework", "spring-webflux"],
                   "min_inclusive": "5.3.0", "max_exclusive": "5.3.18"},
                  {"product": "spring-webmvc", "aliases": ["spring-beans", "spring-framework", "spring-webflux"],
                   "min_inclusive": "5.2.0", "max_exclusive": "5.2.20"}],
     "techniques": ["T1190"], "remediation": "Upgrade Spring Framework to 5.3.18+ / 5.2.20+."},
    {"cve_id": "CVE-2017-5638", "cvss": 10.0, "kev": True, "exploit_available": True,
     "description": "Apache Struts 2 Jakarta Multipart parser remote code execution.",
     "affected": [{"product": "struts2-core", "aliases": ["apache struts", "struts", "struts2"],
                   "min_inclusive": "2.3.5", "max_exclusive": "2.3.32"},
                  {"product": "struts2-core", "aliases": ["apache struts", "struts", "struts2"],
                   "min_inclusive": "2.5.0", "max_exclusive": "2.5.10.1"}],
     "techniques": ["T1190"], "remediation": "Upgrade Struts to 2.3.32 / 2.5.10.1 or later."},
    {"cve_id": "CVE-2021-42013", "cvss": 9.8, "kev": True, "exploit_available": True,
     "description": "Apache HTTP Server 2.4.49-2.4.50 path traversal and remote code execution.",
     "affected": [{"product": "apache http server", "aliases": ["httpd", "apache", "apache httpd"],
                   "min_inclusive": "2.4.49", "max_exclusive": "2.4.51"}],
     "techniques": ["T1190"], "remediation": "Upgrade Apache HTTP Server to 2.4.51 or later."},
    # ---- IoT / embedded. Version ranges are illustrative for the demo: confirm CVSS/KEV/ranges with the NVD and KEV sync.
    {"cve_id": "CVE-2021-36260", "cvss": 9.8, "kev": True, "exploit_available": True,
     "description": "Hikvision IP camera web server command injection (unauthenticated remote code execution).",
     "affected": [{"product": "hikvision firmware", "aliases": ["hikvision", "hikvision-webs"],
                   "min_inclusive": "5.4.0", "max_exclusive": "5.6.0"}],
     "techniques": ["T1190"], "remediation": "Update the camera to the vendor's patched firmware and restrict web/management access to a management VLAN."},
    {"cve_id": "CVE-2017-17562", "cvss": 8.1, "kev": False, "exploit_available": True,
     "description": "GoAhead embedded web server before 3.6.5: remote code execution via CGI environment variable injection.",
     "affected": [{"product": "goahead webserver", "aliases": ["goahead", "goahead-webs"],
                   "min_inclusive": "2.5.0", "max_exclusive": "3.6.5"}],
     "techniques": ["T1190"], "remediation": "Upgrade GoAhead to 3.6.5 or later (device vendor firmware update); disable CGI if unused."},
    {"cve_id": "CVE-2012-0920", "cvss": 7.1, "kev": False, "exploit_available": True,
     "description": "Dropbear SSH server use-after-free (authenticated), versions 0.52 through 2011.54.",
     "affected": [{"product": "dropbear sshd", "aliases": ["dropbear"], "min_inclusive": "0.52", "max_exclusive": "2012.55"}],
     "techniques": ["T1021"], "remediation": "Upgrade Dropbear to 2012.55 or later (embedded device firmware update)."},
    {"cve_id": "CVE-2017-7650", "cvss": 9.8, "kev": False, "exploit_available": False,
     "description": "Mosquitto MQTT broker before 1.4.12: pattern-based ACLs can be bypassed using '#' or '+' as client id/username.",
     "affected": [{"product": "mosquitto", "aliases": ["eclipse mosquitto", "mosquitto mqtt"],
                   "min_inclusive": "1.0", "max_exclusive": "1.4.12"}],
     "techniques": ["T1190"], "remediation": "Upgrade Mosquitto to 1.4.12 or later; require authentication and TLS; do not expose MQTT to the internet."},
    {"cve_id": "CVE-2018-14847", "cvss": 9.1, "kev": False, "exploit_available": True,
     "description": "MikroTik RouterOS Winbox arbitrary file read/write and credential disclosure (6.29 through 6.42).",
     "affected": [{"product": "mikrotik routeros", "aliases": ["routeros", "winbox"],
                   "min_inclusive": "6.29", "max_exclusive": "6.42.1"}],
     "techniques": ["T1190"], "remediation": "Upgrade RouterOS to 6.42.1 or later; restrict Winbox to management addresses; rotate credentials."},
    {"cve_id": "CVE-2024-4577", "cvss": 9.8, "kev": True, "exploit_available": True,
     "description": "PHP-CGI argument injection on Windows (Best-Fit character conversion).",
     "affected": [{"product": "php", "aliases": ["php-cgi"], "min_inclusive": "8.3.0", "max_exclusive": "8.3.8"},
                  {"product": "php", "aliases": ["php-cgi"], "min_inclusive": "8.2.0", "max_exclusive": "8.2.20"},
                  {"product": "php", "aliases": ["php-cgi"], "min_inclusive": "8.1.0", "max_exclusive": "8.1.29"}],
     "techniques": ["T1190"], "remediation": "Upgrade PHP to 8.3.8 / 8.2.20 / 8.1.29 or later."},
]


def _sev(cvss):
    if cvss is None:
        return "unknown"
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"


def seed_vulnerabilities(db: Session):
    for v in SEED_VULNS:
        if not db.get(Vulnerability, v["cve_id"]):
            db.add(Vulnerability(cve_id=v["cve_id"], cvss=v["cvss"], severity=_sev(v["cvss"]), kev=v["kev"],
                                 exploit_available=v["exploit_available"], description=v["description"],
                                 affected=v["affected"], techniques=v["techniques"], remediation=v["remediation"],
                                 source="seed", enriched=True))
    db.commit()


def parse_version(s):
    """Approximate, tolerant version tuple ('8.9p1' -> (8,9,1), '1.0.1f' -> (1,0,1,6))."""
    if s is None:
        return None
    s = str(s).strip().lower().lstrip("v")
    m = re.match(r"^(\d+(?:\.\d+)*)([a-z]*)(\d*)", s)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    letters, tail = m.group(2), m.group(3)
    if letters and len(letters) == 1 and letters != "p":
        nums.append(ord(letters) - 96)
    elif letters == "p" and tail:
        nums.append(int(tail))
    elif letters.startswith("-") or letters in ("", "p"):
        pass
    return tuple(nums)


def _cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_in(aff: dict, version):
    if "versions" in aff:
        vs = aff["versions"]
        if "*" in vs:
            return True
        return version is not None and str(version).strip().lower() in {str(x).lower() for x in vs}
    pv = parse_version(version)
    if pv is None:
        return False
    if "min_inclusive" in aff and _cmp(pv, parse_version(aff["min_inclusive"])) < 0:
        return False
    if "max_exclusive" in aff and _cmp(pv, parse_version(aff["max_exclusive"])) >= 0:
        return False
    if "max_inclusive" in aff and _cmp(pv, parse_version(aff["max_inclusive"])) > 0:
        return False
    return any(k in aff for k in ("min_inclusive", "max_exclusive", "max_inclusive"))


def _names(aff):
    return {str(aff.get("product", "")).lower(), *[str(a).lower() for a in aff.get("aliases", [])]} - {""}


def _match(aff, product, name, version):
    cand = {x.lower() for x in (product, name) if x}
    # tolerate product strings like "Apache httpd" / "OpenSSH_8.9"
    toks = set()
    for c in cand:
        toks.add(c)
        toks |= set(re.split(r"[\s_/]+", c))
    if not (toks & _names(aff)):
        return False
    return version_in(aff, version)


def match_asset(db: Session, asset: Asset, ts=None):
    """Create/refresh/resolve inferred findings for an asset from services + software inventory."""
    ts = ts or now()
    vulns = db.query(Vulnerability).all()
    open_f = {(f.cve_id, f.service_id, f.software_id): f
              for f in db.query(Finding).filter(Finding.asset_id == asset.id, Finding.status.in_(["open"]),
                                                Finding.basis == "inferred").all()}
    seen = set()
    created = []
    items = []
    for s in db.query(Service).filter(Service.asset_id == asset.id, Service.active.is_(True)).all():
        items.append(("service", s, s.product, s.name, s.version))
    for s in db.query(Software).filter(Software.asset_id == asset.id, Software.active.is_(True)).all():
        items.append(("software", s, s.product, None, s.version))
    for kind, obj, product, name, version in items:
        for v in vulns:
            for aff in v.affected or []:
                if _match(aff, product, name, version):
                    key = (v.cve_id, obj.id if kind == "service" else None, obj.id if kind == "software" else None)
                    seen.add(key)
                    f = open_f.get(key)
                    if f:
                        f.last_seen = ts
                        continue
                    # one open finding per CVE per asset: an observed finding supersedes inferred ones, and a
                    # service-based match supersedes a software-based match of the same CVE
                    if db.query(Finding.id).filter(Finding.asset_id == asset.id, Finding.cve_id == v.cve_id,
                                                   Finding.status == "open").first() or any(
                            c.cve_id == v.cve_id for c in created):
                        break
                    f = Finding(asset_id=asset.id, cve_id=v.cve_id, service_id=key[1], software_id=key[2],
                                port=getattr(obj, "port", None), basis="inferred", status="open", first_seen=ts,
                                last_seen=ts,
                                evidence={"match": kind, "product": product or name, "version": version,
                                          "affected_rule": aff,
                                          "note": "Inferred from reported product/version; not confirmed by "
                                                  "an authenticated scan or exploit check."})
                    db.add(f)
                    created.append(f)
                    break
    for key, f in open_f.items():
        if key not in seen:
            f.evidence = {**(f.evidence or {}), "verification_required": True,
                          "match_absent_note": "Product/version no longer matches; a verification scan is required to close."}
    from ..coverage import match_nvd
    created += match_nvd(db, asset, ts)
    db.flush()
    return created


def rematch_all(db: Session):
    n = 0
    for a in db.query(Asset).filter(Asset.merged_into.is_(None)).all():
        n += len(match_asset(db, a))
    db.commit()
    return n


def apply_reported_findings(db: Session, asset: Asset, findings: list, source_id, ts):
    """Scanner-reported findings => basis 'observed'."""
    created = []
    if not isinstance(findings, (list, tuple)):
        return created
    for rep in findings:
        if not isinstance(rep, dict):
            continue
        cve = str(rep.get("cve") or rep.get("cve_id") or "").upper().strip()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
            continue
        v = db.get(Vulnerability, cve)
        if not v:
            try:
                cv = float(rep.get("cvss")) if rep.get("cvss") not in (None, "") else None
            except (TypeError, ValueError):
                cv = None
            desc = rep.get("description")
            v = Vulnerability(cve_id=cve, cvss=cv,
                              severity=_sev(cv) if cv is not None else "unknown",
                              description=(str(desc)[:2000] if isinstance(desc, str) and desc else "Reported by scanner; not yet enriched."),
                              affected=[], source="scanner", enriched=False)
            db.add(v)
            db.flush()
        port = rep.get("port")
        port = int(port) if str(port).isdigit() and int(port) < 65536 else None
        # Findings are asset/CVE records. A firmware match may have no port; later
        # scanner reports on one or more ports must enrich that same record.
        f = db.query(Finding).filter(Finding.asset_id == asset.id, Finding.cve_id == cve).order_by(
            (Finding.status == "open").desc(), Finding.id).first()
        if not f:
            f = Finding(asset_id=asset.id, cve_id=cve, port=port, basis="observed",
                        status="open", first_seen=ts, last_seen=ts, evidence={})
            db.add(f)
            created.append(f)
        evidence = dict(f.evidence or {})
        if f.basis == "inferred":
            evidence["upgraded_from"] = "inferred"
            evidence["note"] = "Product/version match confirmed by scanner-reported evidence."
        reports = list(evidence.get("scanner_reports", []))
        report = {"source_id": source_id, "port": port, "evidence": rep.get("evidence")}
        reports = [r for r in reports if (r.get("source_id"), r.get("port")) != (source_id, port)]
        reports.append(report)
        f.evidence = {**evidence, "reported_by_source": source_id,
                      "scanner_evidence": rep.get("evidence"), "scanner_reports": reports}
        f.basis, f.status, f.resolved_at, f.last_seen = "observed", "open", None, ts
        if f.port is None and port is not None:
            f.port = port
        # Autoflush is disabled: make this record visible to the next report in
        # the same batch, including repeated reports for a previously unseen CVE.
        db.flush()
    db.flush()
    return created


# ------------------------------------------------------------------ feeds
def import_kev_json(db: Session, data: dict):
    n_new = n_flag = 0
    for item in data.get("vulnerabilities", []):
        cve = item.get("cveID")
        if not cve:
            continue
        v = db.get(Vulnerability, cve)
        if v:
            if not v.kev:
                n_flag += 1
            v.kev, v.exploit_available, v.kev_added = True, True, item.get("dateAdded")
        else:
            db.add(Vulnerability(cve_id=cve, description=(item.get("shortDescription") or item.get("vulnerabilityName")),
                                 kev=True, exploit_available=True, kev_added=item.get("dateAdded"), source="kev",
                                 enriched=False, affected=[],
                                 remediation=item.get("requiredAction"), severity="unknown"))
            n_new += 1
    db.commit()
    return {"new": n_new, "flagged_existing": n_flag, "total_in_feed": len(data.get("vulnerabilities", []))}


def sync_kev(db: Session):
    r = httpx.get(KEV_URL, timeout=60, follow_redirects=True)
    r.raise_for_status()
    return import_kev_json(db, r.json())


def import_nvd_json(db: Session, data: dict):
    n = 0
    for item in data.get("vulnerabilities", []):
        c = item.get("cve") or {}
        cve = c.get("id")
        if not cve:
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), None)
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            ms = (c.get("metrics") or {}).get(key)
            if ms:
                cvss = ms[0].get("cvssData", {}).get("baseScore")
                break
        v = db.get(Vulnerability, cve)
        pub = None
        try:
            pub = parse_ts(c.get("published"))
        except Exception:
            pass
        refs = [r.get("url") for r in c.get("references", [])][:10]
        if not v:
            v = Vulnerability(cve_id=cve, affected=[], source="nvd")
            db.add(v)
        v.description, v.cvss, v.severity, v.published, v.references = desc, cvss, _sev(cvss), pub, refs
        v.enriched = True
        v.source = "nvd"
        v.affected = [{"nvd_config": x} for x in c.get("configurations", [])]
        n += 1
    db.commit()
    return {"updated": n}


def sync_nvd_cve(db: Session, cve_id: str):
    r = httpx.get(NVD_URL, params={"cveId": cve_id}, timeout=60)
    r.raise_for_status()
    return import_nvd_json(db, r.json())
