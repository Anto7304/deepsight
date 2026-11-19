"""Policy findings from inventory evidence, independently of CVE matches."""
from ..models import Finding, Service, Vulnerability
from ..util import now, parse_ts

RULES = {
    "DS-IOT-TELNET": ("Cleartext Telnet service", "Disable Telnet; use SSH and restrict management networks.", .8),
    "DS-IOT-FTP": ("Cleartext FTP service", "Replace FTP with SFTP or a TLS protected transfer service.", .6),
    "DS-IOT-MQTT": ("MQTT without transport encryption", "Use MQTT over TLS and restrict broker access.", .7),
    "DS-IOT-RTSP": ("RTSP reported without authentication", "Require stream authentication and restrict camera access.", .8),
    "DS-IOT-PRINT": ("Raw print service", "Restrict print traffic to managed print servers.", .5),
    "DS-IOT-WINBOX": ("Winbox management service", "Restrict Winbox to a trusted management network and update RouterOS.", .7),
    "DS-IOT-MGMT": ("Externally exposed management interface", "Remove public reachability; require a protected management network.", .9),
    "DS-IOT-EOL": ("Unsupported or end-of-life firmware", "Replace or upgrade to supported firmware; verify the vendor lifecycle evidence.", .9),
}
PORT_RULES = {23: 'DS-IOT-TELNET', 2323: 'DS-IOT-TELNET', 21: 'DS-IOT-FTP',
              1883: 'DS-IOT-MQTT', 9100: 'DS-IOT-PRINT', 8291: 'DS-IOT-WINBOX'}
MANAGEMENT_PORTS = {22, 23, 80, 443, 2323, 8080, 8443, 8291, 3389, 5900}


def detect(db, asset, attrs, observation_id, ts):
    if asset.type not in ('iot_device', 'network_device'):
        return []
    matches = {}
    if 'services' in attrs:
        for s in attrs['services']:
            evidence = {'port': s['port'], 'protocol': s.get('name'), 'observation_id': observation_id,
                        'note': 'Service/configuration evidence; does not establish exploitability or malicious activity.'}
            code = PORT_RULES.get(s['port'])
            if code and not (s['port'] in (21, 1883) and s.get('tls') is True):
                matches.setdefault(code, []).append(evidence)
            if s['port'] == 554 and s.get('auth_required') is False:
                matches.setdefault('DS-IOT-RTSP', []).append({**evidence, 'auth_required': False})
            service = db.query(Service).filter(Service.asset_id == asset.id, Service.port == s['port'], Service.active.is_(True)).first()
            if s['port'] in MANAGEMENT_PORTS and service and service.exposed:
                matches.setdefault('DS-IOT-MGMT', []).append({**evidence, 'external': True})
    cfg = attrs.get('config') or {}
    end = parse_ts(cfg.get('firmware_eol_date')) if cfg.get('firmware_eol_date') else None
    if cfg.get('firmware_support') in ('unsupported', 'end_of_life') or (end and end <= now()):
        matches['DS-IOT-EOL'] = [{'observation_id': observation_id, 'support': cfg.get('firmware_support'),
                                'eol_date': cfg.get('firmware_eol_date'), 'lifecycle_source': cfg.get('lifecycle_source'),
                                'note': 'Source-reported lifecycle status; vendor verification is recommended.'}]
    created = []
    for code, evidence in matches.items():
        title, guidance, severity = RULES[code]
        v = db.get(Vulnerability, code)
        if not v:
            v = Vulnerability(cve_id=code, description=title, cvss=None, severity='unknown',
                              source='deepsight-policy', remediation=guidance, affected=[], kev=False)
            db.add(v); db.flush()
        f = db.query(Finding).filter(Finding.asset_id == asset.id, Finding.cve_id == code).first()
        if not f:
            f = Finding(asset_id=asset.id, cve_id=code, basis='inferred', status='open', first_seen=ts, last_seen=ts)
            db.add(f); created.append(f)
        f.status, f.resolved_at, f.last_seen = 'open', None, max(f.last_seen or ts, ts)
        f.evidence = {**(f.evidence or {}), 'kind': 'configuration', 'rule_id': code, 'weakness_severity': severity,
                      'observations': evidence, 'confidence_limit': 'Policy inference from reported service or firmware data.'}
        db.flush()
    return created
