"""Validation and normalization of raw observations (processing layer).

Normalization standardizes identifiers WITHOUT deciding whether two identifiers belong to
the same asset - that is the job of the identity engine.
"""
import ipaddress
import re

from .util import now, parse_ts

KINDS = ("ip", "mac", "hostname", "cloud_id", "device_id", "serial")
STRONG_KINDS = ("mac", "cloud_id", "device_id", "serial")

_ALIASES = {
    "ip": "ip", "ips": "ip", "ip_address": "ip", "ipv4": "ip", "ipv6": "ip", "private_ip": "ip", "public_ip": "ip",
    "mac": "mac", "macs": "mac", "mac_address": "mac",
    "hostname": "hostname", "host": "hostname", "fqdn": "hostname", "dns_name": "hostname",
    "cloud_id": "cloud_id", "resource_id": "cloud_id", "instance_id": "cloud_id", "arn": "cloud_id",
    "device_id": "device_id", "uuid": "device_id", "machine_id": "device_id",
    "serial": "serial", "serial_number": "serial",
}
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]{0,62}[a-z0-9])?)*$")
GENERIC_HOSTS = {"localhost", "localhost.localdomain", "ubuntu", "debian", "centos", "raspberrypi", "unknown",
                 "host", "server", "pc", "desktop", "laptop", "android", "iphone", "ip6-localhost", "kali"}

ADMIN_PORTS = {22, 23, 135, 445, 2375, 2376, 3389, 5900, 5985, 5986}
DB_PORTS = {1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017}


def _scrub(v, depth=0):
    """Strip NUL characters (rejected by PostgreSQL text/JSON) from every string, recursively."""
    if depth > 20:
        return None
    if isinstance(v, str):
        return v.replace("\x00", "")
    if isinstance(v, dict):
        return {(_scrub(k, depth + 1) if isinstance(k, str) else k): _scrub(x, depth + 1) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_scrub(x, depth + 1) for x in v]
    return v


def _clip(v, n):
    """Coerce to a clean string of at most n characters (matches DB column sizes); None if empty."""
    if v is None or isinstance(v, (dict, list, tuple, set)):
        return None
    t = str(v).strip()[:n]
    return t or None


def norm_ip(v):
    try:
        return str(ipaddress.ip_address(str(v).strip().split("%")[0]))
    except ValueError:
        return None


def ip_is_identifying(ip: str) -> bool:
    o = ipaddress.ip_address(ip)
    return not (o.is_loopback or o.is_unspecified or o.is_link_local or o.is_multicast)


# RFC 5737 documentation prefixes are treated as public so lab/sample data can demonstrate exposure.
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def ip_is_public(ip: str) -> bool:
    try:
        o = ipaddress.ip_address(ip)
        return o.is_global or any(o in n for n in _DOC_NETS if o.version == 4)
    except ValueError:
        return False


def norm_mac(v):
    h = re.sub(r"[^0-9a-fA-F]", "", str(v))
    if len(h) != 12:
        return None
    h = h.lower()
    if h in ("000000000000", "ffffffffffff"):
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def norm_hostname(v):
    s = str(v).strip().lower().rstrip(".")
    if not s or len(s) > 253 or not _HOST_RE.match(s):
        return None
    return s


def norm_token(v):
    s = str(v).strip().lower()
    return s[:256] if s else None


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def normalize_identifiers(raw: dict):
    """Return ({kind: [values]}, flags[])."""
    out = {k: [] for k in KINDS}
    flags = []
    if not isinstance(raw, dict):
        return {}, ["invalid_identifiers"]
    for key, val in raw.items():
        kind = _ALIASES.get(str(key).lower())
        if not kind:
            flags.append(f"unknown_identifier_kind:{key}")
            continue
        for item in _as_list(val):
            if item in (None, ""):
                continue
            if kind == "ip":
                n = norm_ip(item)
                if not n:
                    flags.append(f"invalid_ip:{item}")
                elif not ip_is_identifying(n):
                    flags.append(f"non_identifying_ip:{n}")
                else:
                    n and out["ip"].append(n)
            elif kind == "mac":
                n = norm_mac(item)
                if n:
                    out["mac"].append(n)
                else:
                    flags.append(f"invalid_mac:{item}")
            elif kind == "hostname":
                n = norm_hostname(item)
                if not n:
                    flags.append(f"invalid_hostname:{item}")
                elif n in GENERIC_HOSTS or n.split(".")[0] in GENERIC_HOSTS:
                    flags.append(f"generic_hostname:{n}")
                else:
                    out["hostname"].append(n)
            else:
                n = norm_token(item)
                if n:
                    out[kind].append(n)
    out = {k: sorted(set(v)) for k, v in out.items() if v}
    return out, flags


def os_family(os_str):
    if isinstance(os_str, (dict, list, tuple)):
        os_str = " ".join(str(x) for x in (os_str.values() if isinstance(os_str, dict) else os_str))
    s = str(os_str or "").lower()
    if not s or s == "true":
        return None
    if any(w in s for w in ("windows", "win32", "microsoft")):
        return "windows"
    if any(w in s for w in ("ios-xe", "ios xe", "cisco", "junos", "routeros", "fortios", "pan-os", "mikrotik",
                            "arista", "switch", "router")):
        return "network"
    if any(w in s for w in ("mac os", "macos", "darwin")):
        return "macos"
    if any(w in s for w in ("linux", "ubuntu", "debian", "centos", "rhel", "red hat", "alpine", "amazon", "suse",
                            "fedora", "oracle linux", "rocky", "unix", "freebsd", "bsd")):
        return "linux"
    if any(w in s for w in ("android", "ios", "ipados")):
        return "mobile"
    return "other"


def norm_service(s: dict):
    try:
        port = int(s.get("port"))
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    proto = str(s.get("proto") or s.get("protocol") or "tcp").lower()
    return {
        "port": port,
        "proto": proto if proto in ("tcp", "udp", "sctp") else "tcp",
        "name": (_clip(s.get("name") or s.get("service"), 64) or "").lower() or None,
        "product": _clip(s.get("product"), 128),
        "version": _clip(s.get("version"), 64),
        "bind": _clip(s.get("bind"), 64),
        **{k: s[k] for k in ("tls", "auth_required") if isinstance(s.get(k), bool)},
        "exposure": (_clip(s.get("exposure"), 16) or "").lower() or None,
    }


def norm_software(s: dict):
    p = _clip(s.get("product") or s.get("name"), 128)
    if not p:
        return None
    return {"product": p, "version": _clip(s.get("version"), 64), "cpes": [v for v in s.get("cpes", []) if isinstance(v, str) and v.startswith("cpe:2.3:")]}


def validate_observation(raw: dict, source_verified: bool = True):
    """Validate + normalize a raw observation dict.

    Returns a dict with normalized fields and data-quality indicators. Never raises for
    bad data - problems become quality flags so poor data is visible rather than silent.
    """
    flags = []
    raw = _scrub(raw) if isinstance(raw, dict) else {}
    ids, id_flags = normalize_identifiers(raw.get("identifiers") or {})
    flags += id_flags
    attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else {}
    attrs = dict(attrs)
    for k, n in (("name", 256), ("owner", 128), ("os", 128)):  # clamp free-text fields to DB column sizes
        if k in attrs:
            attrs[k] = _clip(attrs[k], n)
    collected = now()

    observed = None
    try:
        observed = parse_ts(raw.get("observed_at"))
    except Exception:
        flags.append("invalid_timestamp")
    if observed is None:
        observed = collected
        if "invalid_timestamp" not in flags:
            flags.append("missing_timestamp")
    elif observed > collected:
        flags.append("future_timestamp_clamped")
        observed = collected
    age_days = (collected - observed).total_seconds() / 86400
    stale = age_days > 30
    if stale:
        flags.append("stale_information")

    if not ids:
        flags.append("missing_identifiers")
    if not any(k in ids for k in STRONG_KINDS) and ids:
        flags.append("weak_identifiers_only")
    if not source_verified:
        flags.append("unverified_source")

    for key in ("services", "software", "relations"):  # wrong shape: drop it (don't claim an empty snapshot)
        if key in attrs and not isinstance(attrs[key], (list, tuple)):
            flags.append(f"invalid_{key}")
            attrs.pop(key)
    services = []
    for s in attrs.get("services") or []:
        n = norm_service(s) if isinstance(s, dict) else None
        if n:
            services.append(n)
        else:
            flags.append("invalid_service_entry")
    attrs["services"] = services if "services" in attrs else None
    sw = []
    for s in attrs.get("software") or []:
        n = norm_software(s) if isinstance(s, dict) else None
        if n:
            sw.append(n)
    attrs["software"] = sw if "software" in attrs else None
    if attrs.get("os"):
        attrs["os_family"] = os_family(attrs["os"])
    for r in attrs.get("relations") or []:
        if isinstance(r, dict) and "target" in r:
            r["target"], _ = normalize_identifiers(r["target"])
    attrs = {k: v for k, v in attrs.items() if v is not None}

    penalty = {"missing_identifiers": 0.6, "weak_identifiers_only": 0.15, "unverified_source": 0.2,
               "stale_information": 0.4, "missing_timestamp": 0.1, "invalid_timestamp": 0.1,
               "future_timestamp_clamped": 0.1}
    score = 1.0
    for f in flags:
        score -= penalty.get(f.split(":")[0], 0.05)
    return {
        "identifiers": ids,
        "attributes": attrs,
        "observed_at": observed,
        "collected_at": collected,
        "flags": flags,
        "quality_score": max(0.05, round(score, 2)),
        "stale": stale,
        "category": _clip(raw.get("category"), 32) or "asset",
    }
