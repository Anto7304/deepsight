"""Connector registry. Each connector acquires observations and preserves original context;
normalization/identity happen later in the pipeline."""
import ipaddress
import json
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import httpx

from ..config import settings
from ..util import iso, now
from . import mappers

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
                8080, 8443, 9200, 27017]
# Typical IoT / embedded services: RTSP, MQTT (plain/TLS), raw printing, IPP, Winbox, alt-Telnet, alt-HTTP
IOT_PORTS = [554, 631, 1883, 2323, 8000, 8291, 8554, 8883, 9100]
BANNER_PORTS = {21, 22, 23, 25, 110, 143}


class ConnectorError(Exception):
    pass


class Connector:
    kind = ""
    label = ""
    category = "infrastructure"
    schedulable = False
    accepts_upload = False
    description = ""
    config_template: dict = {}

    def collect(self, config, secrets):
        raise ConnectorError("this connector does not support active collection; use import")

    def parse(self, content: str, filename: str, config: dict):
        raise ConnectorError("this connector does not accept imports")

    def test(self, config, secrets):
        return {"ok": True, "detail": "no connectivity required"}


class _Upload(Connector):
    accepts_upload = True
    fn = None

    def parse(self, content, filename, config):
        return self.fn(content, filename, config)


class GenericJson(_Upload):
    kind, label = "generic_json", "Generic observations (JSON)"
    description = "DEEPSIGHT observation format: list of {identifiers, attributes, observed_at}."
    fn = staticmethod(lambda c, f, cfg: mappers.parse_generic(json.loads(c)))


class CsvHosts(_Upload):
    kind, label = "csv_hosts", "Host inventory (CSV)"
    description = "CSV with columns ip,hostname,mac,os,owner,criticality,type,tags,ports,cloud_id,serial."
    fn = staticmethod(lambda c, f, cfg: mappers.parse_csv_hosts(c))


class NmapXml(_Upload):
    kind, label = "nmap_xml", "Nmap scan (XML, -oX)"
    description = "Import results of an authorized nmap scan."
    fn = staticmethod(lambda c, f, cfg: mappers.parse_nmap_xml(c))


class AwsEc2(_Upload):
    kind, label, category = "aws_ec2", "AWS EC2 inventory (JSON)", "cloud"
    description = "Output of `aws ec2 describe-instances` (optionally merged with describe-security-groups)."
    fn = staticmethod(lambda c, f, cfg: mappers.parse_aws_ec2(json.loads(c)))


class AzureVm(_Upload):
    kind, label, category = "azure_vm", "Azure VM inventory (JSON)", "cloud"
    description = "Output of `az vm list -d -o json`."
    fn = staticmethod(lambda c, f, cfg: mappers.parse_azure_vms(json.loads(c)))


class OciInstances(_Upload):
    kind, label, category = "oci_instances", "Oracle Cloud instances (JSON)", "cloud"
    description = "Output of `oci compute instance list`."
    fn = staticmethod(lambda c, f, cfg: mappers.parse_oci_instances(json.loads(c)))


class K8sJson(_Upload):
    kind, label, category = "k8s_json", "Kubernetes nodes/pods (JSON)", "container"
    description = "Output of `kubectl get nodes,pods -A -o json`. Set config.cluster_name."
    config_template = {"cluster_name": "prod-cluster"}
    fn = staticmethod(lambda c, f, cfg: mappers.parse_k8s(json.loads(c), (cfg or {}).get("cluster_name", "k8s-cluster")))


class VulnScan(_Upload):
    kind, label, category = "vuln_scan", "Vulnerability scan results (CSV/JSON)", "security"
    description = "Scanner export with host/ip, hostname, cve, port, cvss columns. Findings are 'observed'."
    fn = staticmethod(lambda c, f, cfg: mappers.parse_vuln_scan(c, f))


_MAPPERS = {
    "aws_ec2": lambda d, cfg: mappers.parse_aws_ec2(d),
    "azure_vm": lambda d, cfg: mappers.parse_azure_vms(d),
    "oci_instances": lambda d, cfg: mappers.parse_oci_instances(d),
    "k8s_json": lambda d, cfg: mappers.parse_k8s(d, cfg.get("cluster_name", "k8s-cluster")),
    "generic_json": lambda d, cfg: mappers.parse_generic(d),
}


_METADATA_IPS = {"100.100.100.200", "192.0.0.192", "fd00:ec2::254"}  # Alibaba, Oracle, AWS IPv6 metadata endpoints


def _ip_blocked(ip) -> bool:
    ip = getattr(ip, "ipv4_mapped", None) or ip  # ::ffff:169.254.169.254 must not bypass the checks
    return bool(ip.is_link_local or ip.is_multicast or ip.is_loopback or ip.is_unspecified or str(ip) in _METADATA_IPS)


def _check_url(url):
    if not isinstance(url, str):
        raise ConnectorError("config.url must be a string")
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ConnectorError("url must be http(s)")
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80)):
            if _ip_blocked(ipaddress.ip_address(sa[0].split("%")[0])):
                raise ConnectorError("loopback / link-local / metadata addresses are not permitted")
    except socket.gaierror as e:
        raise ConnectorError(f"cannot resolve host: {e}")
    except UnicodeError:
        raise ConnectorError("invalid host name")


class HttpJson(Connector):
    kind, label, category = "http_json", "HTTP API collector (JSON)", "api"
    schedulable = True
    description = "Poll a JSON API (cloud inventory proxy, CMDB, etc.) and map it with a known mapper."
    config_template = {"url": "https://inventory.example.com/instances", "mapper": "generic_json", "timeout": 30,
                       "verify_tls": True, "cluster_name": ""}

    def _fetch(self, config, secrets):
        _check_url(config.get("url", ""))
        try:
            timeout = min(max(float(config.get("timeout", 30)), 1.0), 120.0)
        except (TypeError, ValueError):
            raise ConnectorError("config.timeout must be a number of seconds")
        r = httpx.get(config["url"], headers=(secrets or {}).get("headers", {}), timeout=timeout,
                      verify=config.get("verify_tls", True), follow_redirects=False)
        if r.status_code in (401, 403):
            raise ConnectorError(f"authentication failed ({r.status_code})")
        r.raise_for_status()
        return r.json()

    def collect(self, config, secrets):
        mapper = _MAPPERS.get(config.get("mapper", "generic_json"))
        if not mapper:
            raise ConnectorError(f"unknown mapper {config.get('mapper')}")
        return mapper(self._fetch(config, secrets), config)

    def test(self, config, secrets):
        self._fetch(config, secrets)
        return {"ok": True, "detail": "endpoint reachable and returned JSON"}


def _parse_banner(port, banner):
    if not banner:
        return None, None
    m = re.match(r"SSH-[\d.]+-([A-Za-z]+)[_-]?([\w.]+)", banner)
    if m:
        return m.group(1), m.group(2).split(" ")[0]
    m = re.search(r"([A-Za-z][\w\-]+)[ /_](\d+(?:\.\d+)+[a-z]?\d*)", banner)
    if m:
        return m.group(1), m.group(2)
    return None, None


def _probe(host, port, timeout):
    """Returns (state, banner). state in open|closed|filtered."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return "closed", None
    except (socket.timeout, TimeoutError, OSError):
        return "filtered", None
    banner = None
    try:
        if port in BANNER_PORTS:
            s.settimeout(1.0)
            banner = s.recv(128).decode("latin-1", "ignore").strip()
    except Exception:
        pass
    finally:
        s.close()
    return "open", banner


class TcpDiscovery(Connector):
    kind, label, category = "tcp_discovery", "TCP connect discovery (authorized targets)", "infrastructure"
    schedulable = True
    description = ("Agentless TCP connect check of explicitly configured targets. Sends no payloads; reads banners "
                   "only on a few protocols that announce themselves. Requires authorized=true.")
    config_template = {"authorized": False, "targets": ["10.0.0.5", "10.0.0.0/28"], "ports": sorted(set(COMMON_PORTS) | set(IOT_PORTS)),
                       "timeout": 1.5, "reverse_dns": False, "max_hosts": 256,
                       "hostnames": {}, "asset_type": ""}

    def _targets(self, config):
        if not settings.allow_tcp_discovery:
            raise ConnectorError("tcp discovery is disabled on this deployment (ASIVM_ALLOW_TCP_DISCOVERY=false)")
        if config.get("authorized") is not True:
            raise ConnectorError("set config.authorized=true to confirm you are authorized to scan these targets")
        try:
            max_hosts = min(int(config.get("max_hosts", 256)), 4096)
        except (TypeError, ValueError):
            raise ConnectorError("config.max_hosts must be an integer")
        out, explicit = [], set()
        for t in config.get("targets", []):
            try:
                if "/" in str(t):
                    net = ipaddress.ip_network(str(t), strict=False)
                    if len(out) + net.num_addresses > max_hosts + 2:  # check BEFORE expanding (a /8 or IPv6 /64 would hang)
                        raise ConnectorError(f"{t} expands to {net.num_addresses} addresses, exceeds max_hosts={max_hosts}")
                    out += [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
                else:
                    ip = str(ipaddress.ip_address(str(t).strip()))
                    out.append(ip)
                    explicit.add(ip)
            except ValueError:
                raise ConnectorError(f"invalid target: {t}")
        out = list(dict.fromkeys(out))
        if len(out) > max_hosts:
            raise ConnectorError(f"{len(out)} hosts exceeds max_hosts={max_hosts}")
        allowed = [ipaddress.ip_network(c) for c in settings.tcp_allowed_cidrs]
        if any(not any(ipaddress.ip_address(h) in n for n in allowed) for h in out):
            raise ConnectorError("target outside ASIVM_TCP_ALLOWED_CIDRS")
        return out, explicit

    def test(self, config, secrets):
        hosts, _ = self._targets(config)
        return {"ok": True, "detail": f"{len(hosts)} target host(s) validated"}

    def collect(self, config, secrets):
        hosts, explicit = self._targets(config)
        ports = [int(p) for p in config.get("ports", COMMON_PORTS)][:200]
        timeout = float(config.get("timeout", 1.5))
        results = {}
        names = config.get("hostnames") if isinstance(config.get("hostnames"), dict) else {}  # optional {ip: name}
        atype = config.get("asset_type") if isinstance(config.get("asset_type"), str) and config.get("asset_type") else None

        def scan(h):
            return h, {p: _probe(h, p, timeout) for p in ports}

        with ThreadPoolExecutor(max_workers=48) as ex:
            for h, res in ex.map(scan, hosts):
                results[h] = res
        ts = iso(now())
        obs = []
        for h, res in results.items():
            open_ports = {p: b for p, (st, b) in res.items() if st == "open"}
            up = any(st in ("open", "closed") for st, _ in res.values())
            ids = {"ip": [h]}
            if config.get("reverse_dns"):
                try:
                    ids["hostname"] = [socket.gethostbyaddr(h)[0]]
                except OSError:
                    pass
            if isinstance(names.get(h), str) and names[h].strip():  # static name: no DNS dependency
                ids.setdefault("hostname", []).append(names[h].strip())
            extra = {"type": atype} if atype else {}
            if open_ports:
                svcs = []
                for p, banner in open_ports.items():
                    prod, ver = _parse_banner(p, banner)
                    svcs.append({"port": p, "proto": "tcp", "product": prod, "version": ver})
                obs.append({"identifiers": ids, "category": "asset", "observed_at": ts, "raw_ref": f"tcp:{h}",
                            "attributes": {"services": svcs, "services_snapshot": True, **extra}})
            elif up:
                obs.append({"identifiers": ids, "category": "asset", "observed_at": ts, "raw_ref": f"tcp:{h}",
                            "attributes": {"services": [], "services_snapshot": True, **extra}})
            elif h in explicit:
                obs.append({"identifiers": ids, "category": "reachability", "observed_at": ts, "raw_ref": f"tcp:{h}",
                            "attributes": {"reachable": False, "_only_if_known": True}})
        return obs


class Trivy(_Upload):
    kind, label, category = "trivy_json", "Trivy JSON", "security"
    description = "Observed package vulnerability results from a Trivy export."
    def parse(self, content, filename, config):
        from .scanners import parse_scanner
        rows = parse_scanner(content, "trivy")
        rows[0]["attributes"]["assessment"]["finding_codes"] += config.get("assessment_codes", [])
        return rows


class Grype(_Upload):
    kind, label, category = "grype_json", "Grype JSON", "security"
    description = "Observed package vulnerability results from a Grype export."
    def parse(self, content, filename, config):
        from .scanners import parse_scanner
        rows = parse_scanner(content, "grype")
        rows[0]["attributes"]["assessment"]["finding_codes"] += config.get("assessment_codes", [])
        return rows


class OutboundWebhook(Connector):
    kind, label, category = "outbound_webhook", "Outbound finding webhook", "notification"
    description = "Durable notifications for new critical or KEV findings; configured destinations only."
    config_template = {"url":"https://tickets.example/webhook"}
    def test(self, config, secrets):
        _check_url(config.get("url", ""))
        return {"ok":True,"detail":"Destination URL validated; no payload sent"}


REGISTRY = {c.kind: c for c in (GenericJson(), CsvHosts(), NmapXml(), AwsEc2(), AzureVm(), OciInstances(), K8sJson(),
                                VulnScan(), HttpJson(), TcpDiscovery(), Trivy(), Grype(), OutboundWebhook())}


def describe():
    return [{"kind": c.kind, "label": c.label, "category": c.category, "schedulable": c.schedulable,
             "accepts_upload": c.accepts_upload, "description": c.description,
             "config_template": c.config_template} for c in REGISTRY.values()]
