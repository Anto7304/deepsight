"""Format mappers: turn third-party export formats into DEEPSIGHT raw observations.

Each mapper returns a list of dicts: {identifiers, attributes, observed_at?, category?, raw_ref?}.
They never assume identical source formats - everything is mapped to the common observation model.
"""
import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def _iso_epoch(v):
    try:
        return datetime.fromtimestamp(int(v), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- nmap (-oX)
def parse_nmap_xml(text):
    root = ET.fromstring(text)
    started = _iso_epoch(root.get("start"))
    out = []
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ids = {"ip": [], "mac": [], "hostname": []}
        for a in host.findall("address"):
            t = a.get("addrtype")
            if t in ("ipv4", "ipv6"):
                ids["ip"].append(a.get("addr"))
            elif t == "mac":
                ids["mac"].append(a.get("addr"))
        for hn in host.findall("hostnames/hostname"):
            if hn.get("name"):
                ids["hostname"].append(hn.get("name"))
        services = []
        for p in host.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            services.append({"port": p.get("portid"), "proto": p.get("protocol"),
                             "name": svc.get("name") if svc is not None else None,
                             "product": svc.get("product") if svc is not None else None,
                             "version": svc.get("version") if svc is not None else None})
        attrs = {"services": services, "services_snapshot": True}
        osm = host.find("os/osmatch")
        if osm is not None and osm.get("name"):
            attrs["os"] = osm.get("name")
        out.append({"identifiers": ids, "attributes": attrs, "category": "asset",
                    "observed_at": _iso_epoch(host.get("endtime")) or started})
    return out


# --------------------------------------------------------------------------- AWS EC2
def _open_ports_from_sgs(sg_defs, sg_ids):
    ports, world_all = set(), False
    for sg in sg_defs:
        if sg.get("GroupId") not in sg_ids:
            continue
        for perm in sg.get("IpPermissions", []):
            world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or any(
                r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not world:
                continue
            if perm.get("IpProtocol") == "-1":
                world_all = True
                continue
            lo, hi = perm.get("FromPort"), perm.get("ToPort")
            if lo is None or hi is None:
                continue
            if hi - lo <= 20:
                ports |= set(range(lo, hi + 1))
            else:
                world_all = True
    return sorted(ports), world_all


def parse_aws_ec2(data):
    if isinstance(data, list):
        data = {"Reservations": data}
    sgs = data.get("SecurityGroups", [])
    out = []
    for res in data.get("Reservations", []):
        for ins in res.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in ins.get("Tags", []) if "Key" in t}
            ids = {"cloud_id": [ins.get("InstanceId")], "ip": [], "mac": [], "hostname": []}
            for k in ("PrivateIpAddress", "PublicIpAddress"):
                if ins.get(k):
                    ids["ip"].append(ins[k])
            for ni in ins.get("NetworkInterfaces", []):
                if ni.get("MacAddress"):
                    ids["mac"].append(ni["MacAddress"])
            if tags.get("Name"):
                ids["hostname"].append(tags["Name"])
            sg_ids = {g.get("GroupId") for g in ins.get("SecurityGroups", [])}
            open_ports, world_all = _open_ports_from_sgs(sgs, sg_ids)
            cfg = {"state": (ins.get("State") or {}).get("Name"), "instance_type": ins.get("InstanceType"),
                   "image_id": ins.get("ImageId"), "vpc_id": ins.get("VpcId"), "subnet_id": ins.get("SubnetId"),
                   "security_groups": sorted(g for g in sg_ids if g),
                   "availability_zone": (ins.get("Placement") or {}).get("AvailabilityZone"),
                   "iam_profile": (ins.get("IamInstanceProfile") or {}).get("Arn")}
            if sgs:
                cfg["security_group_open_to_world"] = open_ports + (["all"] if world_all else [])
            attrs = {"type": "cloud_resource", "config": {k: v for k, v in cfg.items() if v is not None},
                     "tags": [f"aws:{k}={v}" for k, v in list(tags.items())[:10]],
                     "internet_exposed_ports": open_ports}
            if tags.get("Name"):
                attrs["name"] = tags["Name"]
            if tags.get("Owner"):
                attrs["owner"] = tags["Owner"]
            plat = (ins.get("PlatformDetails") or ins.get("Platform") or "").lower()
            if plat:
                attrs["os"] = "Windows" if "windows" in plat else plat
            lt = ins.get("LaunchTime")
            out.append({"identifiers": ids, "attributes": attrs, "category": "cloud_inventory",
                        "observed_at": None, "raw_ref": f"aws:{ins.get('InstanceId')}",
                        "_launch": lt})
    return out


# --------------------------------------------------------------------------- Azure
def parse_azure_vms(data):
    out = []
    for vm in data if isinstance(data, list) else data.get("value", []):
        ips = [x.strip() for x in str(vm.get("privateIps") or "").split(",") if x.strip()]
        ips += [x.strip() for x in str(vm.get("publicIps") or "").split(",") if x.strip()]
        ids = {"cloud_id": [vm.get("id")], "device_id": [vm.get("vmId")] if vm.get("vmId") else [], "ip": ips,
               "hostname": [vm.get("name")] if vm.get("name") else []}
        os_type = (vm.get("storageProfile", {}).get("osDisk", {}) or {}).get("osType")
        cfg = {"power_state": vm.get("powerState"), "location": vm.get("location"),
               "vm_size": (vm.get("hardwareProfile") or {}).get("vmSize"), "resource_group": vm.get("resourceGroup")}
        out.append({"identifiers": ids, "category": "cloud_inventory", "raw_ref": f"azure:{vm.get('vmId')}",
                    "attributes": {"type": "cloud_resource", "os": os_type, "name": vm.get("name"),
                                   "config": {k: v for k, v in cfg.items() if v},
                                   "tags": [f"azure:{k}={v}" for k, v in (vm.get("tags") or {}).items()][:10]}})
    return out


# --------------------------------------------------------------------------- OCI (minimal)
def parse_oci_instances(data):
    items = data.get("data", data) if isinstance(data, dict) else data
    out = []
    for i in items:
        out.append({"identifiers": {"cloud_id": [i.get("id")], "hostname": [i.get("display-name")]},
                    "category": "cloud_inventory", "raw_ref": f"oci:{i.get('id')}",
                    "attributes": {"type": "cloud_resource", "name": i.get("display-name"),
                                   "config": {"shape": i.get("shape"), "state": i.get("lifecycle-state"),
                                              "availability_domain": i.get("availability-domain")}}})
    return out


# --------------------------------------------------------------------------- Kubernetes
def parse_k8s(data, cluster_name="k8s-cluster"):
    items = data.get("items", []) if isinstance(data, dict) else data
    cluster_id = f"k8s-cluster:{cluster_name}".lower()
    out = [{"identifiers": {"cloud_id": [cluster_id], "hostname": [cluster_name]}, "category": "cloud_inventory",
            "attributes": {"type": "cloud_resource", "name": cluster_name, "tags": ["kubernetes"]}}]
    for it in items:
        kind, meta = it.get("kind"), it.get("metadata", {})
        if kind == "Node":
            addrs = {a["type"]: a["address"] for a in it.get("status", {}).get("addresses", [])}
            info = it.get("status", {}).get("nodeInfo", {})
            ids = {"hostname": [addrs.get("Hostname") or meta.get("name")],
                   "ip": [x for x in (addrs.get("InternalIP"), addrs.get("ExternalIP")) if x],
                   "device_id": [info.get("systemUUID") or info.get("machineID")]}
            out.append({"identifiers": ids, "category": "cloud_inventory", "raw_ref": f"k8s-node:{meta.get('name')}",
                        "attributes": {"type": "virtual_machine", "name": meta.get("name"), "os": info.get("osImage"),
                                       "tags": ["kubernetes-node"],
                                       "config": {"kubelet_version": info.get("kubeletVersion"),
                                                  "kernel": info.get("kernelVersion"),
                                                  "runtime": info.get("containerRuntimeVersion")},
                                       "software": [{"product": "kubelet", "version": info.get("kubeletVersion", "").lstrip("v")}]
                                       if info.get("kubeletVersion") else [],
                                       "relations": [{"type": "belongs_to", "direction": "out",
                                                      "target": {"cloud_id": cluster_id}}]}})
        elif kind == "Pod":
            spec, st = it.get("spec", {}), it.get("status", {})
            ids = {"cloud_id": [f"k8s-pod:{meta.get('uid')}"], "ip": [st.get("podIP")] if st.get("podIP") else [],
                   "hostname": [meta.get("name")]}
            services, sw = [], []
            for c in spec.get("containers", []):
                img = c.get("image", "")
                name, _, ver = img.rpartition(":") if ":" in img.split("/")[-1] else (img, "", "")
                if name:
                    sw.append({"product": name.split("/")[-1], "version": ver or None})
                for p in c.get("ports", []):
                    services.append({"port": p.get("containerPort"), "proto": (p.get("protocol") or "TCP").lower(),
                                     "name": p.get("name"), "product": name.split("/")[-1] if name else None,
                                     "version": ver or None})
            rels = [{"type": "belongs_to", "direction": "out", "target": {"cloud_id": cluster_id}}]
            if spec.get("nodeName"):
                rels.append({"type": "runs_on", "direction": "out", "target": {"hostname": spec["nodeName"]}})
            out.append({"identifiers": ids, "category": "cloud_inventory", "raw_ref": f"k8s-pod:{meta.get('name')}",
                        "attributes": {"type": "container", "container": True, "name": meta.get("name"),
                                       "services": services, "services_snapshot": True, "software": sw,
                                       "tags": [f"ns:{meta.get('namespace')}"], "relations": rels,
                                       "config": {"phase": st.get("phase")}}})
    return out


# --------------------------------------------------------------------------- CSV host inventory
def parse_csv_hosts(text):
    rd = csv.DictReader(io.StringIO(text))
    out = []
    for row in rd:
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        ids = {k: [r[k]] for k in ("ip", "hostname", "mac", "cloud_id", "serial", "device_id") if r.get(k)}
        attrs = {}
        for k in ("os", "owner", "type", "name"):
            if r.get(k):
                attrs[k] = r[k]
        if r.get("criticality", "").isdigit():
            attrs["criticality"] = int(r["criticality"])
        if r.get("tags"):
            attrs["tags"] = [t.strip() for t in re.split(r"[;|]", r["tags"]) if t.strip()]
        if r.get("ports"):
            svcs = []
            for p in re.split(r"[;|, ]+", r["ports"]):
                m = re.match(r"^(\d+)(?:/(tcp|udp))?$", p.strip())
                if m:
                    svcs.append({"port": m.group(1), "proto": m.group(2) or "tcp"})
            attrs["services"] = svcs
        out.append({"identifiers": ids, "attributes": attrs, "category": "asset", "observed_at": r.get("last_seen") or None})
    return out


# --------------------------------------------------------------------------- vulnerability scan import
def parse_vuln_scan(text, filename=""):
    rows = []
    s = text.lstrip()
    if s.startswith("[") or s.startswith("{"):
        d = json.loads(text)
        rows = d if isinstance(d, list) else d.get("findings", d.get("vulnerabilities", []))
    else:
        rows = list(csv.DictReader(io.StringIO(text)))
    by_host = {}
    for r in rows:
        r = {(k or "").strip().lower(): v for k, v in r.items()}
        ip = r.get("ip") or r.get("host") or r.get("host ip")
        hn = r.get("hostname") or r.get("dns name") or r.get("fqdn")
        key = (ip or "", hn or "")
        if not any(key):
            continue
        cve = r.get("cve") or r.get("cve_id")
        if not cve:
            continue
        for c in re.split(r"[,; ]+", str(cve)):
            if c:
                by_host.setdefault(key, []).append({"cve": c, "port": r.get("port"), "cvss": r.get("cvss") or r.get("cvss v3.0 base score"),
                                                    "evidence": r.get("evidence") or r.get("plugin name") or r.get("name")})
    out = []
    for (ip, hn), findings in by_host.items():
        ids = {}
        if ip:
            ids["ip"] = [ip]
        if hn:
            ids["hostname"] = [hn]
        out.append({"identifiers": ids, "category": "vulnerability_scan",
                    "attributes": {"findings": findings}, "raw_ref": filename})
    return out


def parse_generic(data):
    if isinstance(data, dict):
        data = data.get("observations", [data])
    return [d for d in data if isinstance(d, dict)]
