"""Demo / lab dataset: a fictional organisation ("corp.example.com") observed by ten sources.

All data here is SYNTHETIC. It is produced in the native export formats of each source
(nmap XML, AWS describe-instances JSON, Azure `az vm list`, OCI, kubectl JSON, CMDB CSV,
scanner CSV) and parsed by the same connectors/mappers used for real imports, then pushed
through the normal pipeline - so the demo exercises the real code path end to end.

 * load():    14 days of backdated history (ordinary churn = the anomaly baseline) + current state
 * advance(): one drift scenario - an exposure change on app-server-01, SMBv1 on files-01, a rogue device,
               plus IoT drift (Telnet switched on for a camera, an MQTT broker port-forwarded to the internet)
 * reset():   wipe platform data (users and audit log are kept)
"""
import calendar
import csv
import io
import json
import logging
import random
from datetime import datetime, time, timedelta
from xml.sax.saxutils import quoteattr

from sqlalchemy.orm import Session

from . import pipeline
from .connectors import mappers
from .db import Base, session_scope
from .engines import anomaly as anomaly_engine
from .engines import intel, ml, risk
from .models import Setting, Source
from .util import iso, now

log = logging.getLogger("asivm.demo")
PROGRESS = {"state": "idle", "detail": "", "done": 0, "total": 0}
DOMAIN = "corp.example.com"

# name, ip, os (nmap), type, criticality, owner, services[(port,name,product,version)], vm
_SRV = "Linux 5.15 (Ubuntu 22.04)"
HOSTS = [
    ("esx-host-01", "10.10.0.50", "VMware ESXi 8.0", "server", 5, "Infrastructure", [(443, "https", "VMware ESXi", "8.0"), (22, "ssh", "OpenSSH", "8.8")], False),
    ("app-server-01", "10.10.1.20", _SRV, "server", 4, "Payments Platform", [(22, "ssh", "OpenSSH", "8.9p1"), (443, "https", "nginx", "1.24.0")], True),
    ("db-server-01", "10.10.2.10", _SRV, "server", 5, "Data Engineering", [(22, "ssh", "OpenSSH", "8.9p1"), (5432, "postgresql", "PostgreSQL", "15.4")], True),
    ("web-proxy-01", "10.10.0.5", "Linux 6.1 (Debian 12)", "server", 4, "Network Ops", [(80, "http", "nginx", "1.24.0"), (443, "https", "nginx", "1.24.0"), (22, "ssh", "OpenSSH", "9.2p1")], True),
    ("mail-01", "10.10.0.25", "Linux 6.1 (Debian 12)", "server", 3, "IT Ops", [(25, "smtp", "Postfix", "3.7.4"), (993, "imaps", "Dovecot", "2.3.19"), (22, "ssh", "OpenSSH", "9.2p1")], True),
    ("files-01", "10.10.3.15", "Microsoft Windows Server 2016", "server", 3, "IT Ops", [(445, "microsoft-ds", "Microsoft Windows SMB", "3.1.1"), (135, "msrpc", "Microsoft Windows RPC", None)], True),
    ("ci-server-01", "10.10.4.30", _SRV, "server", 4, "Engineering", [(22, "ssh", "OpenSSH", "8.9p1"), (8080, "http-proxy", "Jenkins", "2.452")], True),
    ("dev-server-02", "10.10.4.40", _SRV, "server", 2, "Engineering", [(22, "ssh", "OpenSSH", "9.6p1")], True),
    ("intranet-web-02", "10.10.6.12", "Linux 4.18 (Rocky Linux 8)", "server", 2, "HR IT", [(80, "http", "Apache httpd", "2.4.49"), (22, "ssh", "OpenSSH", "8.0p1")], True),
    ("legacy-nas-01", "10.10.7.8", "Linux 3.10", "server", 2, "IT Ops", [(22, "ssh", "OpenSSH", "7.4"), (445, "microsoft-ds", "Samba", "4.9.5")], False),
    ("fw-edge-01", "10.10.0.1", "FortiOS 7.2", "network_device", 5, "Network Ops", [(443, "https", None, None), (22, "ssh", None, None)], False),
    ("switch-core-01", "10.10.0.2", "Cisco IOS XE 17.9", "network_device", 5, "Network Ops", [(22, "ssh", None, None)], False),
    ("switch-access-02", "10.10.0.3", "Cisco IOS XE 17.6", "network_device", 3, "Network Ops", [(22, "ssh", None, None)], False),
    ("printer-02", "10.10.8.21", "Linux 3.x (embedded)", "iot_device", 1, "Facilities", [(80, "http", None, None), (9100, "jetdirect", None, None)], False),
    ("camera-iot-01", "10.10.8.40", "Linux 3.x (embedded)", "iot_device", 2, "Facilities", [(554, "rtsp", None, None), (80, "http", None, None)], False),
    # --- IoT VLAN 10.10.8.0/24 (synthetic). Cameras/printers/badge reader/sensor gateway/router.
    ("camera-iot-02", "10.10.8.41", "Linux 3.x (embedded)", "iot_device", 2, "Security", [(554, "rtsp", None, None), (80, "http", None, None)], False),
    ("camera-iot-03", "10.10.8.42", "Linux 3.x (embedded)", "iot_device", 2, "Security", [(554, "rtsp", None, None), (80, "http", None, None), (23, "telnet", "BusyBox telnetd", None)], False),
    ("printer-03", "10.10.8.22", "Linux 3.x (embedded)", "iot_device", 1, "Facilities", [(80, "http", None, None), (9100, "jetdirect", None, None), (631, "ipp", None, None), (21, "ftp", None, None)], False),
    ("badge-reader-01", "10.10.8.60", "Linux 4.x (embedded)", "iot_device", 4, "Security", [(80, "http", "GoAhead WebServer", "3.6.4")], False),
    ("temp-gw-01", "10.10.8.70", "Linux 4.9 (OpenWrt)", "iot_device", 3, "Facilities", [(22, "ssh", "Dropbear sshd", "2011.54"), (1883, "mqtt", "Mosquitto", "1.4.10"), (8080, "http", None, None)], False),
    ("router-iot-01", "10.10.8.1", "MikroTik RouterOS 6.40", "iot_device", 4, "Network Ops", [(8291, "winbox", "MikroTik RouterOS", "6.40.5"), (80, "http", None, None)], False),
]
# IoT metadata reported by the (fictional) passive IoT-discovery source "iot-inventory":
# device -> (vendor, model, firmware, default_credentials, telnet_enabled). Vendors tied to a real CVE in the seed
# catalog (Hikvision, MikroTik) are real names; the others are fictional.
IOT = {
    "printer-02": ("Generic", "laser printer", "3.4.1", "no", "no"),
    "printer-03": ("Generic", "multifunction printer", "3.4.1", "yes", "no"),
    "camera-iot-01": ("Hikvision", "DS-2CD2043", "5.5.101", "no", "no"),
    "camera-iot-02": ("Hikvision", "DS-2CD2143", "5.7.1", "no", "no"),   # patched firmware: no finding
    "camera-iot-03": ("Hikvision", "DS-2CD2032", "5.4.7", "yes", "yes"),  # old firmware + default creds + Telnet
    "badge-reader-01": ("Acme Access", "AC-900", "1.8.2", "yes", "no"),   # default web admin
    "temp-gw-01": ("Nordic Sensors", "TG-200", "0.9.4", "no", "no"),
    "router-iot-01": ("MikroTik", "hEX", "6.40.5", "no", "no"),
}
WS = [("ws-001", "Microsoft Windows 11", "Finance"), ("ws-002", "Microsoft Windows 11", "Finance"),
      ("ws-003", "Apple macOS 14", "Engineering"), ("ws-004", "Microsoft Windows 11", "HR"),
      ("ws-005", "Microsoft Windows 10", "Sales"), ("ws-006", "Microsoft Windows 11", "Sales")]
AWS = [("api-gateway-aws-01", "i-0a1b2c3d4e5f60001", "172.31.10.5", "203.0.113.50", "sg-0a1", "Platform"),
       ("orders-worker-aws-02", "i-0a1b2c3d4e5f60002", "172.31.10.9", None, "sg-0a2", "Orders"),
       ("reporting-aws-03", "i-0a1b2c3d4e5f60003", "172.31.20.4", None, "sg-0a2", "Analytics")]
K8S_NODES = [("k8s-node-01", "10.30.0.11"), ("k8s-node-02", "10.30.0.12")]
PODS = [("payments-api-7d9c5b6f4-x2k8p", "payments-api", "2.14.1", 8443, "10.244.1.17", "k8s-node-01"),
        ("orders-web-5f6b7c8d9-q7m2z", "orders-web", "1.9.0", 8080, "10.244.2.23", "k8s-node-02"),
        ("redis-cache-0", "redis", "7.2.4", 6379, "10.244.1.30", "k8s-node-01")]


def _mac(i, j=0):
    return f"52:54:00:{i:02x}:{j:02x}:{(i * 7 + j) % 256:02x}"


def _vm_uuid(name):
    h = abs(hash_str(name))
    return f"4223{h % 10**4:04d}-aaaa-bbbb-cccc-{h % 10**12:012d}"


def hash_str(s):  # stable (python's hash() is salted per process)
    v = 5381
    for ch in s:
        v = (v * 33 + ord(ch)) & 0xFFFFFFFF
    return v


def initial_state():
    hosts = {}
    for i, (n, ip, os_, typ, crit, owner, svcs, vm) in enumerate(HOSTS, start=1):
        hosts[n] = {"name": n, "ip": ip, "mac": _mac(i), "os": os_, "type": typ, "crit": crit, "owner": owner,
                    "svcs": [dict(port=p, name=nm, product=pr, version=v) for p, nm, pr, v in svcs], "vm": vm,
                    "up": True, "ssh_root": "no", "serial": None, "dhcp": False}
    for j, (n, os_, owner) in enumerate(WS, start=1):
        hosts[n] = {"name": n, "ip": f"10.10.5.{40 + j}", "mac": _mac(100 + j), "os": os_, "type": "workstation",
                    "crit": 2, "owner": owner, "svcs": [], "vm": False, "up": True, "ssh_root": None,
                    "serial": f"SN{hash_str(n) % 10**8:08d}", "dhcp": True}
    for n, (vendor, model, fw, dflt, tel) in IOT.items():
        hosts[n]["iot"] = {"vendor": vendor, "model": model, "firmware": fw, "default_credentials": dflt,
                           "telnet_enabled": tel}
    return {"hosts": hosts, "step": 0,
            "aws": {n: {"type": "t3.large"} for n, *_ in AWS},
            "azure": {"finance-vm-az-01": "running", "analytics-vm-az-02": "running"},
            "perimeter": {"web-proxy-01": [80, 443], "mail-01": [25, 993]},
            "scanner": [("10.10.6.12", "intranet-web-02", "CVE-2021-41773", 80, 7.5),
                        ("172.31.10.9", "orders-worker-aws-02", "CVE-2021-44228", 8443, 10.0),
                        ("10.10.8.42", "camera-iot-03", "CVE-2021-36260", 80, 9.8)],
            "pod_sw": {"payments-api-7d9c5b6f4-x2k8p": [("log4j-core", "2.14.1")]}}


def churn(st, rng, day):
    """Ordinary day-to-day infrastructure noise (becomes the anomaly baseline)."""
    used = {h["ip"] for h in st["hosts"].values()}
    for h in st["hosts"].values():
        if h["dhcp"] and rng.random() < 0.18:
            for _ in range(20):
                ip = f"10.10.5.{rng.randint(41, 120)}"
                if ip not in used:
                    used.discard(h["ip"])
                    used.add(ip)
                    h["ip"] = ip
                    break
    for n in st["aws"]:
        if rng.random() < 0.08:
            st["aws"][n]["type"] = "m5.large" if st["aws"][n]["type"] == "t3.large" else "t3.large"
    dev = st["hosts"]["dev-server-02"]
    if rng.random() < 0.3:
        if any(s["port"] == 80 for s in dev["svcs"]):
            dev["svcs"] = [s for s in dev["svcs"] if s["port"] != 80]
        else:
            dev["svcs"].append(dict(port=80, name="http", product="nginx", version="1.24.0"))
    upgrades = {10: ("dev-server-02", 22, "9.7p1"), 8: ("mail-01", 25, "3.7.5"), 6: ("db-server-01", 5432, "15.5"),
                4: ("web-proxy-01", 80, "1.24.1")}
    if day in upgrades:
        n, port, ver = upgrades[day]
        for s in st["hosts"][n]["svcs"]:
            if s["port"] == port:
                s["version"] = ver
    if day == 5:  # ordinary maintenance: lobby camera firmware update (not vulnerable before or after)
        st["hosts"]["camera-iot-02"]["iot"]["firmware"] = "5.7.3"
    if day == 12:
        st["hosts"]["mail-01"]["svcs"] = [s for s in st["hosts"]["mail-01"]["svcs"] if s["port"] != 993] + [
            dict(port=993, name="imaps", product="Dovecot", version="2.3.19")]


def step1(st):
    """Emerging-risk scenario: exposure + new service + risky config on a critical server."""
    a = st["hosts"]["app-server-01"]
    a["ip"] = "10.10.1.45"
    a["svcs"].append(dict(port=8009, name="ajp13", product="Apache Tomcat", version="9.0.30"))
    a["ssh_root"] = "yes"
    st["perimeter"]["app-server-01"] = [443, 8009]
    st["pod_sw"]["app-server-01"] = [("apache-tomcat", "9.0.30")]
    for s in st["hosts"]["files-01"]["svcs"]:
        if s["port"] == 445:
            s["product"], s["version"] = "SMBv1", None
    st["hosts"]["unknown-device"] = {"name": None, "ip": "10.10.9.77", "mac": "02:42:ac:11:00:77", "os": "Linux 4.x",
                                      "type": "unknown", "crit": 3, "owner": None, "vm": False, "up": True,
                                      "ssh_root": None, "serial": None, "dhcp": False,
                                      "svcs": [dict(port=22, name="ssh", product="Dropbear sshd", version="2019.78"),
                                               dict(port=80, name="http", product=None, version=None)]}
    # IoT drift: Telnet switched on for a camera; the sensor gateway's MQTT broker gets port-forwarded to the internet
    cam = st["hosts"]["camera-iot-01"]
    cam["svcs"].append(dict(port=23, name="telnet", product="BusyBox telnetd", version=None))
    cam["iot"]["telnet_enabled"] = "yes"
    st["perimeter"]["temp-gw-01"] = [1883]
    st["scanner"] += [("10.10.1.45", "app-server-01", "CVE-2020-1938", 8009, 9.8),
                      ("10.10.3.15", "files-01", "CVE-2017-0144", 445, 8.1)]
    st["step"] = 1


# ------------------------------------------------------------------ payload builders (vendor formats)
def _epoch(ts):
    return calendar.timegm(ts.timetuple())


def nmap_xml(st, ts):
    e = _epoch(ts)
    out = [f'<?xml version="1.0"?><nmaprun scanner="nmap" start="{e}">']
    for h in st["hosts"].values():
        if not h["up"]:
            continue
        out.append(f'<host endtime="{e}"><status state="up"/><address addr="{h["ip"]}" addrtype="ipv4"/>'
                   f'<address addr="{h["mac"]}" addrtype="mac"/>')
        if h["name"] and h["name"] != "ws-006":
            out.append(f'<hostnames><hostname name="{h["name"]}" type="PTR"/></hostnames>')
        out.append("<ports>")
        for s in h["svcs"]:
            attrs = f'name={quoteattr(s["name"] or "")}'
            if s.get("product"):
                attrs += f' product={quoteattr(s["product"])}'
            if s.get("version"):
                attrs += f' version={quoteattr(s["version"])}'
            out.append(f'<port protocol="tcp" portid="{s["port"]}"><state state="open"/><service {attrs}/></port>')
        out.append(f'</ports><os><osmatch name={quoteattr(h["os"])}/></os></host>')
    out.append("</nmaprun>")
    return "".join(out)


def cmdb_csv(st):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "hostname", "mac", "os", "owner", "criticality", "type", "tags", "serial"])
    for h in st["hosts"].values():
        if not h["name"]:
            continue
        ws6 = h["name"] == "ws-006"
        host = f"{h['name']}.{DOMAIN}" if h["type"] == "workstation" else h["name"]
        w.writerow([h["ip"], host, "" if ws6 else h["mac"], h["os"].replace("Linux 5.15 (", "").rstrip(")"), h["owner"] or "",
                    h["crit"], h["type"], "cmdb;managed", h["serial"] or ""])
    return buf.getvalue()


def vcenter_obs(st):
    out = []
    for h in st["hosts"].values():
        if not h["vm"]:
            continue
        out.append({"category": "virtualization",
                    "identifiers": {"hostname": [h["name"]], "device_id": [_vm_uuid(h["name"])], "ip": [h["ip"]]},
                    "attributes": {"os": h["os"], "relations": [{"type": "runs_on", "direction": "out", "target": {"hostname": "esx-host-01"}}],
                                   "config": {"vcpu": 4, "memory_gb": 16, "vm_tools": "running"}},
                    "raw_ref": f"vcenter:{h['name']}"})
    return out


def aws_json(st, ts):
    insts, sgs = [], [{"GroupId": "sg-0a1", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
                      {"GroupId": "sg-0a2", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8443, "IpRanges": [{"CidrIp": "172.31.0.0/16"}]}]}]
    for i, (n, iid, ip, pub, sg, owner) in enumerate(AWS, start=1):
        d = {"InstanceId": iid, "PrivateIpAddress": ip, "NetworkInterfaces": [{"MacAddress": f"0a:58:ac:1f:{i:02x}:05"}],
             "Tags": [{"Key": "Name", "Value": n}, {"Key": "Owner", "Value": owner}], "State": {"Name": "running"},
             "InstanceType": st["aws"][n]["type"], "ImageId": "ami-0abc", "VpcId": "vpc-01", "SecurityGroups": [{"GroupId": sg}],
             "Placement": {"AvailabilityZone": "eu-west-1a"}, "PlatformDetails": "Linux/UNIX"}
        if pub:
            d["PublicIpAddress"] = pub
        insts.append(d)
    return {"Reservations": [{"Instances": insts}], "SecurityGroups": sgs}


def azure_json(st):
    base = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-corp/providers/Microsoft.Compute/virtualMachines/"
    return [{"id": base + n, "vmId": f"9f3c{i}a10-0000-4000-8000-00000000000{i}", "name": n, "privateIps": ip, "publicIps": "",
             "powerState": st["azure"][n], "location": "westeurope", "resourceGroup": "rg-corp",
             "hardwareProfile": {"vmSize": "Standard_D4s_v5"}, "storageProfile": {"osDisk": {"osType": os_}}, "tags": {"env": "prod"}}
            for i, (n, ip, os_) in enumerate([("finance-vm-az-01", "10.20.1.4", "Windows"), ("analytics-vm-az-02", "10.20.2.4", "Linux")], start=1)]


def oci_json():
    return {"data": [{"id": "ocid1.instance.oc1.eu-frankfurt-1.anrw0000000000000001", "display-name": "data-lake-oci-01",
                      "shape": "VM.Standard.E4.Flex", "lifecycle-state": "RUNNING", "availability-domain": "AD-1"}]}


def k8s_json():
    items = []
    for i, (n, ip) in enumerate(K8S_NODES, start=1):
        items.append({"kind": "Node", "metadata": {"name": n},
                      "status": {"addresses": [{"type": "Hostname", "address": n}, {"type": "InternalIP", "address": ip}],
                                 "nodeInfo": {"systemUUID": f"ec2c0000-0000-4000-8000-00000000000{i}", "osImage": "Ubuntu 22.04.4 LTS",
                                              "kubeletVersion": "v1.29.4", "kernelVersion": "5.15.0", "containerRuntimeVersion": "containerd://1.7.13"}}})
    for name, img, ver, port, ip, node in PODS:
        items.append({"kind": "Pod", "metadata": {"name": name, "namespace": "prod", "uid": f"uid-{name[-5:]}"},
                      "spec": {"nodeName": node, "containers": [{"image": f"registry.corp.example.com/{img}:{ver}",
                                                                   "ports": [{"containerPort": port, "protocol": "TCP"}]}]},
                      "status": {"podIP": ip, "phase": "Running"}})
    return {"items": items}


def app_inventory_obs(st):
    out = []
    # software inventory + dependency knowledge reported by the application inventory
    for pod, ip, deps in [("payments-api-7d9c5b6f4-x2k8p", "10.244.1.17", [{"hostname": "db-server-01"}]),
                          ("orders-web-5f6b7c8d9-q7m2z", "10.244.2.23", [{"hostname": "payments-api-7d9c5b6f4-x2k8p"}])]:
        out.append({"category": "application_inventory", "identifiers": {"hostname": [pod], "ip": [ip]},
                    "attributes": {"software": [{"product": p, "version": v} for p, v in st["pod_sw"].get(pod, [])],
                                   "relations": [{"type": "depends_on", "direction": "out", "target": t} for t in deps]},
                    "raw_ref": f"appinv:{pod}"})
    a = st["hosts"]["app-server-01"]
    out.append({"category": "application_inventory", "identifiers": {"hostname": ["app-server-01"], "ip": [a["ip"]]},
                "attributes": {"software": [{"product": p, "version": v} for p, v in st["pod_sw"].get("app-server-01", [])] or
                                           [{"product": "payments-core", "version": "5.2.1"}],
                               "config": {"ssh_permit_root_login": a["ssh_root"]},
                               "relations": [{"type": "depends_on", "direction": "out", "target": {"hostname": "db-server-01"}}]},
                "raw_ref": "appinv:app-server-01"})
    out.append({"category": "application_inventory", "identifiers": {"hostname": ["ci-server-01"], "ip": [st["hosts"]["ci-server-01"]["ip"]]},
                "attributes": {"relations": [{"type": "connects_to", "direction": "out", "target": {"hostname": "app-server-01"}}]},
                "raw_ref": "appinv:ci-server-01"})
    out.append({"category": "application_inventory", "identifiers": {"hostname": ["web-proxy-01"], "ip": [st["hosts"]["web-proxy-01"]["ip"]]},
                "attributes": {"relations": [{"type": "connects_to", "direction": "out", "target": {"hostname": "app-server-01"}}]},
                "raw_ref": "appinv:web-proxy-01"})
    return out


def iot_inventory_obs(st):
    """Passive IoT discovery feed: firmware (as software), vendor/model and risky-config flags, plus uplinks."""
    out = []
    for n in IOT:
        h = st["hosts"][n]
        m = h["iot"]
        target = "fw-edge-01" if n == "router-iot-01" else "router-iot-01"
        out.append({"category": "iot_inventory",
                    "identifiers": {"hostname": [n], "ip": [h["ip"]], "mac": [h["mac"]]},
                    "attributes": {"type": "iot_device",
                                   "software": [{"product": f"{m['vendor']} firmware", "version": m["firmware"]}],
                                   "config": {"vendor": m["vendor"], "model": m["model"],
                                              "default_credentials": m["default_credentials"],
                                              "telnet_enabled": m["telnet_enabled"],
                                              "firmware_support": "end_of_life" if n in ("printer-03", "badge-reader-01") else "unknown",
                                              "lifecycle_source": "CMDB inventory"},
                                   "relations": [{"type": "connects_to", "direction": "out", "target": {"hostname": target}}]},
                    "raw_ref": f"iotinv:{n}"})
    return out


def scanner_csv(st):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "hostname", "cve", "port", "cvss", "evidence"])
    for ip, host, cve, port, cvss in st["scanner"]:
        w.writerow([ip, host, cve, port, cvss, "authenticated scan"])
    return buf.getvalue()


def perimeter_obs(st):
    out = []
    for name, ports in st["perimeter"].items():
        h = st["hosts"][name]
        out.append({"category": "perimeter_policy", "identifiers": {"hostname": [name], "ip": [h["ip"]]},
                    "attributes": {"services": [{"port": p, "proto": "tcp", "exposure": "external"} for p in ports]},
                    "raw_ref": f"fw:{name}"})
    return out


# ------------------------------------------------------------------ orchestration
SOURCES = [("cmdb-inventory", "csv_hosts", "cmdb"), ("corp-network-scan", "nmap_xml", "infrastructure"),
           ("vmware-vcenter", "generic_json", "virtualization"), ("aws-prod", "aws_ec2", "cloud"),
           ("azure-corp", "azure_vm", "cloud"), ("oci-analytics", "oci_instances", "cloud"),
           ("k8s-prod", "k8s_json", "container"), ("app-inventory", "generic_json", "infrastructure"),
           ("vuln-scanner", "vuln_scan", "security"), ("perimeter-firewall", "generic_json", "infrastructure"),
           ("iot-inventory", "generic_json", "iot")]


def _sources(db: Session):
    out = {}
    for name, kind, cat in SOURCES:
        s = db.query(Source).filter(Source.name == name).first()
        if not s:
            s = Source(name=name, kind=kind, category=cat, enabled=True, verified=True, frequency_minutes=0,
                       config={"cluster_name": "prod-k8s"} if kind == "k8s_json" else {},
                       auth_status="ok", status="ok")
            db.add(s)
            db.flush()
        out[name] = s
    db.commit()
    return out


def _push(db, src, raws, ts):
    for r in raws:
        r.pop("_launch", None)
        r["observed_at"] = iso(ts)
    src.last_attempt = src.last_success = now()
    src.status = "ok"
    return pipeline.ingest(db, src, raws, raw_ref="inventory-history")["counts"]


def collect_all(db, srcs, st, ts, include_cmdb=True):
    c = {}
    if include_cmdb:
        c["cmdb"] = _push(db, srcs["cmdb-inventory"], mappers.parse_csv_hosts(cmdb_csv(st)), ts)
    c["nmap"] = _push(db, srcs["corp-network-scan"], mappers.parse_nmap_xml(nmap_xml(st, ts)), ts)
    c["vc"] = _push(db, srcs["vmware-vcenter"], vcenter_obs(st), ts)
    c["aws"] = _push(db, srcs["aws-prod"], mappers.parse_aws_ec2(aws_json(st, ts)), ts)
    c["az"] = _push(db, srcs["azure-corp"], mappers.parse_azure_vms(azure_json(st)), ts)
    c["oci"] = _push(db, srcs["oci-analytics"], mappers.parse_oci_instances(oci_json()), ts)
    c["k8s"] = _push(db, srcs["k8s-prod"], mappers.parse_k8s(k8s_json(), "prod-k8s"), ts)
    c["app"] = _push(db, srcs["app-inventory"], app_inventory_obs(st), ts)
    c["iot"] = _push(db, srcs["iot-inventory"], iot_inventory_obs(st), ts)
    c["vuln"] = _push(db, srcs["vuln-scanner"], mappers.parse_vuln_scan(scanner_csv(st), "scan.csv"), ts)
    c["fw"] = _push(db, srcs["perimeter-firewall"], perimeter_obs(st), ts)
    return c


def _get(db, key, default=None):
    r = db.get(Setting, key)
    return r.value if r else default


def _set(db, key, value):
    r = db.get(Setting, key)
    if r:
        r.value = value
    else:
        db.add(Setting(key=key, value=value))
    db.commit()


def _state_from_db(db):
    """The world state is deterministic: rebuild by replaying churn so advance() works after a restart."""
    st = initial_state()
    rng = random.Random(42)
    for day in range(14, 0, -1):
        churn(st, rng, day)
    if _get(db, "demo_step", 0) >= 1:
        step1(st)
    return st


def is_loaded(db):
    return bool(_get(db, "demo_step") is not None)


def load(days=14):
    """Backdated history + current baseline. Safe to call once on an empty database."""
    try:
        PROGRESS.update(state="running", detail="starting", done=0, total=days + 1)
        with session_scope() as db:
            intel.seed_vulnerabilities(db)
            srcs = _sources(db)
            st = initial_state()
            rng = random.Random(42)
            today = now()
            anomaly_engine.LEARNING["on"] = True  # history = learning window for the anomaly model
            try:
                for i, d in enumerate(range(days, 0, -1)):
                    ts = datetime.combine((today - timedelta(days=d)).date(), time(10, 0))
                    churn(st, rng, d)
                    PROGRESS.update(detail=f"day -{d}", done=i)
                    collect_all(db, srcs, st, ts, include_cmdb=(d % 3 == 2))
            finally:
                anomaly_engine.LEARNING["on"] = False
            PROGRESS.update(detail="learning baseline", done=days)
            db.commit()
            ml.retrain_anomaly()
            PROGRESS.update(detail="current state", done=days)
            collect_all(db, srcs, st, today - timedelta(minutes=5), include_cmdb=True)
            risk.reassess_all(db, force=True)
            _set(db, "demo_step", 0)
        ml.register_models()
        PROGRESS.update(state="done", detail="demo dataset loaded", done=days + 1)
    except Exception as e:  # noqa: BLE001
        log.exception("demo load failed")
        PROGRESS.update(state="error", detail=f"{type(e).__name__}: {e}")


def advance():
    with session_scope() as db:
        if _get(db, "demo_step") is None:
            raise ValueError("demo dataset is not loaded")
        if _get(db, "demo_step", 0) >= 1:
            raise ValueError("the drift scenario has already been applied (reset the demo to replay it)")
        st = _state_from_db(db)
        srcs = _sources(db)
        step1(st)
        counts = collect_all(db, srcs, st, now() - timedelta(minutes=1), include_cmdb=True)
        risk.reassess_all(db, force=True)
        _set(db, "demo_step", 1)
        return counts


def wipe(db: Session):
    keep = {"users", "audit_log", "schema_versions"}
    for t in reversed(Base.metadata.sorted_tables):
        if t.name == "settings":
            # Liveness heartbeats must survive a reset, otherwise /api/health reports a stale worker until the next pulse.
            db.execute(t.delete().where(~t.c.key.like("%\\_heartbeat", escape="\\")))
        elif t.name not in keep:
            db.execute(t.delete())
    db.commit()
