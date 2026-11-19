#!/usr/bin/env python3
"""Register the IoT lab in a running DEEPSIGHT and scan it. Standard library only; run from the project root.

  python lab/scan_lab.py  # reads ASIVM_ADMIN_USER / ASIVM_ADMIN_PASSWORD, or prompts securely

Steps: (1) import lab/lab_inventory.json (what a passive IoT-discovery tool would report: firmware, vendor, risky config),
(2) live TCP-connect scan of the four lab devices (only reachable from inside the compose network, which is why the
scan runs inside the app container), (3) print what was found. Safe to re-run (integrations are reused).
"""
import argparse
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
_PREFIX = os.getenv("ASIVM_LAB_PREFIX", "172.28.50")
TARGETS = {f"{_PREFIX}.10": "lab-camera-01", f"{_PREFIX}.11": "lab-telnet-01",
           f"{_PREFIX}.12": "lab-gateway-01", f"{_PREFIX}.13": "lab-mqtt-01"}
PORTS = [21, 22, 23, 80, 443, 554, 1883, 2323, 8080, 8291, 8883, 9100]
SCAN_NAME, INV_NAME = "iot-lab-scan", "iot-lab-inventory"


class Api:
    def __init__(self, base):
        self.base, self.token = base.rstrip("/"), None

    def call(self, method, path, body=None):
        req = urllib.request.Request(self.base + "/api" + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            sys.exit(f"{method} {path} -> HTTP {e.code}: {e.read().decode()[:300]}")
        except urllib.error.URLError as e:
            sys.exit(f"cannot reach {self.base}: {e.reason}. Is the stack up?")


def ensure(api, name, kind, config):
    for s in api.call("GET", "/integrations"):
        if s["name"] == name:
            return s["id"]
    return api.call("POST", "/integrations", {"name": name, "kind": kind, "config": config, "frequency_minutes": 0})["id"]


def main():
    global TARGETS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--prefix", default=_PREFIX)
    ap.add_argument("--url", default=os.getenv("ASIVM_URL", "http://localhost:8000"))
    a = ap.parse_args()
    TARGETS = {f"127.0.0.{i+2}" if a.local else f"{a.prefix}.{i+10}": name for i, name in enumerate(["lab-camera-01", "lab-telnet-01", "lab-gateway-01", "lab-mqtt-01"])}
    user = os.getenv("ASIVM_ADMIN_USER", "admin")
    password = os.getenv("ASIVM_ADMIN_PASSWORD") or getpass.getpass("DEEPSIGHT administrator password: ")
    api = Api(a.url)
    api.token = api.call("POST", "/auth/login", {"username": user, "password": password})["token"]

    inv_id = ensure(api, INV_NAME, "generic_json", {})
    with open(os.path.join(HERE, "lab_inventory.json"), encoding="utf-8") as handle:
        records = json.load(handle)
    addresses = {name: ip for ip, name in TARGETS.items()}
    for record in records:
        record["identifiers"]["ip"] = [addresses[record["identifiers"]["hostname"][0]]]
        record["observed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    content = json.dumps(records)
    run = api.call("POST", f"/integrations/{inv_id}/import", {"filename": "lab_inventory.json", "content": content})
    print(f"[1/3] inventory import: {run['status']} (received {run['received']}, processed {run['processed']}, failed {run['failed']})")
    if run["status"] != "ok" or run["failed"] or run["rejected"]:
        sys.exit("Inventory import failed: " + str(run))

    scan_id = ensure(api, SCAN_NAME, "tcp_discovery", {
        "authorized": True, "targets": list(TARGETS), "ports": PORTS, "timeout": 2.0,
        "hostnames": TARGETS, "asset_type": "iot_device"})
    test = api.call("POST", f"/integrations/{scan_id}/test")
    if not test.get("ok"):
        sys.exit(f"scan config rejected: {test}")
    api.call("POST", f"/integrations/{scan_id}/collect")
    for _ in range(60):
        time.sleep(1)
        st = api.call("GET", f"/integrations/{scan_id}/status")
        if st["status"] not in ("running", "queued"):
            break
    else:
        sys.exit("The collection has not finished; inspect Administration → Jobs and the worker.")
    runs = api.call("GET", f"/integrations/{scan_id}/runs")
    r = runs[0] if runs else {}
    print(f"[2/3] live scan of {len(TARGETS)} devices: {r.get('status')} (received {r.get('received')}, failed {r.get('failed')})"
          + (f" - {r.get('error')}" if r.get("error") else ""))

    if r.get("status") != "ok" or r.get("failed") or r.get("received") != len(TARGETS):
        sys.exit("The live scan did not return all four devices successfully; inspect the lab and collection run.")

    print("[3/3] lab assets in DEEPSIGHT:")
    items = api.call("GET", "/assets?q=lab-&size=50")["items"]
    for x in sorted(items, key=lambda i: i["name"]):
        print(f"   {x['name']:<16} {x['type']:<11} {','.join(x['ips']):<14} findings={x['open_findings']} "
              f"risk={x['risk_level']}({x['risk_score']}) identity={x['identity_status']}")
    pend = api.call("GET", "/identity/decisions?status=pending")
    print(f"   pending identity decisions: {len(pend.get('items', []))}")
    print(f"\nOpen {a.url} -> Assets, filter type = iot_device (names start with lab-).")


if __name__ == "__main__":
    main()
