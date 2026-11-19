"""Build portable inventory exports for the separate operator exercise.

The application is not changed by these file builders. Provenance is documented in
README.md beside the exports; file and source names follow normal operational naming.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random

NAMES = ["lab-camera-01", "lab-telnet-01", "lab-gateway-01", "lab-mqtt-01"]


def clean(value):
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items() if key not in ("demo", "guided_demo")}
    if isinstance(value, list):
        return [clean(item) for item in value if not (isinstance(item, str) and item in
                {"demo", "guided-demo", "synthetic-history", "synthetic-scenario", "synthetic-verification"})]
    if isinstance(value, str):
        value = re.sub(r"(?i)synthetic demo inventory", "Inventory export", value)
        value = re.sub(r"(?i)\bdemo\b", "reference", value)
        return value
    return value


def exports(world, timestamp):
    from app import demo as builders
    return [
        ("CMDB inventory", "csv_hosts", "cmdb", "cmdb.csv", builders.cmdb_csv(world)),
        ("Corporate network scan", "nmap_xml", "infrastructure", "network-scan.xml", builders.nmap_xml(world, timestamp)),
        ("VMware inventory", "generic_json", "virtualization", "vcenter.json", builders.vcenter_obs(world)),
        ("AWS inventory", "aws_ec2", "cloud", "aws.json", builders.aws_json(world, timestamp)),
        ("Azure inventory", "azure_vm", "cloud", "azure.json", builders.azure_json(world)),
        ("OCI inventory", "oci_instances", "cloud", "oci.json", builders.oci_json()),
        ("Kubernetes inventory", "k8s_json", "container", "kubernetes.json", builders.k8s_json()),
        ("Application inventory", "generic_json", "infrastructure", "applications.json", builders.app_inventory_obs(world)),
        ("Device management inventory", "generic_json", "iot", "devices.json", builders.iot_inventory_obs(world)),
        ("Vulnerability scanner", "vuln_scan", "security", "vulnerabilities.csv", builders.scanner_csv(world)),
        ("Perimeter inventory", "generic_json", "infrastructure", "perimeter.json", builders.perimeter_obs(world)),
    ]


def normalized_history(world, timestamp):
    from app.connectors import REGISTRY
    rows = []
    for _name, kind, _category, filename, content in exports(world, timestamp):
        text = content if isinstance(content, str) else json.dumps(content)
        for row in REGISTRY[kind].parse(text, filename, {"cluster_name": "prod-k8s"}):
            row.pop("_launch", None)
            row["observed_at"] = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
            rows.append(clean(row))
    return rows


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    value = clean(content)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2))


def assessment(timestamp=None):
    timestamp = timestamp or datetime.now(timezone.utc)
    return [{"identifiers": {"cloud_id": ["i-0a1b2c3d4e5f60002"], "hostname": ["orders-worker-aws-02"]},
             "category": "security", "observed_at": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "attributes": {"findings": [], "assessment": {"kind": "vulnerability", "status": "success",
                 "complete": True, "finding_codes": ["CVE-2021-44228"],
                 "scope": "Log4j check on orders-worker-aws-02"}}}]


def build(output, prefix="172.28.50", local=False, feed_url=None, verification_only=False):
    output = Path(output)
    if verification_only:
        write(output / "clean-assessment.json", assessment())
        return
    from app import demo as builders
    root = Path(__file__).resolve().parents[1]
    anchor = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)
    world, rng = builders.initial_state(), random.Random(42)
    history = []
    for day in range(14, 0, -1):
        builders.churn(world, rng, day)
        history.extend(normalized_history(world, anchor - timedelta(days=day)))
    write(output / "baseline-history.json", history)
    manifest = []
    for name, kind, category, filename, content in exports(world, anchor):
        if kind == "generic_json":
            for row in content:
                row["observed_at"] = anchor.strftime("%Y-%m-%dT%H:%M:%SZ")
        write(output / "current" / filename, content)
        manifest.append({"file": "current/" + filename, "drift_file": "drift/" + filename,
                         "source": name, "kind": kind, "category": category,
                         "config": {"cluster_name": "prod-k8s"} if kind == "k8s_json" else {}})
    builders.step1(world)
    for _name, kind, _category, filename, content in exports(world, anchor + timedelta(minutes=2)):
        if kind == "generic_json":
            for row in content:
                row["observed_at"] = (anchor + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        write(output / "drift" / filename, content)
    targets = {f"127.0.0.{index + 2}" if local else f"{prefix}.{index + 10}": name
               for index, name in enumerate(NAMES)}
    records = json.loads((root / "lab/lab_inventory.json").read_text())
    by_name = {name: address for address, name in targets.items()}
    for row in records:
        row["identifiers"]["ip"] = [by_name[row["identifiers"]["hostname"][0]]]
        row["observed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write(output / "lab-inventory.json", records)
    write(output / "scan-config.json", {"authorized": True, "targets": list(targets), "hostnames": targets,
        "asset_type": "iot_device", "ports": [21, 22, 23, 80, 443, 554, 1883, 8080, 8291, 8883, 9100],
        "timeout": .6, "max_hosts": 4})
    write(output / "clean-assessment.json", assessment())
    current = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write(output / "intelligence/nvd.json", {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI endpoints in affected versions."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]}, "configurations": [], "references": []}}]})
    snapshot = json.loads((root / "lab/epss-snapshot.json").read_text())
    write(output / "intelligence/epss.json", snapshot["records"])
    write(output / "package-scans/trivy.json", {"ArtifactName": "payments-worker-image", "CreatedAt": current,
        "Results": [{"Target": "application packages", "Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228",
            "PkgName": "log4j-core", "InstalledVersion": "2.14.1", "FixedVersion": "2.17.1",
            "Title": "Apache Log4j remote code execution", "CVSS": {"nvd": {"V3Score": 10.0}}}]}]})
    write(output / "package-scans/grype.json", {"source": {"target": {"userInput": "payments-worker-image"}}, "CreatedAt": current,
        "matches": [{"vulnerability": {"id": "CVE-2021-44228", "description": "Apache Log4j remote code execution",
            "cvss": [{"metrics": {"baseScore": 10.0}}], "fix": {"versions": ["2.17.1"]}},
            "artifact": {"name": "log4j-core", "version": "2.14.1", "locations": []}}]})
    feed_url = (feed_url or f"http://{prefix}.20:8081").rstrip("/")
    write(output / "manifest.json", {"generated_at": current, "imports": manifest,
        "scan_source": {"name": "Network discovery", "kind": "tcp_discovery", "config_file": "scan-config.json"},
        "lab_inventory_source": {"name": "Device inventory", "kind": "generic_json", "file": "lab-inventory.json"},
        "history_source": {"name": "Historical inventory", "kind": "generic_json", "file": "baseline-history.json"},
        "http_source": {"name": "Asset API", "kind": "http_json", "config": {"url": feed_url + "/inventory", "mapper": "generic_json", "timeout": 5}},
        "webhook_source": {"name": "Security alerts", "kind": "outbound_webhook", "config": {"url": feed_url + "/webhook"}},
        "verification_source": {"name": "Verification scan", "kind": "generic_json", "file": "clean-assessment.json"}})
    (output / "README.md").write_text("""# Operator exercise files

These exports describe a fictional organization and deliberately vulnerable lab devices.
They are supplied for a presentation rehearsal and are not observations of your production
infrastructure. Package imports are controlled scanner-export fixtures. The EPSS file preserves the
FIRST API measurement and date retrieved on 19 November 2026; see lab/epss-snapshot.json.
Refresh from FIRST when current intelligence is required. The clean assessment represents the planned
verification exercise, not an actual patch of a production resource.

Use the normal Integrations screens to scan and import. Select connectors using manifest.json.
Import baseline-history.json as Generic observations; retrain in Intelligence → Models, then
import current/ and drift/ files using the same named sources. Device inventory is mapped to
the addresses in scan-config.json. Refresh only clean-assessment.json after the latest finding
evidence: python3 scripts/prepare_imports.py --output <this folder> --verification-only.

The application contains no extra presentation dashboard or control page.
""")
