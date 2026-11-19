#!/usr/bin/env python3
"""Exercise normal analyst and administration workflows on an explicitly prepared lab database.

This is an explicit automated rehearsal: it triages findings, makes/reverts one identity
choice, creates and validates a synthetic investigation, and verifies the prepared fix.
It never calls external feeds or an LLM. Evidence is written under work/ by default.
"""
import argparse
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class Client:
    def __init__(self, url, token):
        self.url, self.token, self.checks = url.rstrip("/"), token, []

    def call(self, method, path, body=None):
        request = urllib.request.Request(self.url + "/api" + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token})
        with urllib.request.urlopen(request, timeout=600 if path.endswith("/import") else 60) as response:
            raw = response.read()
            content_type = response.headers.get("Content-Type", "")
            self.checks.append({"method": method, "path": path, "http_status": response.status,
                "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        return json.loads(raw) if "application/json" in content_type else raw.decode()


def exercise(url, token, imports, population, output=None):
    client = Client(url, token)
    initial = population["initial_counts"]
    findings = client.call("GET", "/findings?size=200")["items"]
    if not findings:
        raise RuntimeError("The database has no open findings to exercise.")
    ids = [f["id"] for f in findings[:3]]
    due = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    client.call("PUT", "/saved-filters", {"name": "Owner queue", "filters": {"owner": "Payments analyst", "state": "in_progress"}})
    bulk = client.call("POST", "/bulk-triage", {"finding_ids": ids, "workflow": {
        "state": "in_progress", "owner": "Payments analyst", "due_date": due,
        "note": "Assign ownership and prioritize overdue remediation."}})
    queue = client.call("GET", "/work-queue?owner=Payments%20analyst")
    if not queue.get("items"):
        raise RuntimeError("Saved/bulk-triaged owner queue is unexpectedly empty.")
    client.call("GET", "/saved-filters")
    what_if = client.call("GET", f"/findings/{ids[0]}/what-if")
    expiry = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    client.call("PATCH", f"/findings/{ids[-1]}", {"state": "accepted_risk", "reason": "Documented temporary operational exception", "approver": "Payments owner", "expiry": expiry})
    client.call("PATCH", f"/findings/{ids[-1]}", {"state": "false_positive", "reason": "Reviewed configuration exception", "approver": "Payments owner", "expiry": expiry})
    client.call("PATCH", f"/findings/{ids[-1]}", {"state": "confirmed", "note": "Returned to confirmed after rehearsing exception workflows."})
    pending = client.call("GET", "/identity/decisions?status=pending&size=200")["items"]
    identity_events = []
    for decision in pending:
        if str(decision.get("asset", "")).startswith("lab-") and decision.get("asset") == decision.get("candidate"):
            client.call("POST", f"/identity/decisions/{decision['id']}/confirm", {})
            merged = client.call("GET", f"/assets/{decision['candidate_asset_id']}")
            if merged.get("owner") != "Lab" or not merged.get("config", {}).get("vendor"):
                raise RuntimeError("Confirmed lab identity did not retain imported inventory owner/vendor profile.")
            identity_events.append({"id": decision["id"], "action": "confirmed_lab_match"})
    pending = client.call("GET", "/identity/decisions?status=pending&size=200")["items"]
    if pending:
        decision = pending[0]
        client.call("POST", f"/identity/decisions/{decision['id']}/confirm", {})
        client.call("POST", f"/identity/decisions/{decision['id']}/revert", {})
        identity_events.append({"id": decision["id"], "action": "confirmed_then_reverted"})
    else:
        previous = client.call("GET", "/identity/decisions?status=reverted&size=200")["items"]
        if not previous:
            raise RuntimeError("No organisation identity decision is available for confirm/revert rehearsal.")
        identity_events.append({"id": previous[0]["id"], "action": "previous_confirm_revert_verified"})
    assets = client.call("GET", "/assets?q=app-server-01&size=50")["items"]
    app_asset = next(a for a in assets if a["name"] == "app-server-01")
    detail = client.call("GET", f"/assets/{app_asset['id']}")
    client.call("PATCH", f"/assets/{app_asset['id']}", {"owner": "Payments analyst", "criticality": 4})
    impact = client.call("GET", f"/assets/{app_asset['id']}/impact")
    graph = client.call("GET", "/graph")
    if not graph.get("edges"):
        raise RuntimeError("The imported inventory has no relationship edges.")
    db_asset = next(a for a in client.call("GET", "/assets?q=db-server-01&size=50")["items"] if a["name"] == "db-server-01")
    client.call("POST", "/relationships", {"src_id": app_asset["id"], "dst_id": db_asset["id"], "type": "connects_to"})
    relationships = client.call("GET", f"/assets/{app_asset['id']}/relationships")
    added = next(r for r in relationships if r["direction"] == "out" and r["other_id"] == db_asset["id"] and r["type"] == "connects_to" and not r.get("valid_to"))
    client.call("DELETE", f"/relationships/{added['id']}")
    search = client.call("GET", "/search?q=" + urllib.parse.quote("app-server-01"))
    anomalies = client.call("GET", "/anomalies?size=200")["items"]
    if not anomalies:
        raise RuntimeError("Drift did not produce an anomaly to review.")
    anomaly = anomalies[0]
    client.call("PATCH", f"/anomalies/{anomaly['id']}", {"status": "reviewed", "note": "Reviewed service exposure change and source evidence."})
    investigation = client.call("POST", "/investigations", {"title": "Review application exposure change",
        "asset_ids": [app_asset["id"]], "finding_ids": ids[:1], "anomaly_ids": [anomaly["id"]],
        "note": "Review scanner evidence, service changes and affected dependencies."})
    iid = investigation["id"]
    client.call("POST", f"/investigations/{iid}/notes", {"text": "Checked scanner evidence, service changes and affected dependencies."})
    client.call("PATCH", f"/investigations/{iid}", {"status": "in_progress"})
    validated = client.call("POST", f"/investigations/{iid}/validate", {"outcome": "true_positive", "conclusion": "The new AJP exposure is supported by the service observation. Remediation is assigned to the application owner."})
    if validated.get("status") != "closed":
        raise RuntimeError("Investigation validation did not close the case.")
    answer = client.call("POST", "/assistant/query", {"question": "Why has the risk of app-server-01 increased?", "context": {"asset_id": app_asset["id"]}})
    references = answer.get("references") or answer.get("citations") or []
    if not references:
        raise RuntimeError("Assistant returned no evidence references for the populated asset question.")
    client.call("GET", "/assistant/suggestions?asset_id=" + str(app_asset["id"]))
    fixture_nvd = json.loads((imports / "intelligence/nvd.json").read_text())
    fixture_epss = json.loads((imports / "intelligence/epss.json").read_text())
    client.call("POST", "/intelligence/nvd-import", fixture_nvd)
    client.call("POST", "/intelligence/epss", fixture_epss)
    client.call("GET", "/vulnerabilities/CVE-2021-44228")
    sources_by_name = {src["name"]: src for src in client.call("GET", "/integrations")}
    for kind, filename in [("trivy_json", "trivy.json"), ("grype_json", "grype.json")]:
        name = {"trivy_json": "Container package scan", "grype_json": "Container software scan"}[kind]
        source = sources_by_name.get(name)
        if not source:
            source = client.call("POST", "/integrations", {"name": name, "kind": kind, "config": {}, "frequency_minutes": 0})
        content = json.loads((imports / "package-scans" / filename).read_text())
        content["CreatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        imported = client.call("POST", f"/integrations/{source["id"]}/import", {"filename": filename, "content": json.dumps(content)})
        if imported["status"] != "ok" or imported["failed"] or imported["rejected"]:
            raise RuntimeError("Scanner import failed: " + filename)
    client.call("POST", "/intelligence/rematch", {})
    fid, oid = prepare_verification(client, imports)
    current = client.call("GET", f"/findings/{fid}")
    if current.get("status") == "open":
        client.call("PATCH", f"/findings/{fid}", {"state": "pending_verification", "owner": "Payments analyst"})
        verified = client.call("POST", f"/findings/{fid}/verify", {"observation_id": oid})
    else:
        verified = current.get("verification") or current.get("evidence", {}).get("verification")
    metrics = client.call("GET", "/remediation/metrics")
    if metrics["verified_fixes"] < 1:
        raise RuntimeError("Verification did not populate remediation metrics.")
    reports = client.call("GET", "/reports")
    report_results = []
    for report in reports:
        for fmt in ("json", "csv", "html"):
            exported = client.call("GET", f"/reports/{report['kind']}?format={fmt}")
            if not exported:
                raise RuntimeError(f"Empty report: {report['kind']} {fmt}")
            report_results.append({"kind": report["kind"], "format": fmt, "passed": True})
    client.call("POST", "/ml/retrain/anomaly", {})
    client.call("GET", "/ml/models")
    client.call("GET", "/intelligence")
    client.call("GET", "/risk-assessments?limit=200")
    client.call("GET", "/changes?hours=336&limit=200")
    client.call("GET", "/observations?size=200")
    integrations = client.call("GET", "/integrations")
    for src in integrations:
        runs = client.call("GET", f"/integrations/{src['id']}/runs")
        if src["kind"] != "outbound_webhook" and not runs:
            raise RuntimeError("Integration has no run history: " + src["name"])
    deliveries = client.call("GET", "/webhooks/deliveries")
    if not any(r.get("status") == "delivered" for r in deliveries):
        raise RuntimeError("No delivered webhook alerts were found.")
    client.call("GET", "/jobs")
    client.call("GET", "/metrics")
    client.call("GET", "/roles")
    client.call("GET", "/users")
    client.call("POST", "/system/lifecycle-sweep", {})
    client.call("POST", "/system/reassess", {})
    client.call("GET", "/settings/assessment-age")
    client.call("GET", "/system/status")
    client.call("GET", "/audit?size=200")
    final = summary(client)
    result = {"status": "passed", "url": url, "generated_at": datetime.now(timezone.utc).isoformat(),
        "initial_counts": initial, "final_counts": final, "checks": [*population["checks"], *client.checks], "population": population,
        "report_exports": report_results, "identity_events": identity_events, "investigation_id": iid,
        "verification": {"finding_id": fid, "observation_id": oid, "metrics": metrics},
        "assistant_references": len(references), "what_if": what_if,
        "bulk_triage": bulk, "search": search, "impact": impact, "asset_detail_loaded": bool(detail),
        "exceptions": "Online CISA/NVD refresh and optional external LLM mode need internet/credentials; this rehearsal uses labelled synthetic offline intelligence and the evidence assistant."}
    output = Path(output) if output else ROOT / "work" / "workflow-results.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2))
    print(f"Workflow checks passed: {len(result["checks"])} API checks, {len(report_results)} report exports. Evidence: {output}")
    return result



def summary(client):
    data = client.call("GET", "/overview")["metrics"]
    return {"assets": data["assets_total"], "findings": data["open_findings"],
            "anomalies": data["anomalies_open"], "investigations": data["investigations_open"]}


def source(client, name, kind, config=None, category=None):
    existing = next((row for row in client.call("GET", "/integrations") if row["name"] == name), None)
    if existing:
        if existing["kind"] != kind:
            raise RuntimeError(f"{name} is already configured with a different connector")
        return existing
    payload = {"name": name, "kind": kind, "config": config or {}, "frequency_minutes": 0}
    if category:
        payload["category"] = category
    return client.call("POST", "/integrations", payload)


def import_file(client, src, path):
    result = client.call("POST", f"/integrations/{src['id']}/import",
                         {"filename": path.name, "content": path.read_text()})
    if result["status"] != "ok" or result["failed"] or result["rejected"]:
        raise RuntimeError(f"Import failed for {path.name}: {result}")
    return result


def collect(client, src):
    import time
    previous = client.call("GET", f"/integrations/{src['id']}/runs")
    old_id = previous[0]["id"] if previous else 0
    tested = client.call("POST", f"/integrations/{src['id']}/test", {})
    if not tested.get("ok"):
        raise RuntimeError(f"Collector test failed: {tested}")
    client.call("POST", f"/integrations/{src['id']}/collect", {})
    for _ in range(240):
        runs = client.call("GET", f"/integrations/{src['id']}/runs")
        result = runs[0] if runs else None
        if result and result["id"] > old_id and result["status"] != "running":
            if result["status"] != "ok" or result["failed"]:
                raise RuntimeError(f"Collector failed: {result}")
            return result
        time.sleep(.5)
    raise RuntimeError("Collection has not completed; inspect its run history and the worker")


def populate(client, imports):
    import time
    initial = summary(client)
    if initial["assets"]:
        raise RuntimeError("This automated rehearsal requires an empty lab database. Use a fresh isolated deployment.")
    manifest = json.loads((imports / "manifest.json").read_text())
    scan_config = json.loads((imports / "scan-config.json").read_text())
    scan = source(client, "Network discovery", "tcp_discovery", scan_config)
    scan_result = collect(client, scan)
    if scan_result["received"] != 4:
        raise RuntimeError("The scan did not return all four isolated devices")
    print("Network discovery: four devices collected", flush=True)
    inventory = source(client, "Device inventory", "generic_json")
    records = json.loads((imports / "lab-inventory.json").read_text())
    for row in records:
        row["observed_at"] = datetime.now(timezone.utc).isoformat()
    result = client.call("POST", f"/integrations/{inventory['id']}/import", {"filename": "lab-inventory.json", "content": json.dumps(records)})
    if result["status"] != "ok" or result["failed"] or result["rejected"]:
        raise RuntimeError("The inventory import failed")
    history = source(client, "Historical inventory", "generic_json")
    print("Importing historical observations through the normal importer", flush=True)
    import_file(client, history, imports / "baseline-history.json")
    client.call("POST", "/ml/retrain/anomaly", {})
    for spec in manifest["imports"]:
        src = source(client, spec["source"], spec["kind"], spec.get("config"), spec.get("category"))
        import_file(client, src, imports / spec["file"])
    api_spec = manifest["http_source"]
    api_source = source(client, api_spec["name"], api_spec["kind"], api_spec["config"])
    collect(client, api_source)
    alert_spec = manifest["webhook_source"]
    source(client, alert_spec["name"], alert_spec["kind"], alert_spec["config"])
    print("Baseline inventory, scanner exports and HTTP collection completed", flush=True)
    for spec in manifest["imports"]:
        src = source(client, spec["source"], spec["kind"], spec.get("config"), spec.get("category"))
        import_file(client, src, imports / spec["drift_file"])
    client.call("POST", "/webhooks/dispatch", {})
    for _ in range(20):
        deliveries = client.call("GET", "/webhooks/deliveries")
        if any(row["status"] == "delivered" for row in deliveries):
            break
        time.sleep(.5)
    else:
        raise RuntimeError("No alert reached the configured receiver")
    client.call("POST", "/system/reassess", {})
    print("Exposure changes imported and alerts delivered", flush=True)
    return {"initial_counts": initial, "scan": scan_result, "final_counts": summary(client), "checks": client.checks}


def prepare_verification(client, imports):
    import time
    assets = client.call("GET", "/assets?q=orders-worker-aws-02&size=50")["items"]
    asset = next(row for row in assets if row["name"] == "orders-worker-aws-02")
    detail = client.call("GET", f"/assets/{asset['id']}")
    finding = next(row for row in detail["findings"] if row["cve"] == "CVE-2021-44228" and row["status"] == "open")
    time.sleep(1.1)
    rows = json.loads((imports / "clean-assessment.json").read_text())
    for row in rows:
        row["observed_at"] = datetime.now(timezone.utc).isoformat()
    (imports / "clean-assessment.json").write_text(json.dumps(rows, indent=2))
    src = source(client, "Verification scan", "generic_json")
    import_file(client, src, imports / "clean-assessment.json")
    observations = client.call("GET", f"/observations?asset_id={asset['id']}&source_id={src['id']}&size=50")["items"]
    observation = next(row for row in observations if row["status"] == "processed")
    return finding["id"], observation["id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("ASIVM_URL", "http://localhost:8001"))
    parser.add_argument("--imports", type=Path, required=True, help="Generated import folder printed by start_lab.py")
    parser.add_argument("--output", type=Path, default=ROOT / "work/workflow-results.json")
    args = parser.parse_args()
    password = os.getenv("ASIVM_ADMIN_PASSWORD") or getpass.getpass("Administrator password: ")
    request = urllib.request.Request(args.url.rstrip("/") + "/api/auth/login",
        data=json.dumps({"username": os.getenv("ASIVM_ADMIN_USER", "admin"), "password": password}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            token = json.load(response)["token"]
        population = populate(Client(args.url, token), args.imports)
        exercise(args.url, token, args.imports, population, args.output)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Workflow check failed: HTTP {error.code}: {error.read().decode()[:500]}") from None


if __name__ == "__main__":
    main()
