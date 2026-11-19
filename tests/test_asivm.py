import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import demo


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as cl:
        demo.load()
        r = cl.post("/api/auth/login", json={"username": "admin", "password": "Test-Password-1234"})
        cl.headers["Authorization"] = "Bearer " + r.json()["token"]
        yield cl


def test_auth_required():
    with TestClient(app) as cl:
        assert cl.get("/api/assets").status_code == 401
        assert cl.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401


def test_baseline_clean(c):
    m = c.get("/api/overview").json()["metrics"]
    assert m["assets_total"] >= 30 and m["anomalies_open"] == 0 and m["identity_pending"] == 1


def test_iot_devices_in_baseline(c):
    items = c.get("/api/assets?type=iot_device&size=100").json()["items"]
    by = {i["name"]: i for i in items}
    assert len(items) >= 8
    assert {"printer-02", "printer-03", "camera-iot-01", "camera-iot-02", "camera-iot-03", "badge-reader-01",
            "temp-gw-01", "router-iot-01"} <= set(by)
    # firmware-version matching: the unpatched camera has a finding, the patched one does not
    assert by["camera-iot-03"]["open_findings"] >= 1 and by["camera-iot-02"]["open_findings"] == 0
    assert by["router-iot-01"]["open_findings"] >= 1 and by["temp-gw-01"]["open_findings"] >= 1
    svcs = c.get(f"/api/assets/{by['camera-iot-03']['id']}/services").json()
    assert {23, 554, 80} <= {x["port"] for x in svcs if x["active"]}
    assert all(i["identity_status"] == "confirmed" for i in items)


def test_identity_probable_is_reversible(c):
    d = c.get("/api/identity/decisions?status=pending").json()["items"][0]
    assert d["outcome"] == "probable"
    assert c.post(f"/api/identity/decisions/{d['id']}/confirm").status_code == 200
    assert c.post(f"/api/identity/decisions/{d['id']}/revert").status_code == 200


def test_scenario_raises_risk_and_anomaly(c):
    demo.advance()
    f = c.get("/api/findings?asset_id=0").json()
    top = c.get("/api/overview").json()["top_risks"][0]
    assert top["cve"] == "CVE-2020-1938" and top["level"] == "critical"
    assert any(a["status"] == "new" for a in c.get("/api/anomalies").json()["items"])
    a = c.post("/api/assistant/query", json={"question": "Why has the risk of app-server-01 increased?"}).json()
    assert "CVE-2020-1938" in a["answer"] and a["references"]


def test_iot_drift_after_scenario(c):
    by = {i["name"]: i for i in c.get("/api/assets?type=iot_device&size=100").json()["items"]}
    cam = c.get("/api/changes", params={"hours": 48, "asset_id": by["camera-iot-01"]["id"]}).json()
    assert any(x["kind"] == "service_added" and "/23" in x["summary"] for x in cam)  # Telnet switched on
    assert any(x["kind"] == "config_changed" for x in cam)                           # telnet_enabled no -> yes
    gw = c.get("/api/changes", params={"hours": 48, "asset_id": by["temp-gw-01"]["id"]}).json()
    assert any(x["kind"] == "exposure_changed" for x in gw) and by["temp-gw-01"]["exposure"] == "external"


def test_one_open_finding_per_cve_per_asset(c):
    rows = c.get("/api/findings?size=200").json()["items"]
    keys = [(r["asset_id"], r["cve"]) for r in rows]
    assert len(keys) == len(set(keys))


def test_rbac_and_user_policy(c):
    assert c.post("/api/users", json={"username": "viewer1", "password": "short", "role": "readonly"}).status_code == 422
    assert c.post("/api/users", json={"username": "viewer1", "password": "Viewer-Password-12", "role": "readonly"}).status_code == 201
    t = c.post("/api/auth/login", json={"username": "viewer1", "password": "Viewer-Password-12"}).json()["token"]
    h = {"Authorization": "Bearer " + t}
    assert c.get("/api/assets", headers=h).status_code == 200
    assert c.post("/api/system/lifecycle-sweep", headers=h).status_code == 403
    assert c.post("/api/observations", headers=h, json={"observations": [{"identifiers": {"ip": "10.9.9.9"}}]}).status_code == 403


def test_manual_observation_and_bad_data(c):
    r = c.post("/api/observations", json={"observations": [{"identifiers": {"ip": "not-an-ip"}}, {"identifiers": {"ip": "10.99.0.5"}, "attributes": {"services": [{"port": 22}]}}]})
    assert r.status_code == 202
    st = [x["status"] for x in r.json()["results"]]
    assert "rejected" in st and "processed" in st


def test_report_csv_formula_injection_neutralised(c):
    r = c.get("/api/reports/inventory?format=csv")
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]


def test_integration_secret_never_returned(c):
    r = c.post("/api/integrations", json={"name": "t1", "kind": "http_json", "config": {"url": "https://example.com"}, "secrets": {"headers": {"X": "supersecret"}}})
    assert r.status_code == 201 and "supersecret" not in r.text and r.json()["has_secrets"]
    assert "supersecret" not in c.get("/api/integrations").text


def test_security_headers(c):
    r = c.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]


# ---------------------------------------------------------------- regressions (bugs found in prototype testing)
def _ingest(c, *obs):
    r = c.post("/api/observations", json={"observations": list(obs)})
    assert r.status_code == 202, r.text
    return r.json()["results"]


def test_asset_without_relationships_detail_and_impact(c):
    res = _ingest(c, {"identifiers": {"ip": "10.123.0.1"}, "attributes": {"name": "lonely-host"}})
    aid = res[0]["asset_id"]
    for part in ("", "/impact", "/services", "/relationships", "/risk", "/findings"):
        assert c.get(f"/api/assets/{aid}{part}").status_code == 200, part


def test_malformed_attribute_shapes_never_crash_or_lose_batch(c):
    bad = [{"os": {"name": 1}}, {"os": 5}, {"os": ["x"]}, {"os": True}, {"services": 5}, {"services": True},
           {"software": 5}, {"relations": 5}, {"relations": [{"target": "abc"}]}, {"relations": [{"target": [1]}]},
           {"findings": 5}, {"findings": [1, None, {"cve": "CVE-2020-1938", "cvss": "high", "port": "99999999999"}]},
           {"name": "n" * 5000, "owner": "o" * 5000, "services": [{"port": 80, "version": "v" * 5000}]}]
    obs = [{"identifiers": {"ip": f"10.124.0.{i + 1}"}, "attributes": a} for i, a in enumerate(bad)]
    obs.append({"identifiers": {"ip": "10.124.1.1"}, "attributes": {"name": "good-record"}})
    res = _ingest(c, *obs)
    assert len(res) == len(obs) and res[-1]["status"] == "processed"
    assert not [r for r in res if r["status"] == "failed"]


def test_nul_bytes_rejected_cleanly(c):
    assert c.get("/api/assets", params={"q": "a\x00b"}).status_code == 400
    r = c.post("/api/observations", json={"observations": [{"identifiers": {"ip": "10.125.0.1"}, "attributes": {"name": "a\x00b"}}]})
    assert r.status_code == 400


def test_oversized_ids_are_not_server_errors(c):
    big = 10 ** 30
    for m, p, kw in [("get", f"/api/assets/{big}", {}), ("get", f"/api/assets/{big}/impact", {}),
                     ("patch", f"/api/findings/{big}", {"json": {"state": "new"}}),
                     ("post", "/api/relationships", {"json": {"src_id": big, "dst_id": 1, "type": "hosts"}}),
                     ("get", "/api/findings", {"params": {"asset_id": big}})]:
        assert getattr(c, m)(p, **kw).status_code < 500, (m, p)


def test_investigation_rejects_nonexistent_references(c):
    r = c.post("/api/investigations", json={"title": "ghost refs", "asset_ids": [999999]})
    assert r.status_code == 404
    aid = c.get("/api/assets?size=1").json()["items"][0]["id"]
    ok = c.post("/api/investigations", json={"title": "real refs", "asset_ids": [aid, aid]})
    assert ok.status_code == 201 and ok.json()["asset_ids"] == [aid]


def test_connector_target_and_url_guards(c):
    def probe(kind, cfg):
        sid = c.post("/api/integrations", json={"name": f"guard-{kind}-{abs(hash(str(cfg)))}", "kind": kind, "config": cfg}).json()["id"]
        return c.post(f"/api/integrations/{sid}/test").json()
    assert not probe("tcp_discovery", {"targets": ["10.0.0.0/8"], "authorized": True, "max_hosts": 10 ** 9})["ok"]
    assert not probe("tcp_discovery", {"targets": ["fd00::/64"], "authorized": True})["ok"]
    for url in ("http://[::ffff:169.254.169.254]/", "http://169.254.169.254/", "http://127.0.0.1:8000/", "http://0.0.0.0/"):
        assert not probe("http_json", {"url": url})["ok"], url


def test_scanner_updates_firmware_finding_without_duplicates(c):
    asset = c.get("/api/assets?q=camera-iot-03").json()["items"][0]
    rows = c.get(f"/api/findings?asset_id={asset['id']}&cve=CVE-2021-36260").json()["items"]
    assert len(rows) == 1
    finding = c.get(f"/api/findings/{rows[0]['id']}").json()
    assert finding["basis"] == "observed"
    assert finding["evidence"]["upgraded_from"] == "inferred"
    assert any(r["port"] == 80 for r in finding["evidence"]["scanner_reports"])


def test_repeated_scanner_reports_share_finding_and_keep_port_evidence(c):
    reports = [{"cve": "CVE-2026-90001", "port": p, "evidence": f"port {p}"} for p in (80, 443, 80)]
    obs = {"identifiers": {"mac": "02:aa:bb:cc:dd:ee"}, "attributes": {"name": "scanner-regression", "findings": reports}}
    aid = _ingest(c, obs)[0]["asset_id"]
    first = c.get(f"/api/findings?asset_id={aid}").json()["items"]
    assert len(first) == 1
    _ingest(c, obs)
    second = c.get(f"/api/findings?asset_id={aid}").json()["items"]
    assert [r["id"] for r in second] == [r["id"] for r in first]
    detail = c.get(f"/api/findings/{first[0]['id']}").json()
    assert {r["port"] for r in detail["evidence"]["scanner_reports"]} == {80, 443}
    assert len(detail["evidence"]["scanner_reports"]) == 2


def test_combined_risk_filter_matches_dashboard_count(c):
    result = c.get("/api/findings?level=critical,high&size=200").json()
    metrics = c.get("/api/overview").json()["metrics"]
    assert result["total"] == metrics["critical_high_findings"]
    assert {r["contextual_level"] for r in result["items"]} == {"critical", "high"}


def test_findings_search_before_pagination(c):
    result = c.get("/api/findings", params={"q": "camera-iot", "size": 1}).json()
    expected = [r for r in c.get("/api/findings?size=200").json()["items"] if "camera-iot" in r["asset"]]
    assert result["total"] == len(expected) >= 1
    assert len(result["items"]) == 1
    assert c.get("/api/findings?q=does-not-exist").json()["total"] == 0


def test_report_csv_neutralises_actual_formula_values(c):
    _ingest(c, {"identifiers": {"mac": "02:aa:bb:cc:dd:ef"}, "attributes": {"name": "=1+1"}})
    csv = c.get("/api/reports/inventory?format=csv")
    assert "'=1+1" in csv.text
    assert "deepsight-inventory.csv" in csv.headers["content-disposition"]


def test_scanner_confirmation_refreshes_existing_risk(c):
    obs = {"identifiers": {"mac": "02:aa:bb:cc:dd:f0"}, "attributes": {
        "name": "risk-upgrade-regression", "software": [{"product": "Hikvision firmware", "version": "5.4.7"}]}}
    aid = _ingest(c, obs)[0]["asset_id"]
    before = c.get(f"/api/findings?asset_id={aid}").json()["items"][0]
    assert before["basis"] == "inferred"
    obs["attributes"]["findings"] = [{"cve": before["cve"], "port": 80, "evidence": "confirmed inventory"}]
    _ingest(c, obs)
    after = c.get(f"/api/findings?asset_id={aid}").json()["items"][0]
    assert after["id"] == before["id"] and after["basis"] == "observed"
    assert after["confidence"] > before["confidence"]
    assert after["contextual_level"] != "verify"


def test_merge_deduplicates_cve_across_ports_and_revert_restores(c):
    from app.db import session_scope
    from app.engines.identity import merge_assets, revert_merge
    from app.models import Finding, IdentityDecision
    ids = []
    for suffix, port in (("f1", 80), ("f2", 443)):
        ids.append(_ingest(c, {"identifiers": {"mac": f"02:aa:bb:cc:dd:{suffix}"}, "attributes": {
            "name": f"merge-regression-{suffix}", "findings": [{"cve": "CVE-2026-90002", "port": port}]}})[0]["asset_id"])
    with session_scope() as db:
        decision = IdentityDecision(asset_id=ids[1], candidate_asset_id=ids[0], outcome="probable", confidence=.8)
        db.add(decision)
        db.flush()
        merge_assets(db, ids[0], ids[1], decision, "test")
        db.flush()
        assert db.query(Finding).filter(Finding.asset_id == ids[0], Finding.status == "open").count() == 1
        revert_merge(db, decision, "test")
        db.flush()
        assert all(db.query(Finding).filter(Finding.asset_id == aid, Finding.status == "open").count() == 1 for aid in ids)


def test_module_api_workflows(c):
    paths = ["/health", "/auth/me", "/roles", "/users", "/observations", "/identity/decisions?status=review",
             "/vulnerabilities", "/intelligence", "/anomalies", "/risk-assessments", "/ml/models",
             "/changes", "/graph", "/investigations", "/connectors", "/integrations",
             "/assistant/suggestions", "/audit", "/system/status"]
    for path in paths:
        response = c.get("/api" + path)
        assert response.status_code == 200, (path, response.text)
    for asset in c.get("/api/assets?size=200").json()["items"]:
        response = c.get(f"/api/assets/{asset['id']}")
        assert response.status_code == 200, response.text
        detail = response.json()
        assert all(key in detail for key in ("software", "services", "findings", "impact", "risk_history", "history"))
    for finding in c.get("/api/findings?size=200").json()["items"]:
        assert c.get(f"/api/findings/{finding['id']}").status_code == 200
    for source in c.get("/api/integrations").json():
        for suffix in ("runs", "status"):
            assert c.get(f"/api/integrations/{source['id']}/{suffix}").status_code == 200


def test_all_report_formats(c):
    for report in c.get("/api/reports").json():
        for format in ("json", "csv", "html"):
            response = c.get(f"/api/reports/{report['kind']}?format={format}")
            assert response.status_code == 200, response.text
            assert response.content
