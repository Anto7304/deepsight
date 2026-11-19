"""Normal startup and ingestion remain useful without a separate presentation interface."""
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models import Asset, BackgroundJob, CollectionRun, Observation, Source, User
from app.security import make_token


@pytest.fixture
def platform(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/platform.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        admin = User(username="platform-admin", role="administrator", pw_hash="unused")
        reader = User(username="platform-reader", role="readonly", pw_hash="unused")
        db.add_all([admin, reader])
        db.commit()
        tokens = {"administrator": make_token(admin), "readonly": make_token(reader)}

    def isolated_db():
        with sessions() as db:
            yield db

    previous = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = isolated_db
    # Explicitly initialized tables; avoid starting real workers or collectors in these checks.
    client = TestClient(app)
    client.headers["Authorization"] = "Bearer " + tokens["administrator"]
    try:
        yield client, sessions, tokens
    finally:
        client.close()
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)
        engine.dispose()


def test_reading_empty_platform_does_not_create_inventory(platform):
    client, sessions, tokens = platform
    client.headers["Authorization"] = "Bearer " + tokens["readonly"]
    for _ in range(2):
        assert client.get("/api/overview").json()["metrics"]["assets_total"] == 0
        assert client.get("/api/assets").json()["items"] == []
        assert client.get("/api/integrations").json() == []
    with sessions() as db:
        assert db.query(Asset).count() == db.query(Observation).count() == db.query(Source).count() == 0


def test_health_and_system_metadata_describe_the_operating_system(platform):
    client, _, _ = platform
    for path in ("/api/health", "/api/system/status"):
        response = client.get(path)
        assert response.status_code == 200
        assert "demo" not in response.json()


def test_internal_presentation_routes_are_not_exposed(platform):
    client, _, _ = platform
    paths = client.get("/api/openapi.json").json()["paths"]
    assert not any(path.startswith("/api/demo") for path in paths)
    for path in ("/api/demo/status", "/api/demo/guide", "/api/user-manual"):
        assert client.get(path).status_code == 404
    for path in ("/api/demo/load", "/api/demo/advance", "/api/demo/reset"):
        assert client.post(path, json={}).status_code == 404


def test_normal_import_enriches_inventory_and_records_a_run(platform):
    client, sessions, tokens = platform
    created = client.post("/api/integrations", json={"name": "Facilities inventory", "kind": "csv_hosts"})
    assert created.status_code == 201
    source_id = created.json()["id"]
    body = {"filename": "facilities-inventory.csv", "content": (
        "hostname,mac,ip,owner,type,os,criticality,ports\n"
        "camera-campus-01,02:11:22:33:44:55,10.24.8.10,Facilities,iot_device,Embedded Linux,3,23\n"
    )}
    client.headers["Authorization"] = "Bearer " + tokens["readonly"]
    assert client.post(f"/api/integrations/{source_id}/import", json=body).status_code == 403
    client.headers["Authorization"] = "Bearer " + tokens["administrator"]
    imported = client.post(f"/api/integrations/{source_id}/import", json=body)
    assert imported.status_code == 200, imported.text
    assert imported.json()["status"] == "ok" and imported.json()["processed"] == 1
    assets = client.get("/api/assets").json()["items"]
    assert len(assets) == 1
    detail = client.get(f"/api/assets/{assets[0]['id']}").json()
    assert detail["name"] == "camera-campus-01" and detail["owner"] == "Facilities"
    assert detail["observations"] and detail["services"] and detail["findings"]
    assert any(f["cve"].startswith("DS-IOT-") for f in detail["findings"])
    assert client.get(f"/api/integrations/{source_id}/runs").json()[0]["status"] == "ok"
    with sessions() as db:
        assert db.query(Asset).count() == db.query(Observation).count() == db.query(CollectionRun).count() == 1


def test_normal_discovery_configuration_and_collection_keep_role_boundaries(platform):
    client, sessions, tokens = platform
    body = {"name": "Network discovery", "kind": "tcp_discovery", "config": {
        "targets": ["127.0.0.2"], "ports": [23], "authorized": True,
    }}
    client.headers["Authorization"] = "Bearer " + tokens["readonly"]
    assert client.post("/api/integrations", json=body).status_code == 403
    client.headers["Authorization"] = "Bearer " + tokens["administrator"]
    created = client.post("/api/integrations", json=body)
    assert created.status_code == 201
    source_id = created.json()["id"]
    assert client.post(f"/api/integrations/{source_id}/test").json()["ok"]
    client.headers["Authorization"] = "Bearer " + tokens["readonly"]
    assert client.post(f"/api/integrations/{source_id}/collect").status_code == 403
    client.headers["Authorization"] = "Bearer " + tokens["administrator"]
    queued = client.post(f"/api/integrations/{source_id}/collect")
    assert queued.status_code == 202 and queued.json()["status"] == "queued"
    with sessions() as db:
        assert db.query(Asset).count() == 0
        assert db.query(BackgroundJob).one().source_id == source_id
        assert db.get(Source, source_id).status == "queued"
