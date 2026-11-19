"""Inventory context must survive an analyst merge and remain reversible."""
from copy import deepcopy

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db import Base
from app.engines.identity import merge_assets, revert_merge
from app.models import Asset, IdentityDecision


PROFILE = ("owner", "os", "os_family", "type", "config", "tags", "criticality", "criticality_source")


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/identity.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def decision_for(db, keep, drop):
    db.add_all([keep, drop])
    db.flush()
    decision = IdentityDecision(asset_id=drop.id, candidate_asset_id=keep.id, outcome="probable",
                                status="pending", confidence=.85)
    db.add(decision)
    db.commit()
    return decision


def profile(asset):
    return {field: deepcopy(getattr(asset, field)) for field in PROFILE}


def test_merge_carries_missing_inventory_profile_and_revert_restores_it(db):
    keep = Asset(name="scanned-camera", type="unknown", config={"nested": {"scan": "live"}},
                 tags=["live"], criticality=3, criticality_source="default")
    drop = Asset(name="inventory-camera", owner="Facilities", os="Embedded Linux", os_family="linux",
                 type="iot_device", config={"vendor": "Hikvision", "nested": {"scan": "inventory", "model": "C1"}},
                 tags=["synthetic-inventory", "live"], criticality=5, criticality_source="source")
    decision = decision_for(db, keep, drop)
    before, incoming = profile(keep), profile(drop)
    merge_assets(db, keep.id, drop.id, decision, "analyst")
    db.commit()
    db.expire_all()
    assert keep.owner == "Facilities" and keep.os == "Embedded Linux" and keep.os_family == "linux"
    assert keep.type == "iot_device" and keep.criticality == 5 and keep.criticality_source == "source"
    assert keep.config == {"vendor": "Hikvision", "nested": {"scan": "live", "model": "C1"}}
    assert keep.tags == ["live", "synthetic-inventory"]
    assert drop.merged_into == keep.id and profile(drop) == incoming
    revert_merge(db, decision, "analyst")
    db.commit()
    db.expire_all()
    assert profile(keep) == before
    assert profile(drop) == incoming and drop.merged_into is None


def test_merge_preserves_existing_context_and_analyst_criticality(db):
    keep = Asset(name="existing-server", owner="Production", os="Linux 6", os_family="linux", type="server",
                 criticality=4, criticality_source="analyst", tags=["production"],
                 config={"vendor": "Existing", "enabled": False, "limit": 0, "nested": {"auth_required": True}})
    drop = Asset(name="inventory-server", owner="Inventory", os="Windows", os_family="windows", type="iot_device",
                 criticality=5, criticality_source="source", tags=["inventory", "production"],
                 config={"vendor": "Incoming", "enabled": True, "limit": 50,
                         "nested": {"auth_required": False, "model": "C1"}})
    decision = decision_for(db, keep, drop)
    before = profile(keep)
    merge_assets(db, keep.id, drop.id, decision, "analyst")
    db.commit()
    assert keep.owner == "Production" and keep.os == "Linux 6" and keep.type == "server"
    assert keep.criticality == 4 and keep.criticality_source == "analyst"
    assert keep.config == {"vendor": "Existing", "enabled": False, "limit": 0,
                           "nested": {"auth_required": True, "model": "C1"}}
    assert keep.tags == ["production", "inventory"]
    revert_merge(db, decision, "analyst")
    db.commit()
    assert profile(keep) == before


def test_revert_keeps_profile_edits_made_after_merge(db):
    keep = Asset(name="scanned-device", type="unknown", tags=["scan"])
    drop = Asset(name="inventory-device", owner="Inventory", os="Embedded Linux", os_family="linux",
                 type="iot_device", config={"vendor": "Incoming"}, tags=["inventory"],
                 criticality=5, criticality_source="source")
    decision = decision_for(db, keep, drop)
    merge_assets(db, keep.id, drop.id, decision, "analyst")
    db.commit()
    keep.owner = "Owner corrected after merge"
    keep.criticality, keep.criticality_source = 2, "analyst"
    keep.config = {**keep.config, "later_observation": "retained"}
    db.commit()
    revert_merge(db, decision, "analyst")
    db.commit()
    db.expire_all()
    assert keep.owner == "Owner corrected after merge"
    assert keep.criticality == 2 and keep.criticality_source == "analyst"
    assert keep.config["later_observation"] == "retained"
    assert keep.os is None and keep.os_family is None and keep.type == "unknown" and keep.tags == ["scan"]
    assert drop.merged_into is None and drop.owner == "Inventory"
