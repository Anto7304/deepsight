"""Relational model for the infrastructure intelligence model.

Raw observations, normalized identifiers, asset state, inferred relationships, ML
predictions (anomalies), risk assessments and analyst-validated outcomes are kept in
separate tables so that an uncertain prediction can never be mistaken for a fact.
Historical tables (observations, changes, risk assessments, eval vectors) are indexed by
(asset, time) and serve as the time-series store; relationships form the graph.
"""
from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text)

from .db import Base
from .util import now


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    pw_hash = Column(String(256), nullable=False)
    role = Column(String(24), nullable=False, default="readonly")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now)
    last_login = Column(DateTime)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=now, index=True)
    user = Column(String(64), index=True)
    action = Column(String(64), index=True)
    resource = Column(String(128))
    detail = Column(JSON)
    ip = Column(String(64))


class Source(Base):
    """An integration (connector configuration)."""
    __tablename__ = "sources"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False)
    category = Column(String(32), default="infrastructure")
    kind = Column(String(48), nullable=False)
    config = Column(JSON, default=dict)
    secrets_enc = Column(Text)
    enabled = Column(Boolean, default=True)
    verified = Column(Boolean, default=True)
    frequency_minutes = Column(Integer, default=0)
    status = Column(String(24), default="never_run")
    auth_status = Column(String(24), default="unknown")
    last_success = Column(DateTime)
    last_attempt = Column(DateTime)
    last_error = Column(Text)
    created_at = Column(DateTime, default=now)


class CollectionRun(Base):
    __tablename__ = "collection_runs"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("sources.id"), index=True)
    started = Column(DateTime, default=now)
    finished = Column(DateTime)
    status = Column(String(24), default="running")
    trigger = Column(String(24), default="manual")
    received = Column(Integer, default=0)
    processed = Column(Integer, default=0)
    duplicates = Column(Integer, default=0)
    rejected = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    error = Column(Text)
    summary = Column(JSON)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), index=True)
    type = Column(String(32), default="unknown", index=True)
    status = Column(String(24), default="discovered", index=True)  # lifecycle
    identity_status = Column(String(24), default="unresolved", index=True)
    identity_confidence = Column(Float, default=0.4)
    criticality = Column(Integer, default=3)
    criticality_source = Column(String(16), default="default")
    owner = Column(String(128))
    os = Column(String(128))
    os_family = Column(String(24))
    exposure = Column(String(16), default="internal")
    primary_identifier = Column(String(256))
    config = Column(JSON, default=dict)
    tags = Column(JSON, default=list)
    first_seen = Column(DateTime, default=now)
    last_seen = Column(DateTime, default=now)
    merged_into = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), default="low")
    risk_confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)


class AssetIdentifier(Base):
    __tablename__ = "asset_identifiers"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    kind = Column(String(16))
    value = Column(String(256))
    source_id = Column(Integer, nullable=True)
    first_seen = Column(DateTime, default=now)
    last_seen = Column(DateTime, default=now)
    active = Column(Boolean, default=True)
    __table_args__ = (Index("ix_ident_kind_value", "kind", "value"),)


class Observation(Base):
    __tablename__ = "observations"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, index=True)
    source_type = Column(String(48))
    category = Column(String(32), default="asset")
    identifiers = Column(JSON, default=dict)
    attributes = Column(JSON, default=dict)
    observed_at = Column(DateTime, default=now)
    collected_at = Column(DateTime, default=now)
    raw = Column(JSON)
    raw_ref = Column(String(512))
    status = Column(String(24), default="received", index=True)
    error = Column(Text)
    quality = Column(JSON, default=dict)
    quality_score = Column(Float, default=1.0)
    content_hash = Column(String(64), index=True)
    asset_id = Column(Integer, index=True, nullable=True)
    match_outcome = Column(String(24))
    match_confidence = Column(Float)
    __table_args__ = (Index("ix_obs_asset_time", "asset_id", "observed_at"),)


class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    port = Column(Integer)
    proto = Column(String(8), default="tcp")
    name = Column(String(64))
    product = Column(String(128))
    version = Column(String(64))
    bind = Column(String(64))
    exposed = Column(Boolean, default=False)
    source_id = Column(Integer)
    first_seen = Column(DateTime, default=now)
    last_seen = Column(DateTime, default=now)
    active = Column(Boolean, default=True)
    extra = Column(JSON, default=dict)


class Software(Base):
    __tablename__ = "software"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    product = Column(String(128))
    version = Column(String(64))
    source_id = Column(Integer)
    first_seen = Column(DateTime, default=now)
    last_seen = Column(DateTime, default=now)
    active = Column(Boolean, default=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    cve_id = Column(String(32), primary_key=True)
    description = Column(Text)
    cvss = Column(Float)
    severity = Column(String(16))
    published = Column(DateTime)
    affected = Column(JSON, default=list)
    kev = Column(Boolean, default=False)
    kev_added = Column(String(16))
    exploit_available = Column(Boolean, default=False)
    techniques = Column(JSON, default=list)
    references = Column(JSON, default=list)
    remediation = Column(Text)
    source = Column(String(32), default="manual")
    enriched = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=now, onupdate=now)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    cve_id = Column(String(32), ForeignKey("vulnerabilities.cve_id"), index=True)
    service_id = Column(Integer, nullable=True)
    software_id = Column(Integer, nullable=True)
    port = Column(Integer, nullable=True)
    basis = Column(String(16), default="inferred")  # observed (scanner) | inferred (version match)
    status = Column(String(24), default="open", index=True)
    first_seen = Column(DateTime, default=now)
    last_seen = Column(DateTime, default=now)
    resolved_at = Column(DateTime)
    evidence = Column(JSON, default=dict)


class Relationship(Base):
    __tablename__ = "relationships"
    id = Column(Integer, primary_key=True)
    src_id = Column(Integer, ForeignKey("assets.id"), index=True)
    dst_id = Column(Integer, ForeignKey("assets.id"), index=True)
    type = Column(String(24))
    basis = Column(String(16), default="observed")
    source_id = Column(Integer)
    confidence = Column(Float, default=1.0)
    valid_from = Column(DateTime, default=now)
    valid_to = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, default=now)
    evidence = Column(JSON, default=dict)


class Change(Base):
    __tablename__ = "changes"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    ts = Column(DateTime, default=now, index=True)
    kind = Column(String(32), index=True)
    summary = Column(String(512))
    detail = Column(JSON, default=dict)
    observation_id = Column(Integer, nullable=True)
    __table_args__ = (Index("ix_change_asset_ts", "asset_id", "ts"),)


class EvalVector(Base):
    """Every change-vector evaluated by the anomaly model (training data for retraining)."""
    __tablename__ = "eval_vectors"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, index=True)
    observation_id = Column(Integer)
    ts = Column(DateTime, default=now)
    features = Column(JSON)
    score = Column(Float)


class Anomaly(Base):
    __tablename__ = "anomalies"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    ts = Column(DateTime, default=now, index=True)
    observation_id = Column(Integer, nullable=True)
    score = Column(Float)
    threshold = Column(Float)
    summary = Column(String(512))
    features = Column(JSON)
    contributors = Column(JSON)
    model_version = Column(String(64))
    status = Column(String(24), default="new", index=True)  # new | true_positive | false_positive | reviewed
    reviewer = Column(String(64))
    review_note = Column(Text)
    reviewed_at = Column(DateTime)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    finding_id = Column(Integer, nullable=True, index=True)
    ts = Column(DateTime, default=now, index=True)
    score = Column(Float)
    level = Column(String(16))
    cvss = Column(Float)
    factors = Column(JSON)
    confidence = Column(Float)
    version = Column(String(48))
    evidence = Column(JSON)
    summary = Column(String(512))
    __table_args__ = (Index("ix_risk_asset_ts", "asset_id", "ts"),)


class IdentityDecision(Base):
    __tablename__ = "identity_decisions"
    id = Column(Integer, primary_key=True)
    observation_id = Column(Integer, index=True)
    asset_id = Column(Integer, index=True)           # asset the observation was attached to
    candidate_asset_id = Column(Integer, nullable=True, index=True)
    outcome = Column(String(24))                     # confirmed|probable|unresolved|potentially_separate|new
    status = Column(String(24), default="auto", index=True)  # auto|pending|confirmed|rejected|reverted
    confidence = Column(Float)
    evidence = Column(JSON)
    model_version = Column(String(64))
    ts = Column(DateTime, default=now)
    decided_by = Column(String(64))
    decided_at = Column(DateTime)
    merge_snapshot = Column(JSON)


class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True)
    title = Column(String(256))
    status = Column(String(24), default="open", index=True)
    created_by = Column(String(64))
    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)
    asset_ids = Column(JSON, default=list)
    finding_ids = Column(JSON, default=list)
    anomaly_ids = Column(JSON, default=list)
    notes = Column(JSON, default=list)
    conclusion = Column(Text)
    outcome = Column(String(24))  # true_positive | false_positive | benign | unknown
    validated_by = Column(String(64))
    validated_at = Column(DateTime)
    validation_history = Column(JSON, default=list)


class ModelRun(Base):
    __tablename__ = "model_runs"
    id = Column(Integer, primary_key=True)
    name = Column(String(48), index=True)
    version = Column(String(64))
    trained_at = Column(DateTime, default=now)
    metrics = Column(JSON)
    status = Column(String(16), default="active")
    data_origin = Column(String(32))
    notes = Column(Text)
    inference_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(64), primary_key=True)
    value = Column(JSON)
    updated_at = Column(DateTime, default=now, onupdate=now)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id = Column(Integer, primary_key=True)
    event_key = Column(String(160), unique=True, nullable=False)
    source_id = Column(Integer, index=True)
    payload = Column(JSON)
    status = Column(String(24), default="pending", index=True)
    attempts = Column(Integer, default=0)
    next_attempt = Column(DateTime, default=now)
    delivered_at = Column(DateTime)
    error = Column(Text)


class BackgroundJob(Base):
    __tablename__ = "background_jobs"
    id = Column(Integer, primary_key=True)
    kind = Column(String(32), nullable=False)
    source_id = Column(Integer, index=True)
    active_key = Column(String(128), unique=True)
    requested_by = Column(String(64), default="system")
    status = Column(String(24), default="queued", index=True)
    attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=now)
    available_at = Column(DateTime, default=now)
    heartbeat = Column(DateTime)
    finished_at = Column(DateTime)
    error = Column(Text)
    result = Column(JSON)


class IdentityBlock(Base):
    __tablename__ = "identity_blocks"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, index=True)
    kind = Column(String(24))
    value = Column(String(256))
    __table_args__ = (Index("ix_identity_block_lookup", "kind", "value"),)


class SchemaVersion(Base):
    __tablename__ = "schema_versions"
    version = Column(Integer, primary_key=True)
    applied_at = Column(DateTime, default=now)
    description = Column(String(256))
