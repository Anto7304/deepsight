"""Additive versioned migration for databases created by the prototype."""
from sqlalchemy.orm import Session
from .db import Base
from .models import AssetIdentifier, IdentityBlock, SchemaVersion


def upgrade(engine):
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        if not db.get(SchemaVersion,1):
            db.add(SchemaVersion(version=1,description='Legacy DEEPSIGHT schema registered without rewriting data'))
            db.commit()
        if not db.get(SchemaVersion,2):
            existing={(b.asset_id,b.value) for b in db.query(IdentityBlock)}
            for aid,value in db.query(AssetIdentifier.asset_id,AssetIdentifier.value).filter(AssetIdentifier.kind=='hostname'):
                key=(aid,value.split('.')[0])
                if key not in existing:
                    db.add(IdentityBlock(asset_id=aid,kind='hostname_short',value=key[1]));existing.add(key)
            db.add(SchemaVersion(version=2,description='DEEPSIGHT 1.1.0: durable jobs, outbox and indexed hostname blocks'))
            db.commit()
