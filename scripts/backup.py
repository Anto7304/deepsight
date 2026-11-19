#!/usr/bin/env python3
"""Portable consistent database backup with an automated restore comparison.

Run with ASIVM_DATABASE_URL in the environment. Credentials are never CLI arguments.
Restore requires a new, empty target database via ASIVM_RESTORE_DATABASE_URL.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sqlalchemy import create_engine, select, text, DateTime
from app.config import settings
from app.db import Base, engine
from app import models  # register metadata
from app.migrations import upgrade


def encode(value):
    if isinstance(value,datetime.datetime):return {'__datetime__':value.isoformat()}
    if isinstance(value,bytes):return {'__bytes__':base64.b64encode(value).decode()}
    return value


def decode(value):
    if isinstance(value,dict) and set(value)=={'__datetime__'}:return datetime.datetime.fromisoformat(value['__datetime__'])
    if isinstance(value,dict) and set(value)=={'__bytes__'}:return base64.b64decode(value['__bytes__'])
    return value


def snapshot(db_engine):
    # A repeatable-read transaction keeps PostgreSQL tables at one database snapshot.
    isolation='SERIALIZABLE' if db_engine.dialect.name=='sqlite' else 'REPEATABLE READ'
    out={}
    with db_engine.connect().execution_options(isolation_level=isolation) as conn:
        with conn.begin():
            for table in Base.metadata.sorted_tables:
                rows=[dict(r._mapping) for r in conn.execute(select(table).order_by(*table.primary_key.columns))]
                out[table.name]=rows
    return out


def dump(db_engine,path):
    files={}
    data_root=Path(settings.data_dir)
    for directory in ('evidence','archive'):
        folder=data_root/directory
        if folder.exists():
            for file in folder.rglob('*'):
                if file.is_file() and not file.is_symlink():files[str(file.relative_to(data_root))]=base64.b64encode(file.read_bytes()).decode()
    key=data_root/'secret.key'
    if key.exists():files['secret.key']=base64.b64encode(key.read_bytes()).decode()
    payload={'database':snapshot(db_engine),'files':files,'format':'deepsight-backup-1.1.0'}
    blob=json.dumps(payload,default=encode,sort_keys=True,separators=(',',':')).encode()
    target=Path(path)
    with target.open('xb') as f:os.chmod(target,0o600);f.write(blob)
    digest=hashlib.sha256(blob).hexdigest()
    target.with_suffix(target.suffix+'.sha256').write_text(digest+'\n')
    return {'sha256':digest,'tables':len(Base.metadata.tables)}


def restore(path,target_engine,data_dir=None):
    blob=Path(path).read_bytes()
    expected=Path(path).with_suffix(Path(path).suffix+'.sha256').read_text().strip()
    if hashlib.sha256(blob).hexdigest()!=expected:raise ValueError('Backup checksum mismatch')
    payload=json.loads(blob)
    data=payload['database']
    for table in Base.metadata.sorted_tables:
        for row in data.get(table.name,[]):
            for column in table.columns:
                if isinstance(column.type,DateTime) and row.get(column.name) is not None:
                    row[column.name]=decode(row[column.name])
    if payload.get('files') and data_dir is not None:
        output=Path(data_dir)
        if output.exists() and any(output.iterdir()):raise ValueError('Evidence restore directory must be empty')
        for name in payload['files']:
            target=(output/name).resolve()
            if not target.is_relative_to(output.resolve()):raise ValueError('Invalid backup file path')
    Base.metadata.create_all(target_engine)
    with target_engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if conn.execute(select(table).limit(1)).first():raise ValueError('Restore target must be empty')
        for table in Base.metadata.sorted_tables:
            if data.get(table.name):
                rows=data[table.name]
                if table.name=='assets':
                    conn.execute(table.insert(),[{**r,'merged_into':None} for r in rows])
                    for row in rows:
                        if row.get('merged_into'):conn.execute(table.update().where(table.c.id==row['id']).values(merged_into=row['merged_into']))
                else:conn.execute(table.insert(),rows)
        if target_engine.dialect.name=='postgresql':
            # Reset serial sequences after explicit primary-key inserts.
            for table in Base.metadata.sorted_tables:
                for column in table.primary_key.columns:
                    if str(column.type)=='INTEGER' and column.autoincrement is not False:
                        seq=conn.execute(text('SELECT pg_get_serial_sequence(:table,:column)'),{'table':table.name,'column':column.name}).scalar()
                        if seq:
                            conn.execute(text(f'SELECT setval(:seq, COALESCE((SELECT MAX("{column.name}") FROM "{table.name}"),1), EXISTS(SELECT 1 FROM "{table.name}"))'),{'seq':seq})
    if snapshot(target_engine)!=data:raise ValueError('Restored database differs from backup')
    for name,value in payload.get('files',{}).items():
        content=base64.b64decode(value,validate=True)
        if data_dir is not None:
            target=Path(data_dir)/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(content);os.chmod(target,0o600)
            if target.read_bytes()!=content:raise ValueError('Restored evidence differs')
    return {'verified':True,'tables':len(data),'rows':sum(map(len,data.values())),'evidence_files':len(payload.get('files',{}))}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode',choices=['backup','restore','check']);ap.add_argument('path');args=ap.parse_args()
    if args.mode=='backup':result=dump(engine,args.path)
    elif args.mode=='restore':
        url=os.environ.get('ASIVM_RESTORE_DATABASE_URL')
        if not url:raise SystemExit('Set ASIVM_RESTORE_DATABASE_URL to a new empty database')
        result=restore(args.path,create_engine(url),os.environ.get('ASIVM_RESTORE_DATA_DIR'))
    else:
        import tempfile
        with tempfile.TemporaryDirectory(prefix='deepsight-restore-') as directory:
            result=restore(args.path,create_engine('sqlite:///'+directory+'/restored.db'),directory+'/evidence')
    print(json.dumps(result))

if __name__=='__main__':main()
