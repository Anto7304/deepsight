"""DEEPSIGHT application entrypoint: FastAPI app, bootstrap, scheduler, security headers, static UI."""
import logging
import os
import secrets
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import exc as sa_exc
from sqlalchemy import text

from . import collector
from . import models  # noqa: F401  (register tables)
from .api import router
from .config import settings
from .connectors import REGISTRY
from .db import Base, SessionLocal, engine, session_scope
from .engines import intel, ml, state
from .models import Asset, Setting, Source, User
from .security import hash_password, limiter
from .util import iso, now

from .observability import JsonFormatter
logging.basicConfig(level=os.getenv("ASIVM_LOG_LEVEL", "INFO"))
for handler in logging.getLogger().handlers:
    handler.setFormatter(JsonFormatter())
log = logging.getLogger("asivm")
STATIC = os.path.join(os.path.dirname(__file__), "static")
_stop = threading.Event()


def init_db(retries=60):
    for i in range(retries):
        try:
            with engine.connect() as c:
                c.execute(text("SELECT 1"))
            break
        except Exception as e:  # noqa: BLE001
            log.warning("database not ready (%s); retry %d/%d", type(e).__name__, i + 1, retries)
            time.sleep(2)
    else:
        raise RuntimeError("database unavailable")
    from .migrations import upgrade
    upgrade(engine)


def ensure_admin():
    with session_scope() as db:
        if db.query(User).count():
            return
        generated = not settings.admin_password
        pw = settings.admin_password or secrets.token_urlsafe(14)
        db.add(User(username=settings.admin_user, pw_hash=hash_password(pw), role="administrator"))
    if generated:
        banner = "=" * 64
        print(f"\n{banner}\n DEEPSIGHT first start - administrator account created\n"
              f"   username: {settings.admin_user}\n   password: {pw}\n"
              f" (shown once; set ASIVM_ADMIN_PASSWORD to choose your own)\n{banner}\n", flush=True)
    else:
        log.info("administrator account '%s' created from ASIVM_ADMIN_PASSWORD", settings.admin_user)


def scheduler_loop():
    from .jobs import enqueue
    last_sweep = last_kev = 0.0
    while not _stop.is_set():
        try:
            with session_scope() as db:
                row = db.get(Setting, "scheduler_heartbeat")
                if row: row.value = iso(now())
                else: db.add(Setting(key="scheduler_heartbeat", value=iso(now())))
                db.commit()
                for src in db.query(Source).filter(Source.enabled.is_(True), Source.frequency_minutes > 0):
                    conn = REGISTRY.get(src.kind)
                    if conn and conn.schedulable and (src.last_attempt is None or now()-src.last_attempt >= timedelta(minutes=src.frequency_minutes)):
                        enqueue(db, "collection", src.id)
                enqueue(db, "webhooks")
                if time.time()-last_sweep > 3600:
                    enqueue(db, "maintenance");last_sweep=time.time()
                if settings.kev_auto_sync and time.time()-last_kev > 86400:
                    enqueue(db, "kev");last_kev=time.time()
        except Exception:
            log.exception("scheduler tick failed")
        _stop.wait(20)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _stop.clear()
    init_db()
    ensure_admin()
    with session_scope() as db:
        intel.seed_vulnerabilities(db)
        # a restart while a collection was running leaves it stuck in 'running'
        for s in db.query(Source).filter(Source.status == "running"):
            s.status, s.last_error = "error", "interrupted by restart"
    ml.register_models()
    if settings.ephemeral_secret:
        log.warning("ASIVM_SECRET_KEY is not set: sessions and stored integration secrets will not survive a restart")
    if settings.worker_enabled:
        from .jobs import Worker
        threading.Thread(target=Worker(_stop).run, daemon=True, name="collection-worker").start()
    if settings.scheduler_enabled:
        threading.Thread(target=scheduler_loop, daemon=True, name="scheduler").start()
    log.info("DEEPSIGHT ready")
    yield
    _stop.set()


app = FastAPI(title="DEEPSIGHT", description="MACHINE LEARNING-DRIVEN ATTACK SURFACE INTELLIGENCE AND VULNERABILITY MANAGEMENT PLATFORM. See beyond the surface.", version="1.1.0",
              lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
app.include_router(router)

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")


class RejectNul:
    """PostgreSQL cannot store NUL characters; reject them up front (URL or JSON body) with a clean 400
    instead of letting them surface as 500s deep inside a query."""

    def __init__(self, app):
        self.inner = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)
        bad = any(b"\x00" in x or b"%00" in x for x in (scope.get("raw_path") or b"", scope.get("query_string") or b""))
        replay = None
        if not bad and scope["method"] in ("POST", "PUT", "PATCH"):
            chunks, more = [], True
            while more:
                msg = await receive()
                if msg["type"] != "http.request":
                    chunks.append(msg)
                    break
                chunks.append(msg)
                more = msg.get("more_body", False)
            bad = any(m.get("type") == "http.request" and (b"\x00" in m.get("body", b"") or b"\\u0000" in m.get("body", b""))
                      for m in chunks)
            it = iter(chunks)

            async def replay():
                try:
                    return next(it)
                except StopIteration:
                    return await receive()
        if bad:
            return await JSONResponse({"detail": "NUL characters are not allowed in requests"}, status_code=400)(scope, receive, send)
        return await self.inner(scope, replay or receive, send)


app.add_middleware(RejectNul)


@app.exception_handler(OverflowError)
async def _overflow(request: Request, exc: OverflowError):
    return JSONResponse({"detail": "numeric value out of range"}, status_code=422)


@app.exception_handler(sa_exc.DBAPIError)
@app.exception_handler(sa_exc.StatementError)
async def _db_value_error(request: Request, exc):
    orig = getattr(exc, "orig", None)
    if isinstance(exc, sa_exc.DataError) or isinstance(orig, OverflowError):
        return JSONResponse({"detail": "value out of range or not storable"}, status_code=422)
    log.error("database error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse({"detail": "Internal Server Error"}, status_code=500)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "?"
    if request.url.path.startswith("/api") and not limiter.allow(f"ip:{ip}", settings.rate_limit_per_min):
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith("/api/docs"):
        resp.headers["Content-Security-Policy"] = CSP
    if request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-cache"})




@app.get("/api/docs", include_in_schema=False)
def offline_docs():
    return FileResponse(os.path.join(STATIC, "docs.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=os.getenv("ASIVM_HOST", "0.0.0.0"), port=int(os.getenv("ASIVM_PORT", "8000")), workers=1)

