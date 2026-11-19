import hashlib
import hmac
import os
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import AuditLog, User
from .util import now

ROLES = ["administrator", "analyst", "manager", "readonly"]
ROLE_DESCRIPTIONS = {
    "administrator": "Manages platform configuration, integrations, users and permissions.",
    "analyst": "Investigates assets, findings, intelligence and risk assessments.",
    "manager": "Reviews security posture, investigations and reports; can validate investigations.",
    "readonly": "Views authorized information without modifying platform records.",
}
_ITER = 210_000


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, _ITER)
    return f"pbkdf2${_ITER}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, it, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


def make_token(user: User) -> str:
    exp = now() + timedelta(minutes=settings.token_ttl_minutes)
    return jwt.encode({"sub": user.username, "role": user.role, "exp": exp}, settings.secret_key, algorithm="HS256")


_fernet = Fernet(settings.fernet_key)


def encrypt_secrets(d: dict) -> str:
    import json
    return _fernet.encrypt(json.dumps(d or {}).encode()).decode()


class SecretDecryptionError(RuntimeError):
    """Stored integration secrets cannot be decrypted with this deployment key."""


def decrypt_secrets(s: str | None) -> dict:
    import json
    if not s:
        return {}
    try:
        return json.loads(_fernet.decrypt(s.encode()).decode())
    except (InvalidToken, ValueError) as exc:
        raise SecretDecryptionError("Stored integration secrets could not be decrypted; check the deployment encryption key.") from exc


_bearer = HTTPBearer(auto_error=False)


def current_user(request: Request, cred: HTTPAuthorizationCredentials = Depends(_bearer),
                 db: Session = Depends(get_db)) -> User:
    if not cred:
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(cred.credentials, settings.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user or not user.active:
        raise HTTPException(401, "User disabled or unknown")
    request.state.user = user.username
    return user


def require(*roles: str):
    allowed = set(roles)

    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(403, f"Requires role: {', '.join(sorted(allowed))}")
        return user
    return dep


ADMIN = ("administrator",)
ANALYST = ("administrator", "analyst")
VALIDATOR = ("administrator", "analyst", "manager")
ANY = tuple(ROLES)


def audit(db: Session, user, action: str, resource: str = "", detail: dict | None = None, request: Request | None = None):
    name = user.username if hasattr(user, "username") else (user or "system")
    ip = request.client.host if request is not None and request.client else None
    db.add(AuditLog(user=name, action=action, resource=resource, detail=detail or {}, ip=ip))
    db.commit()


class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()
        self.expiry = {}
        self.last_sweep = 0.0

    def allow(self, key: str, limit: int, window: int = 60) -> bool:
        t = time.monotonic()
        with self.lock:
            if t - self.last_sweep >= 60:
                for old in [k for k, expiry in self.expiry.items() if expiry <= t]:
                    self.hits.pop(old, None)
                    self.expiry.pop(old, None)
                self.last_sweep = t
            self.expiry[key] = t + window
            q = self.hits[key]
            while q and q[0] < t - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(t)
            return True


limiter = RateLimiter()
