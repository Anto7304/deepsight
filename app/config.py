import base64
import hashlib
import os
import secrets


def _bool(v, default=False):
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self):
        self.data_dir = os.getenv("ASIVM_DATA_DIR", "./data")
        self.database_url = os.getenv("ASIVM_DATABASE_URL", f"sqlite:///{self.data_dir}/asivm.db")
        key = os.getenv("ASIVM_SECRET_KEY")
        if not key:  # persist a generated key next to the data so sessions and encrypted secrets survive restarts
            path = os.path.join(self.data_dir, "secret.key")
            try:
                os.makedirs(self.data_dir, exist_ok=True)
                if os.path.exists(path):
                    key = open(path).read().strip()
                else:
                    key = secrets.token_urlsafe(48)
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as fh:
                        fh.write(key)
            except OSError:
                key = None
        self.ephemeral_secret = not key
        self.secret_key = key or secrets.token_urlsafe(48)
        self.token_ttl_minutes = int(os.getenv("ASIVM_TOKEN_TTL_MINUTES", "480"))
        self.admin_user = os.getenv("ASIVM_ADMIN_USER", "admin")
        self.admin_password = os.getenv("ASIVM_ADMIN_PASSWORD")
        self.worker_enabled = _bool(os.getenv("ASIVM_WORKER"), True)
        self.raw_retention_days = int(os.getenv("ASIVM_RAW_RETENTION_DAYS", "30"))
        self.tcp_allowed_cidrs = [x.strip() for x in os.getenv("ASIVM_TCP_ALLOWED_CIDRS", "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if x.strip()]
        self.scheduler_enabled = _bool(os.getenv("ASIVM_SCHEDULER"), True)
        self.assessment_age_hours = float(os.getenv("ASIVM_ASSESSMENT_AGE_HOURS", "168"))
        self.inactive_after_hours = int(os.getenv("ASIVM_INACTIVE_AFTER_HOURS", "48"))
        thr = os.getenv("ASIVM_ANOMALY_THRESHOLD")
        self.anomaly_threshold = float(thr) if thr else None  # None = derived from model
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.assistant_model = os.getenv("ASIVM_ASSISTANT_MODEL", "claude-sonnet-5-5")
        self.rate_limit_per_min = int(os.getenv("ASIVM_RATE_LIMIT_PER_MIN", "600"))
        self.login_rate_limit_per_min = int(os.getenv("ASIVM_LOGIN_RATE_LIMIT_PER_MIN", "10"))
        self.kev_auto_sync = _bool(os.getenv("ASIVM_KEV_AUTO_SYNC"), False)
        self.allow_tcp_discovery = _bool(os.getenv("ASIVM_ALLOW_TCP_DISCOVERY"), True)

    @property
    def fernet_key(self) -> bytes:
        return base64.urlsafe_b64encode(hashlib.sha256(self.secret_key.encode()).digest())


settings = Settings()
