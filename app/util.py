from datetime import datetime, timezone


def now() -> datetime:
    """Naive UTC 'now' - every timestamp in DEEPSIGHT is stored as naive UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def parse_ts(v):
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, (int, float)):
        dt = datetime.fromtimestamp(v, timezone.utc)
    else:
        s = str(v).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def uid(prefix: str, n: int) -> str:
    return f"{prefix}-{n:06d}"
