# Historical fixes from the supplied prototype

These notes came with the original (pre-1.1.0) archive and are kept for history; some “left alone” items below were addressed in 1.1.0
(for example, re-importing the same file is now idempotent). See [QA.md](QA.md) for this revision’s verified results.

Tested on SQLite and PostgreSQL 16 (the docker-compose stack). Regression tests for each item are at the end of `tests/test_asivm.py`.

| # | Problem | Fix (file) |
|---|---------|-----------|
| 1 | `GET /api/assets/{id}` and `/impact` returned 500 for any asset with no relationships | guard in `engines/graph.py::_bfs` |
| 2 | Malformed attribute shapes (`os` as object/number, `services`/`software`/`relations`/`findings` as non-lists, bad `relations[].target`) crashed ingestion and lost the whole batch | hardened `normalize.py`, safety net in `pipeline.receive`, tolerant `intel.apply_reported_findings` |
| 3 | Oversized integer ids returned 500 on ~29 endpoints | global `OverflowError` / DB `DataError` handlers in `main.py` (422) |
| 4 | NUL bytes caused 500s on PostgreSQL (search, login, patches, ingestion) | `RejectNul` middleware in `main.py` (400) + NUL scrub in `normalize.py` |
| 5 | Over-long strings silently failed on PostgreSQL column limits | clamped to column sizes in `normalize.py` |
| 6 | TCP discovery expanded a whole CIDR before the `max_hosts` check (`/8` = OOM, IPv6 `/64` = hang) | check size first; hard cap 4096 (`connectors/__init__.py`) |
| 7 | HTTP collector URL filter missed `::ffff:169.254.169.254`, loopback, `0.0.0.0`, non-169.254 metadata IPs | stricter `_ip_blocked` (`connectors/__init__.py`) |
| 8 | Investigations stored ids of nonexistent assets/findings/anomalies | existence check on create/patch (`api.py`) |
| 9 | Scheduled KEV sync status was written once and never updated | `main.py` |

## Known, intentionally left alone (prototype)
- Re-importing the same CSV / AWS / K8s / scanner file is not de-duplicated (observations without their own timestamp get a fresh one, so they hash differently). State stays idempotent; observations accumulate. Changing it would stop repeated manual observations from refreshing `last_seen`.
- HTTP collector resolves DNS once to validate and again to connect (DNS-rebinding window). Admin-only feature.
- `ASIVM_SECRET_KEY` has no minimum length check; use a long random value (see README).
- A CSV with no recognised columns reports "ok" with 0 usable rows.
- Not exercised: assistant in Claude-API mode, `docker compose build`, load/scale.
