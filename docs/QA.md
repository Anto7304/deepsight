> Current interface and ordinary workflow validation: [VALIDATION.md](VALIDATION.md). Older results below describe the original archive.

# DEEPSIGHT 1.1.0 — QA record

Revision 1.1.0 · verified 15 November 2026 (UTC) on Linux 6.18, 2 CPUs, Python 3.13.18, Node 22, PostgreSQL 16.15.
Raw logs are in `qa/`. Every number below comes from a command run in the final pass (section 1) or from a saved log that is
explicitly labelled **historical** (section 2). Nothing here is a production claim.

## 1. Verified in the final pass, on the release files

Run from the project root.

| Command | Result | Log |
|---|---|---|
| `python -m pytest tests -q` (SQLite) | **64 passed** in 37.36 s | `qa/final-sqlite.txt` |
| `ASIVM_TEST_DATABASE_URL=<new empty PostgreSQL 16 database> python -m pytest tests -q` | **64 passed** in 71.40 s | `qa/final-postgres.txt` |
| `ruff check app lab scripts tests` | All checks passed | `qa/ruff.txt` |
| `node --check app/static/app.js` | ok | `qa/ruff.txt` |
| `python -m compileall -q app lab scripts` | ok | `qa/ruff.txt` |
| `python scripts/backup.py backup / check / restore` | see 1.2 | `qa/backup-restore.txt` |
| `python scripts/load_test.py --assets 1000` and `--assets 5001` | see 1.3 | `qa/load-1000.json`, `qa/load-5001.json` |
| `python scripts/measure_evaluation.py` | see 1.4 | `qa/evaluation.json` |
| `pip-audit -r requirements.txt` | **19 rows, 16 distinct advisories, all PyJWT 2.12.1** | `qa/pip-audit-final.txt` |

PostgreSQL note: the first PostgreSQL run in this pass reused the database from an earlier run and 14 tests failed on leftover
rows. After dropping and recreating an empty database the full suite passed. Use a new empty database for every run.

The suite grew from the 33-test baseline of 1.0.2 to 64. New tests cover freshness, remediation, IoT policy findings, work queue,
evaluation, EPSS, NVD/CPE, Trivy/Grype, CMDB reconciliation, attack paths, webhooks, assistant grounding, durable jobs,
migration, retention, backup/restore, rate-limit eviction, secret-decryption errors, TCP CIDR limits, offline docs, plus two
regression tests added in the final pass (demo CMDB source category; demo reset keeps heartbeats).

### 1.1 Browser walk through (final pass)
Playwright/Chromium against a locally started instance with the synthetic demo dataset: signed in, then opened Overview,
Work queue, Assets, Findings, Infrastructure, Intelligence, Effectiveness, Investigations, Reports, Integrations, Coverage,
Global search and Administration at 1440×900. No page showed an error, and there were no browser console errors or warnings and no
failed or 4xx/5xx requests. The Overview “Reset demo” button was clicked: the demo reloaded, `/api/health` stayed 200 throughout,
and Coverage then showed one asset in the CMDB but never seen (`ws-006`) and the cloud/Kubernetes assets as seen but not in the
CMDB. Effectiveness was checked before and after *Run fixed evaluation*. `/api/docs` loads its CSS and JavaScript from
`/static/vendor/` (no external hosts). The mobile layout was **not** re-checked in this pass.

### 1.2 Backup and restore
Source: a SQLite database loaded with the synthetic demo (24 tables, 3,203 rows, 1 data file — the secret key).
- `backup` wrote `backup.json` and a SHA-256 file. `check` restored into a temporary SQLite database and compared every table: verified.
- `restore` into a new SQLite database: verified. `restore` into an empty PostgreSQL 16.15 database (cross-database): verified,
  with sequences reset.
- A second restore into the now non-empty PostgreSQL database was refused (“Restore target must be empty”).
- A backup edited after its checksum was written was refused (“Backup checksum mismatch”).

Limits: the backup is unencrypted JSON containing password hashes and the secret key; it was exercised on a demo-sized database
(no large evidence archive); restore of a live, multi-replica deployment was not tested.

### 1.3 Load test (`scripts/load_test.py`)
Isolated temporary SQLite database, single process, one synthetic source, one device identifier and hostname per asset.

| Assets | Stored | Failed | Ingest time | Observations/s | 1,000 candidate lookups | Max candidates |
|---|---|---|---|---|---|---|
| 1,000 | 1,000 | 0 | 10.827 s | 92.365 | 0.605 s | 1 |
| 5,001 | 5,001 | 0 | 57.327 s | 87.237 | 0.513 s | 1 |

Candidate lookup time stays flat as the table grows from 1,000 to 5,001 assets, which is what indexed hostname blocking is meant
to do. What this does **not** show: findings, relationships, graph or anomaly work, network collectors, PostgreSQL behaviour,
concurrent users or production capacity. The saved log from the earlier session measured 60.8 and 63.9 observations/s on a
different machine, so treat throughput as machine-dependent and roughly 60–90 observations/s here, not a guarantee.

### 1.4 Fixed evaluation (`scripts/measure_evaluation.py`, `qa/evaluation.json`)
Fixtures are in `eval/`: 16 hand-labelled identity pairs and 12 hand-labelled change events, authored independently of the training
generators; they are not production data.

| Model | n | Precision | Recall | Accuracy | Error rate |
|---|---|---|---|---|---|
| Identity matching | 16 | 1.000 | 0.778 | 0.875 | false-merge rate 0.000 (0 of 7 predicted merges) |
| Anomaly detection | 12 | 0.714 | 1.000 | 0.833 | false-alert rate 0.286 (2 of 7 negatives alerted) |

“Positive” for anomalies means *warrants review*, never *malicious*. With sixteen and twelve examples a single case moves a metric
by 6–8 points, so these figures describe the fixtures, not real-world performance.
Analyst-feedback sensitivity: the script adds **one simulated** analyst “false positive” review (labelled as simulated in the
output). The combined anomaly cohort then reads precision 0.625, recall 1.000, accuracy 0.769 (n = 13). This shows that feedback is
captured and reported separately; it is not a measured effect of real analyst feedback, and no retraining occurs.

## 2. Historical evidence (saved by the earlier session; not re-run)

| Item | Saved result | Why it is not re-run |
|---|---|---|
| Per-phase test counts (`qa/phase1.txt` … `qa/phase7.txt`) | 35, 38, 46, 47, 49, 55, 55, 62 passed | superseded by section 1 |
| Docker image build (`qa/docker-build.txt`) | built `deepsight:1.1.0` | No Docker daemon in the recovery environment. The log was produced from a `Dockerfile.qa`, which is not in this repository, so it does not prove the shipped `Dockerfile` builds. Re-run `docker build -t deepsight:1.1.0 .` |
| Protected-scope check (`qa/protected-scope.json`) | 15 of 15 comparisons true | needs the 1.0.2 archive (`python scripts/check_scope.py <archive>`) |
| Original-archive baseline (1.0.2 QA) | 23 passed, 1 failed (duplicate IoT findings, fixed in 1.0.1) | superseded |

## 3. Unresolved issues and limits

1. **Dependency advisory.** `pip-audit` reports 16 distinct advisories (19 rows) against PyJWT 2.12.1. Its output lists fixed
   versions between 2.13.0 and 2.15.0 (PYSEC-2026-4146 lists none). Upgrading was not done: the brief puts sessions and tokens out of
   scope, and a PyJWT change must be tested with the authentication tests deliberately. The CI `pip-audit` step fails until then.
2. **CI workflow not executed.** `.github/workflows/ci.yml` lists the same checks as section 1 plus `docker build` and `pip-audit`,
   but it has not run on a CI service.
3. **Docker.** See section 2. The full compose stack and the four-container IoT lab were not started in the final pass.
4. **No model trained on CISA KEV.** The brief made it optional. The contextual risk score remains a weighted heuristic.
5. **Small, synthetic validation.** Evaluation fixtures, the assistant question set (4 questions) and the load test are small and
   synthetic. The identity and anomaly models were trained on generated data.
6. **Assessment evidence.** Only observations that declare a complete, successful vulnerability assessment (Trivy/Grype imports,
   or the API with an `assessment` block) make an asset “no vulnerability detected”. Demo scanner-CSV data therefore shows assets as
   “not recently assessed”.
7. **Not exercised:** KEV/NVD network sync, EPSS download (values are imported), the assistant in Claude mode, delivery of webhooks
   to a real receiver, live customer infrastructure, mobile layout in the final pass, multi-replica operation.
8. **CMDB flag.** A source is counted as the CMDB only when created with category `cmdb` (or `config.is_cmdb`) through the API;
   the integration dialog has no such field.
9. **Authentication.** Unchanged from 1.0.2, including the absence of SSO/MFA.

## 4. How to reproduce
```bash
pip install -r requirements-dev.txt
python -m pytest tests -q
node --check app/static/app.js && python -m compileall -q app lab scripts && ruff check app lab scripts tests
python scripts/load_test.py --assets 1000 && python scripts/load_test.py --assets 5001
python scripts/measure_evaluation.py
pip-audit -r requirements.txt
python scripts/backup.py backup backup.json && python scripts/backup.py check backup.json
```
Notes from before 1.1.0 are kept in [FIXES.md](FIXES.md) (historical).
