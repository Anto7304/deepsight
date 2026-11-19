# DEEPSIGHT — See beyond the surface

DEEPSIGHT collects infrastructure evidence, resolves asset identity, records changes, matches vulnerability and IoT configuration findings, scores contextual risk, and supports investigation and evidence-gated remediation.

Read the separate [User manual](docs/USER_MANUAL.html) and [Operator walkthrough](docs/OPERATOR_WALKTHROUGH.html). Markdown sources are included in `docs/`.

The interface contains the normal operational pages: Overview, Work queue, Assets, Findings, Infrastructure, Intelligence, Investigations, Reports, Integrations, Global search and Administration. Effectiveness and Coverage are removed. New installations start with no collected infrastructure evidence. Scanning, importing and analyst work happen through the existing operational controls.

## Start the application

From the extracted application folder:

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs app
```

Open `http://localhost:8000`, or the configured `ASIVM_PORT`. On first start, the application prints the generated administrator password once if `ASIVM_ADMIN_PASSWORD` is empty. The normal administrator name is `admin`. Set a password in the environment before first start if preferred. Existing database contents survive restarts.

API documentation at `/api/docs` uses bundled Swagger assets and works without a CDN. Obtain a session through `POST /api/auth/login`, then use its Bearer token for authenticated requests.

## Isolated working lab

To rehearse the ordinary system workflows with reachable devices and prepared import files:

```bash
python3 scripts/start_lab.py
```

This starts the normal application with a separate empty database and an isolated lab. It does not create integrations, run scans or import evidence. Choose an administrator password of at least 12 characters at its hidden prompt, or set `ASIVM_ADMIN_PASSWORD`.

The launcher prints the application URL, device addresses, TCP configuration, HTTP receiver URL and generated import directory. The default project is `deepsight-lab` on `http://localhost:8001`. Follow the [Operator walkthrough](docs/OPERATOR_WALKTHROUGH.html) to add a discovery source, scan devices, upload the prepared files and use each remaining feature through its normal page.

The Docker lab uses emulated camera/Telnet/SSH devices and a Mosquitto broker on a private network. Lab services publish no host ports. The launcher selects a free private subnet so separate deployments do not collide. Prepared organization history and assessment files describe a controlled fictional environment; the separate walkthrough explains their provenance. Live TCP collection obtains current service reachability from the lab itself.

Linux users can install `requirements.txt` in a virtual environment and use:

```bash
python3 scripts/start_lab.py --local
```

Local mode uses four loopback emulators and an HTTP feed bound to a private local interface. Its MQTT device is a protocol stub. Stop the named lab using the command printed by the launcher; stopping preserves its data. `--fresh --port 8002` starts a new deployment on a free port.

After importing changed evidence, refresh the clean verification file before uploading it:

```bash
python3 scripts/prepare_imports.py --output data/deepsight-lab/imports --verification-only
```

Use the actual import directory printed for your deployment. This command changes a file; it does not close a finding. An analyst imports the file and uses its observation ID in **Verify and close**.

For an explicit automated rehearsal against the isolated lab, the operator script uses ordinary APIs:

```bash
python3 scripts/run_scenario.py --url http://localhost:8001 --imports data/deepsight-lab/imports
```

This optional test performs the operational actions and records their results. Use the manual scan/import controls for the first walkthrough. Practice exports are also provided under `samples/scenario/`; use the launcher's generated folder for correctly mapped device addresses and current timestamps.

## Run without Docker

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

SQLite data and the deployment secret key live in `./data` by default. Use one application replica: identity resolution is serialized in process. The scheduler and durable worker run by default.

## Configuration

| Setting | Purpose |
|---|---|
| `ASIVM_ADMIN_USER`, `ASIVM_ADMIN_PASSWORD` | Initial administrator credentials. An empty password is generated and printed once. |
| `ASIVM_SECRET_KEY` | Session signing and integration-secret encryption key; generated and persisted if absent. |
| `ASIVM_DATABASE_URL`, `ASIVM_DATA_DIR` | Database and application storage. |
| `ASIVM_PORT` | Published application port. |
| `ASIVM_ALLOW_TCP_DISCOVERY`, `ASIVM_TCP_ALLOWED_CIDRS` | Enable discovery and limit authorized target ranges. |
| `ASIVM_WORKER`, `ASIVM_SCHEDULER` | Durable background work and scheduled collection. |
| `ASIVM_ASSESSMENT_AGE_HOURS` | Freshness threshold for successful scoped assessments, default 168 hours. |
| `ASIVM_RAW_RETENTION_DAYS` | Age threshold for raw-payload archiving, default 30 days. |
| `ASIVM_KEV_AUTO_SYNC` | Optional daily live CISA KEV synchronization; needs internet access. |
| `ANTHROPIC_API_KEY`, `ASIVM_ASSISTANT_MODEL` | Optional external LLM assistant mode. The built-in evidence mode works without a key. |

## Checks and operations

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests -q
node --check app/static/app.js
python3 -m compileall -q app lab scripts
ruff check app lab scripts tests
```

Tests use a disposable database. Optional PostgreSQL tests require `ASIVM_TEST_DATABASE_URL` pointing to a new, empty test database.

`GET /api/health` checks readiness. Authenticated `/api/metrics` provides Prometheus text; administrators can inspect `/api/jobs` for durable work and `/api/webhooks/deliveries` for notifications. `scripts/backup.py` supports backup, restore and backup verification; restore requires a separate empty database. The user manual explains sources, roles, assessment scope and operational limits.
