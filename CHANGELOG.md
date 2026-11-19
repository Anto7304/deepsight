# Changelog

## Interface and workflow update — 19 November 2026

- Removed the Effectiveness and Coverage pages.
- Kept the original Monitor, Analyze and Platform navigation. Removed the added Learn section, tutorial dashboard and in-app demonstration controls.
- New deployments start with empty inventory and collect through ordinary Integrations actions.
- The user manual and operator walkthrough are separate documents.
- Added an optional isolated working lab and import files for exercising normal scanning, importing and analyst workflows.
- Corrected queued integration labels and restricted Administration tabs to the relevant role.
- Identity merges carry missing inventory profile fields into discovered assets and restore them on revert while preserving later edits.

The entries below describe the original release. Backend evaluation and coverage APIs remain available for compatibility.

## 1.1.0 — 15 November 2026

Built on the 1.0.2 prototype. The dark interface, nine modules, evidence-grounded assistant and the protected
sign-in/session/token/role code are unchanged (see [docs/QA.md](docs/QA.md) for how that was checked).

### Added
- **Data freshness** — per asset: last successful observation, sources that saw it, expected sources that did not,
  and conflicting evidence. “No vulnerability detected” is separated from “not recently assessed”; the assessment-age
  threshold is a setting (`ASIVM_ASSESSMENT_AGE_HOURS`, adjustable at `/api/settings/assessment-age`).
- **Remediation workflow** — owner, due date, guidance, ticket link, status, and accepted-risk / false-positive states that
  require reason, approver and expiry. Findings close only through a newer, successful, in-scope verification scan; the
  before/after evidence is stored. Time to fix, SLA breaches, aging, risk removed per verified fix and a what-if view.
- **IoT policy findings** — exposed management interface, unsupported/end-of-life firmware, Telnet, FTP, cleartext MQTT,
  RTSP without authentication, raw print and Winbox are scored as findings without needing a CVE match.
- **Analyst workflow** — prioritized work queue with a “why this needs attention” explanation, saved filters, global
  search and atomic bulk triage.
- **ML validation** — fixed evaluation fixtures for identity matching and anomaly detection that the training generator did
  not produce, stored as model runs; analyst feedback is reported as a separate cohort; EPSS as a labelled risk factor; an
  Effectiveness page.
- **Coverage and integrations** — NVD/CPE applicability matching on imported NVD JSON, Trivy and Grype import, CMDB
  reconciliation view, candidate attack paths, outbound webhooks for new critical/KEV findings with a durable outbox, and
  assistant prompts that treat asset text as untrusted data plus a fixed question set that checks citations.
- **Reliability** — durable background jobs with an independent heartbeat, schema-version migration, backup with an automated
  restore comparison, raw-evidence archiving, idempotent re-imports, indexed identity-candidate blocking, health endpoint,
  Prometheus metrics, JSON logs, rate-limiter eviction, a distinct error for undecryptable secrets, and an allowed-CIDR setting
  for TCP discovery.
- **Packaging** — pinned dependencies, `requirements-dev.txt`, CI workflow, offline Swagger UI, one-command demo script,
  “Reset demo” button.

### Changed in the final 1.1.0 pass
- Effectiveness page now shows tables and metric tiles instead of raw JSON, and says “Not evaluated yet” until the fixed
  evaluation has been run.
- Evaluation output reports only the error rate that is meaningful for each model (`false_merge_rate` for identity,
  `false_alert_rate` for anomaly detection).
- Documentation rewritten for 1.1.0 (README, HANDOFF, `docs/IMPLEMENTATION_STATUS.md` with separate Status and Roadmap
  columns, `docs/QA.md`). The README no longer shows a password on the command line.

### Fixed in the final 1.1.0 pass
- The demo CMDB feed was categorised as `infrastructure`, so the Coverage page listed every demo asset as “seen, not in CMDB”.
  It is now a CMDB source.
- “Reset demo” deleted the worker/scheduler heartbeat rows, so `/api/health` answered 503 for a few seconds afterwards. The
  heartbeats are now preserved.

### Known limits carried into 1.1.0
- `pip-audit` reports 16 distinct advisories (19 rows) against PyJWT 2.12.1. The fix is a PyJWT upgrade; it was not made because
  the brief places tokens and sessions out of scope. The CI `pip-audit` step will fail until that is done.
- No model trained on CISA KEV was built (the brief made it optional). The risk score remains an explainable weighted heuristic.
- Evaluation fixtures are small (16 identity pairs, 12 change events). Load figures are single-process SQLite measurements.
- The Docker image was built in the original session, but it was **not** rebuilt in this recovery (no Docker daemon available).
