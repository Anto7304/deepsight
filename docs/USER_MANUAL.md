# DEEPSIGHT user manual

Use DEEPSIGHT to answer four practical questions: **What assets do I have? What changed? What should I investigate or fix first? What evidence shows the work is complete?**

The platform starts with an empty inventory. You add evidence through a scan, a file import, or a collector. DEEPSIGHT then proposes or confirms asset identities, records their services and history, matches findings, and calculates risk. Probable identity matches stay separate until an analyst confirms them. It does not patch devices, execute the assistant's advice, or create tickets simply because you enter a ticket link.

For a first session, follow the separate [Operator walkthrough](OPERATOR_WALKTHROUGH.html) ([Markdown source](OPERATOR_WALKTHROUGH.md)). A printable [HTML copy of this manual](USER_MANUAL.html) is included with the release. The platform uses its normal operational screens for scanning, importing and analysis.

## 1. Start and sign in

Extract the application archive, open a terminal in the application folder, and run:

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs app
```

Open `http://localhost:8000`, unless you changed `ASIVM_PORT`. The first start prints the generated administrator password if `ASIVM_ADMIN_PASSWORD` is empty. Set your own password in the environment before the first start if preferred. Sign in as the configured administrator, normally `admin`.

New installations have no collected infrastructure evidence. Existing database contents remain when you restart. Scan or import through **Integrations** to build the inventory. For the isolated working lab, use `python3 scripts/start_lab.py` and follow the separate operator walkthrough; this also starts the normal application, without collecting data automatically.

### Your account determines which buttons work

| Account role | What you can do |
|---|---|
| Readonly | Browse assets, findings, graph, intelligence and investigations; search; ask the assistant; download reports; save your own queue filters. |
| Manager | Readonly actions, view system status, and validate investigation conclusions. |
| Analyst | Readonly actions, change asset criticality, review identity/anomalies, triage findings, verify fixes, and create/update investigations and notes. |
| Administrator | Analyst actions plus integrations, collections, imports, users, audit, model retraining and system operations. |

Sign out from the sidebar when finished. If the session expires, sign in again. A permission error generally means the action needs a different role; creating an integration or importing a file needs an administrator.

## 2. A simple daily routine

1. **Integrations:** collect or import new evidence. Check that the run succeeded and processed records.
2. **Overview:** look for new assets, external exposure, critical/high risks, and anomalies awaiting review.
3. **Work queue:** choose the next finding, read why it is prioritized, and assign an owner and status.
4. **Finding or asset:** read the source evidence and suggested action before changing anything outside DEEPSIGHT.
5. **Investigations:** record what you checked and your conclusion. Use the assistant to retrieve supporting evidence.
6. After an actual fix, import a newer assessment that explicitly covers the finding. **Verify and close** records the evidence that the finding is absent.
7. **Reports:** download a summary to share or retain.

## 3. Understand source labels before acting

| Label or term | Meaning and what to do |
|---|---|
| Asset | A device, server, cloud resource, virtual machine, container or other thing that a source observed. |
| Observation | One source's record about an asset at a particular time. Open it to see the normalized record and original source data. |
| Finding | A CVE match or configuration concern attached to an asset. A finding can require investigation without proving exploitation. |
| Observed | The source directly reported the information, such as a scanner reporting a CVE. Still check source quality and age. |
| Inferred | DEEPSIGHT derived the result, such as matching a service version against a catalog or identifying an unsafe IoT configuration. Verify the inference. |
| ML-predicted / predicted | A model detected an unusual pattern or supplied a prediction. Review the evidence; it is not confirmation of an attack. |
| Analyst-validated | A user with validation rights recorded a review decision. This is a human judgment, not a new scan. |
| CVSS | The published severity score for a vulnerability, usually 0–10. It does not consider your full environment. Configuration findings can have no CVSS. |
| Contextual risk | DEEPSIGHT's weighted 0–100 priority score. It considers severity, exposure, business criticality, known exploitation, dependencies and evidence. It is not a probability of compromise. |
| Confidence | Confidence in the identity or finding evidence, not a guarantee that the device is secure or compromised. |
| KEV | The CVE is in CISA's Known Exploited Vulnerabilities catalog. The bundled snapshot is historical; use live synchronization for current information. |
| External | Evidence indicates internet exposure. A private IP alone does not prove a service is internal; perimeter or cloud evidence can identify forwarding/exposure. |
| Criticality | Your business importance for an asset, from 1 to 5. Raising it can raise contextual risk. |
| Not recently assessed | No recent successful assessment with explicit scope is available. It does not mean “no vulnerabilities.” |
| No vulnerability detected | A recent successful assessment reported no finding within its stated scope. It does not establish that every possible vulnerability was tested. |

The `verify` risk level means the evidence needs verification. Times shown in the interface are UTC. Empty optional fields mean the source did not supply that information. For example, a TCP scan cannot supply a business owner, and an IoT policy finding may have no published CVSS or ATT&CK technique.

## 4. Overview: decide where to look

Open **Overview** after an import or collection. Use **Refresh** to fetch current results.

The main cards show total assets, external assets, open findings, critical/high contextual findings, anomalies awaiting review, and open investigations. Click a card to open the corresponding records. “Published vs contextual” compares vendor CVSS severity with DEEPSIGHT's environment-specific priorities. Trends show changes and open findings across 14 days when history exists; a new deployment cannot show a meaningful past trend until you import historical evidence or collect over time.

The freshness line shows assets lacking recent assessment and assets with conflicting source evidence. Investigate conflicts on the asset's detail page. “Top contextual risks” is your shortlist; it is not a list of confirmed attacks.

Stopping or restarting the application preserves stored evidence. Use a separate deployment and database when you need an empty inventory for an operator rehearsal.

## 5. Integrations: get data into the platform

An integration defines a source and how DEEPSIGHT receives its data. Some integrations collect from a target. Others only import files exported by another tool.

### Import a file

1. Open **Integrations → Add integration**.
2. Give the source a meaningful name, such as `Weekly Nmap` or `Server inventory`.
3. Choose the connector matching the file format in the table below. Use **Insert template** where configuration is needed. Leave a file-only source's schedule at zero.
4. Save the integration. Choose **Test**; an import connector's test validates setup and does not parse a file or scan a device.
5. Choose **Import file**, select the source, choose your file, and click **Upload & import**.
6. Read received, processed, duplicate, rejected and failed counts. Open **Run history** to see details. Then open **Assets** or **Findings**.

The import dialog accepts text-based formats. The import payload limit is 20,000,000 characters and filenames are limited to 200 characters. Split larger exports. Merely selecting a file does not import it.

| Connector | File to supply | What it adds |
|---|---|---|
| Host inventory (CSV) | CSV with identifiers such as `ip`, `hostname`, `mac`, `cloud_id`, `serial`; optional `os`, `owner`, `criticality`, `type`, `tags`, `ports`, `last_seen`. See `samples/cmdb.csv`. | Asset identity, owner/business context and optional ports. Separate tags with `;` or `|`. Inventory is not a vulnerability assessment. |
| Nmap scan (XML, -oX) | XML created with Nmap's `-oX` export. See `samples/nmap-scan.xml`. | Host identifiers, reported OS, open services, products and versions. It imports an existing scan; DEEPSIGHT does not run Nmap. |
| Vulnerability scan results (CSV/JSON) | CSV/JSON with `host` or `ip`, optional `hostname`, and `cve`, `port`, `cvss`. See `samples/vuln-scan.csv`. | Scanner-reported CVEs as observed findings. A missing CVE row in a CSV does not prove a complete clean assessment. |
| Generic observations (JSON) | A list of objects containing `identifiers`, `attributes`, optional `observed_at`, `category` and `raw_ref`. See the prepared `lab-inventory.json` and `baseline-history.json` files described in the operator walkthrough. | Rich inventory, services, software, IoT metadata, relationships, historical observations and explicitly scoped assessments. |
| AWS EC2 inventory (JSON) | `aws ec2 describe-instances` output. Optional merged `SecurityGroups` data. See `samples/aws-describe-instances.json`. | EC2 identifiers, network information, tags and configuration; security-group definitions can add exposure evidence. |
| Azure VM inventory (JSON) | `az vm list -d -o json`. | VM/cloud identifiers, OS, location and configuration. |
| Oracle Cloud instances (JSON) | `oci compute instance list` output. | Instance/cloud identifiers, shape and state. Network addresses are only present if your source provides them through a supported observation format. |
| Kubernetes nodes/pods (JSON) | `kubectl get nodes,pods -A -o json`; set `cluster_name` in configuration. See `samples/kubectl-nodes-pods.json`. | Cluster, nodes, containers, software/services and relationships such as “runs on.” |
| Trivy JSON | Trivy JSON export; set `assessment_codes` when a clean scan must explicitly cover particular prior findings. | Observed package findings and successful assessment scope. |
| Grype JSON | Grype JSON export; use `assessment_codes` for additional explicitly assessed finding codes. | Observed package findings and successful assessment scope. |

Do not select a JSON connector merely because the extension is `.json`: AWS, Kubernetes, scanner and generic observation structures are different. Use the matching connector.

### Run live TCP discovery

1. Open **Integrations → Configure discovery**, or add **TCP connect discovery (authorized targets)**.
2. Enter only IP addresses or CIDR ranges you are authorized to scan.
3. Confirm **I am authorised to scan these targets**.
4. Enter ports, timeout and maximum hosts. The **IoT ports** button adds common embedded-device ports. You can supply static hostnames and an asset type in Advanced settings.
5. Save; run **Test**, then **Collect** or **Collect now**. Wait for the run result.

**Test** checks target configuration and the deployment's allowed ranges; it does not establish that ports are reachable. **Collect** performs TCP connections and reads limited banners. It is not a full vulnerability scanner, authenticated audit, UDP discovery or firmware detector. Firmware/vendor/owner information comes from an inventory import or another source.

The server setting `ASIVM_TCP_ALLOWED_CIDRS` controls permitted ranges. Discovery can be disabled with `ASIVM_ALLOW_TCP_DISCOVERY=false`. At most 4,096 hosts and the first 200 configured ports are processed. For the isolated lab, use the four addresses and configuration printed by `scripts/start_lab.py`; Linux local mode uses `127.0.0.2`–`127.0.0.5`. The launcher selects and saves a free private Docker subnet to avoid another deployment.

### Collect an HTTP API and use a schedule

Add **HTTP API collector (JSON)**. Its configuration needs a reachable `url`, a supported `mapper` (`generic_json`, `aws_ec2`, `azure_vm`, `oci_instances`, or `k8s_json`), a timeout and TLS verification setting. If required, enter authorization headers in **Secrets**; secrets are encrypted and never shown again. **Test** checks the endpoint returns JSON, then **Collect** maps and ingests it.

Set **Collection schedule (minutes)** above zero for HTTP or TCP collectors. Zero means manual collection. The scheduler and background worker must be enabled. File import connectors cannot run on a schedule. Loopback, link-local and metadata HTTP destinations are blocked; a private Docker network address is appropriate for a local lab collector.

### Understand run results

| Result | Meaning | Next step |
|---|---|---|
| Success, processed records | Evidence was ingested. | Inspect assets/findings and check timestamps. |
| Duplicate records | The same observation was already ingested. | Usually expected on repeated imports. Use genuinely newer evidence to create change history. |
| Partial | Some records were rejected or failed, or none were usable. | Read run history; fix source data before treating the run as complete. |
| Failed | The collection/import could not complete. | Read the error, check format, credentials, targets and server/network access; retry after fixing it. |
| Running | Work is in progress. | Wait for completion. If stuck, inspect Administration system status and background jobs. |

## 6. Assets: understand one device or resource

Use the filters to find an asset by name, IP, MAC, owner, type, status, exposure, risk or identity. Sorting applies to the currently displayed page. Click a row to open its details.

| Asset tab | What to look for |
|---|---|
| Overview | Owner, OS, identifiers, identity confidence, risk factors and impact on connected assets. Change **Criticality** if your business importance differs from the imported value. |
| Identifiers | IPs, MACs, hostnames, cloud/device IDs, source and dates. Identity decisions help explain whether sources refer to the same asset. |
| Observations | Which sources reported it, when, quality flags and matching outcome. Click an observation to inspect normalized and raw data. |
| Services | Active and closed ports, products/versions and exposure evidence. Software appears beneath services. A banner is evidence of what was reported, not a complete installed-software audit. |
| Vulnerabilities | The asset's matched CVEs and configuration findings. Open a finding to review its basis. |
| Relationships | Which assets host it, depend on it, belong to it or connect to it; direction, evidence basis and confidence. |
| History | Changes between observations: services, software, attributes, configuration or lifecycle. |
| Risk | Past contextual scores, confidence and explanatory summary. |

The freshness panel lists recent/stale sources, expected sources that are missing when configured, and conflicting evidence. A vulnerability assessment must be recent, successful and explicitly scoped to support a “no vulnerability detected” state. Simple inventory, TCP/Nmap discovery or a scanner CSV without complete scope cannot establish that state.

For **IoT devices**, import both discovery evidence and inventory metadata. DEEPSIGHT can create `DS-IOT-*` configuration findings for cleartext management/services, exposed management, end-of-life firmware and related policies. The isolated lab uses emulators plus a Mosquitto broker; it does not exploit devices or test real credentials.

## 7. Findings and Work queue: organize remediation

**Findings** is the list of current findings; its visible search, contextual-risk and KEV filters help narrow the list. Additional asset/CVE/workflow filtering is available through the API. **Work queue** is ordered for action, with reasons such as active work, overdue due date, KEV and contextual priority. Its ordering does not prove a finding is exploitable.

In the queue, set `q`, `owner` or `state`, click **Apply**, and use **Save filter** to keep the current query under your own account. For bulk updates, select finding checkboxes, enter an owner, choose a state, then **Apply to selected findings**.

Open a finding to see the published data, affected asset/service, contextual factors, suggested actions, evidence and score history. Configuration findings have policy explanations and may have no CVSS. Suggested actions are advice; DEEPSIGHT does not apply them to your system.

### Save a workflow

Enter an owner, due date, remediation guidance and optional HTTP(S) ticket link, choose the status, then **Save workflow**.

| Status | Use it when |
|---|---|
| `new` | Work has not been reviewed. |
| `confirmed` | You reviewed the evidence and believe the finding is valid. |
| `in_progress` | Someone is actively working on it. |
| `pending_verification` | The fix is applied and a newer assessment is needed. |
| `accepted_risk` | A documented exception is in force. Supply its own reason, approver and future expiry. |
| `false_positive` | You documented why the finding is incorrect. Supply its own reason, approver and future expiry. |
| `resolved` | A successful newer scoped assessment verified absence of the finding. You cannot select this as a manual workflow shortcut. |

Use dates in ISO form, for example `2026-12-01`, or a timestamp such as `2026-12-01T12:00:00Z`. The approver field records your assertion; it does not send an approval request. Expired exceptions return to active work and do not count as verified fixes. A ticket link records a reference and does not create a ticket.

**What if this finding is fixed?** estimates the current weighted risk score after removing this finding while holding context unchanged. A small or zero reduction can be correct when another finding dominates risk. It does not predict reduced business loss or incidents.

### Verify and close a finding

1. Apply and assess the actual fix outside DEEPSIGHT. The separate operator walkthrough provides a controlled assessment fixture for rehearsing this process.
2. Import a **newer**, recent, successful **complete assessment of the same asset**. It must explicitly include the finding code in its assessed scope and omit the finding from reported results.
3. Find that record's observation ID in **Assets → asset → Observations**. Open the observation and check its source, assessment scope and time before using its ID.
4. Open the finding, enter the ID in **Verification observation ID**, and click **Verify and close**.
5. Confirm the finding is resolved and the evidence contains the verification record.

A service disappearing from a TCP scan or a CVE missing from a CSV is insufficient. Verification fails if the record is too old, not newer than the finding's last sighting, belongs to a different asset, lacks complete scope, or still reports the finding. If a later valid observation reports the finding again, it can reopen.

## 8. Infrastructure: follow dependencies and changes

Open **Infrastructure** after importing relationships or Kubernetes data. The graph shows connected assets; isolated assets without recorded relationships may not appear. Select a node to inspect related assets. Search a name, toggle **Edge labels** or **Inferred links**, and use graph controls to adjust the view. Follow an asset link to open its details.

Read the basis and confidence on each relationship. A recorded/inferred connection is not proof that an attacker can traverse it. The recent-changes list helps explain the graph's evolution. To populate it, collect/import a second observation that changes a service, version, address, configuration or relationship. Use the same source for consecutive snapshots so their differences can be compared. HTTP collectors provide another way to obtain these observations. Outbound webhook integrations can deliver newly eligible findings to your receiver; inspect delivery status through the API.

## 9. Intelligence: review unusual activity and identity

### Anomalies

The model compares changes with learned patterns. Open **Intelligence → anomalies**, read the summary/contributors, follow the asset and compare observations. The score is shown beside the decision threshold.

Use **True positive** when the unusual change merits the alert, **False positive** when the alert was inappropriate, or **Reviewed** when you have looked at it without giving that label. A true-positive anomaly can be a legitimate but unusual change; this decision alone does not prove malicious activity. Reviews become recorded analyst feedback.

To trigger useful anomalies, first collect a baseline/history, then change the environment and collect again. Importing historical baseline observations before a changed snapshot lets you rehearse this through the ordinary import controls. With no baseline or no unusual changes, no anomalies may be the correct result.

### Identity

Sources may describe the same device differently. Open **Intelligence → identity** and compare the observation's asset with the proposed candidate, the match confidence and the identifier evidence.

- **Same asset (merge):** combine the records when you have evidence they are the same device.
- **Separate:** reject the proposed match when they represent different devices.
- **Revert decision:** undo an analyst decision using its saved snapshot when you need to correct it.

Do not merge based on IP alone when addresses may have been reused. A confirmed identity is distinct from a confirmed security finding. An inventory record with a MAC address may require review before combining with an earlier IP/hostname-only scan record. Confirm a supported pair to obtain one combined profile; unresolved pairs can temporarily increase the asset count. Already confident matches can be confirmed automatically. Merges carry missing inventory profile fields into the combined asset. Reverting preserves later profile edits.

### Models

**Intelligence → models** explains the active identity, anomaly and contextual-risk models, their training data, versions, metrics and inference/error counts. Contextual risk is a rule-weighted heuristic. Model measurements on synthetic or analyst-labeled data describe those data; they are not a guarantee of field accuracy.

An administrator can choose **Retrain anomaly model on platform data**. The active version changes when retraining succeeds. Collect or import enough baseline history first so collected platform vectors participate; retraining on an empty database only uses bootstrap training data. Do not train only on one unusual event and assume the result is reliable.

### Catalog

**Intelligence → catalog** lists CVEs, CVSS, KEV, exploit information and affected findings. The bundled catalog is a snapshot. **Sync CISA KEV** needs internet access and the remote service to be available. Stored catalog evidence remains available without calling CISA. Administrators can also import NVD and EPSS information through the API, described below.

## 10. Investigations: keep a case record

From an asset or finding, click **Start investigation**. The investigation includes its scope and an evidence timeline. Add an analyst note stating what you checked, the evidence IDs, who will act, and any limits.

When ready, choose an outcome (`true_positive`, `false_positive`, `benign` or `unknown`), write a conclusion of at least three characters, and validate it. A permitted validator closes the investigation and records who/when. Closing an investigation does **not** verify and resolve its findings. Findings need their own newer assessment and **Verify and close**.

An administrator/analyst can link asset, finding and anomaly IDs through the investigation API. Validating a linked, still-new anomaly as true/false positive records corresponding feedback. Merely starting from an asset does not automatically link every anomaly to the case.

## 11. Assistant: ask for evidence

Open **Assistant** from the sidebar. When you are on an asset, finding or investigation, the assistant receives that page context. Try:

- “Why has the risk of app-server-01 increased?” after a changed observation has been collected or imported.
- “What is connected to ci-server-01?” after relationship evidence has been imported.
- “What changed in the last 24 hours?”
- “Which assets need attention?”
- On a finding: “Explain this finding and what I should check.”

Follow the references in the answer to verify its evidence. The assistant only retrieves/explains platform data; it cannot scan, patch, merge identities or close work on your behalf. Questions about assets absent from the database correctly produce a missing-evidence answer.

Without `ANTHROPIC_API_KEY`, the built-in **evidence** mode works locally with supported question types. Setting a valid key enables optional LLM mode, which requires internet/service access and still uses platform evidence. Leave the key unset for the reproducible offline walkthrough. Answers and chat history in the sidebar are not a substitute for saved investigation notes.

## 12. Reports and Global search

**Reports** provides Infrastructure inventory, Asset identity reconciliation, Vulnerability assessment, Contextual risk summary, Infrastructure changes, Anomaly investigation, Security posture overview and Investigation findings. Choose **HTML** to read/share a formatted report, **CSV** for a spreadsheet, or **JSON** for structured data. Each export states scope, sources and limitations; it is generated from current stored evidence.

Collect inventory, change, identity and finding evidence, then create an investigation before exporting all report categories. An empty investigation report before you create a case is expected.

**Global search** searches asset names/identifiers, findings and investigation titles. Enter an existing asset name, CVE or investigation title, then follow the result. A search with no matching evidence should say no matches; it should not invent records.

## 13. Administration and advanced operations

### System, users and audit

**Administration → system** shows API/database state, integrations, pipeline statistics and the scheduler heartbeat when your role permits it. `/api/health` also checks worker readiness. Collection starts asynchronous work; healthy worker and scheduler heartbeats are needed for scheduled operations. **Lifecycle sweep** updates old unseen assets according to the inactivity threshold; it does not rescan them.

Administrators create users on **Administration → users**. Use a username of 3–64 allowed characters and a password of at least 12 characters. Choose the least powerful role that supports the person's work. User role/password/active-status changes are available through `PATCH /api/users/{id}`.

**Administration → audit** records actions such as sign-in, imports/collections, triage, identity decisions, investigation validation, users and reports. It starts with few rows on a new database and grows as you perform operational tasks.

### API-only functions

Open `/api/docs` on your deployment for exact request schemas. For an authenticated API session, use `POST /api/auth/login`, then pass the returned token through **Authorize** as a Bearer token. Treat it like a password. These functions are useful to an administrator or developer; they are not all buttons in the main interface.

| Function | Trigger / evidence needed |
|---|---|
| Add/end an explicit relationship | `POST /api/relationships` with valid source/target asset IDs and a supported relationship type; `DELETE /api/relationships/{id}` ends it. Requires analyst/admin. |
| Submit custom observations | `POST /api/observations` with a batch of valid identifiers/attributes. Requires analyst/admin. Use a file-based generic integration for the beginner workflow. |
| Reassess/rematch | `POST /api/system/reassess`, `POST /api/intelligence/rematch`; use after context/catalog changes if needed. Requires admin. It recalculates from evidence; it does not scan. |
| NVD CVE enrichment | `POST /api/intelligence/nvd/{cve}` needs network access. `POST /api/intelligence/nvd-import` accepts a valid NVD JSON response locally, then rematches findings. Requires admin. |
| EPSS | `POST /api/intelligence/epss` with a list of `{cve, epss, date}` records, scores 0–1 and a valid date not in the future. Requires admin. It is a prediction from imported data, not exploitation confirmation. |
| Assessment freshness threshold | `GET/PUT /api/settings/assessment-age`; supply `hours` for updates. Requires admin to change. It alters freshness interpretation, not observation timestamps. |
| Jobs | `GET /api/jobs` after collection/maintenance; shows queued/running/completed/failed durable work and errors. Requires admin. |
| Metrics | `GET /api/metrics` returns Prometheus text to any signed-in user. `/api/health` is the readiness check and returns 503 if degraded. |
| Outbound notifications | Add an `outbound_webhook` integration with your HTTP(S) receiver URL before importing a **new critical or KEV finding**. New eligible evidence queues a delivery; `POST /api/webhooks/dispatch` attempts pending deliveries and `GET /api/webhooks/deliveries` shows status. Requires admin. **Test** validates the destination URL and sends no event. Repeated evidence is deduplicated; failed deliveries retry with a bound. A real receiver or local lab endpoint must exist. |

Backup, restore and raw-data retention are maintenance tasks. `scripts/backup.py` provides backup/check/restore commands, and `ASIVM_RAW_RETENTION_DAYS` controls raw-payload archiving. Use a separate empty database for restore. A backup contains sensitive account and secret material and must be stored appropriately. Recent records do not need to be archived merely to exercise retention.

## 14. When something looks blank or does not work

| Symptom | What to check |
|---|---|
| No assets | Finish a scan/import, inspect run counts, then refresh. On first start this is intentional. |
| Services but no owner/firmware | Import inventory metadata; discovery cannot infer business ownership or authoritative firmware details. |
| No findings | The source may not report CVEs and the service/version may not match the stored catalog. Import scanner findings and/or enrich the catalog. No finding does not imply a clean assessment. |
| No anomalies | Import/collect baseline history, then changed evidence; inspect collected model vectors and thresholds. The operator walkthrough supplies baseline and changed snapshots for controlled rehearsal. |
| No graph | Import relationships/Kubernetes data with valid referenced identifiers. Isolated nodes without links are not displayed in the main graph. |
| No history or flat trend | A single current snapshot contains no past changes. Import historical observations or collect again after an actual change. |
| No investigations | Open an asset/finding and choose Start investigation; add a note and conclusion. |
| Not recently assessed despite discovery | Discovery is not a complete vulnerability assessment. Import a successful scoped assessment. |
| Verify fails | Check same asset, explicit finding code scope, recent/newer timestamp, processed status, and finding absent from results. |
| TCP scan finds nothing | Confirm lab/target reachability **from the app server/container**, configured ports, authorization and allowed CIDRs. For the isolated lab, start it with `scripts/start_lab.py` and use its printed configuration. |
| HTTP test fails | Check the app server can resolve/reach the endpoint, returns supported JSON, and has correct secret headers/TLS settings. `localhost` is blocked for HTTP destinations. |
| Scheduled collection does not run | Ensure schedule is above zero, integration enabled, worker/scheduler enabled and system heartbeats healthy; inspect jobs. |
| KEV/LLM call fails | It requires working internet, credentials where applicable and an available remote service. Use stored catalog/evidence mode when working offline. |
| Import processed zero | Check format/connector, identifiers, duplicates and rejected/failed counts. Retrying an unchanged imported record can correctly be a duplicate. |
| Permission denied / expired session | Sign in with a role permitted for the operation or renew the session. |

The separate [Operator walkthrough](OPERATOR_WALKTHROUGH.html) maps each feature to an ordinary scan, import or analyst action. Optional missing values reflect absent source evidence; do not replace them with invented production facts.
