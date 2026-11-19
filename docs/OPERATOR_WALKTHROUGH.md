# DEEPSIGHT operator walkthrough

Use this sequence to operate DEEPSIGHT through its ordinary screens: connect a source, scan, import evidence, review risk, investigate a change and verify remediation. No presentation page or special dashboard is required.

The isolated lab provides reachable TCP devices, an HTTP inventory endpoint and an alert receiver. Prepared organization history, vulnerability exports and clean assessments describe a controlled fictional environment. They are practice evidence, not claims that cloud resources were provisioned or that a live device was patched. The system remains the normal DEEPSIGHT application throughout.

Read the separate [User manual](USER_MANUAL.html) for each feature's meaning. Use this document as the action sequence and feature checklist.

## 1. Start an empty working environment

Extract the application archive and open a terminal in the application folder:

```bash
python3 scripts/start_lab.py
```

This requires Python 3 and Docker Compose. Choose the administrator password at the hidden prompt, unless you supplied `ASIVM_ADMIN_PASSWORD`. The launcher starts a separate normal application and the isolated devices, but performs no collection or import.

Open the printed application URL, normally `http://localhost:8001`, and sign in as the configured administrator, normally `admin`. Keep the terminal output available. It contains:

- The four target addresses and their hostnames.
- A complete authorized TCP configuration.
- The private HTTP inventory and alert receiver URL.
- The generated import directory, normally `data/deepsight-lab/imports`.
- The command to stop this named environment.

The Docker launcher selects and saves a free subnet. Use its printed addresses and generated files rather than assuming a particular `172.28.*` range. On **Overview**, **Assets**, **Findings**, **Investigations** and **Integrations**, confirm that no infrastructure evidence has been collected. Bootstrap model/catalog information and the administrator account can already exist.

An existing deployment keeps its previous data. To obtain a separate empty environment, use `python3 scripts/start_lab.py --fresh --port 8002`, choosing a free port. The launcher prints its generated deployment name and import directory.

### Linux without Docker

Install the application dependencies in a Python environment, then run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 scripts/start_lab.py --local
```

Local mode uses loopback devices at `127.0.0.2`–`127.0.0.5`. Its HTTP service binds to a private local interface, and its MQTT service is a protocol stub. Docker mode uses Mosquitto. Listener ports must be free. Use the addresses and generated import folder printed for this mode.

## 2. Scan through Integrations

1. Open **Integrations → Add integration**.
2. Name the source **Network discovery** and choose **TCP connect discovery**.
3. Paste the launcher's TCP configuration into **Configuration**, or enter the printed targets, ports, hostnames and asset type in the discovery fields.
4. Confirm **I am authorised to scan these targets**. Keep the collection schedule at zero for the first run.
5. Choose **Add integration**, then **Test**. The test validates configuration and allowed ranges.
6. Choose **Collect** or **Collect now**. Watch the source's run history until it records success.
7. Open **Assets** and inspect the four discovered devices.

Show the run's received/processed counts and one asset's **Services** and **Observations** tabs. The observations come from real TCP connections to the isolated devices. The camera, Telnet and SSH targets emulate protocol responses; they do not execute commands or accept real credentials.

Owner, vendor and firmware fields can be absent after discovery because TCP connections do not supply business context. The next file import adds that information.

If a scan fails, read its run error. Check the targets are reachable from the app server/container, the lab processes are running, authorization is true and the allowed CIDRs include the printed targets. A saved Nmap file exercises parsing; it does not replace a successful live collection.

## 3. Import inventory through the ordinary file dialog

1. Open **Integrations → Add integration**.
2. Name the source **Device inventory**, choose **Generic observations (JSON)**, and leave its schedule at zero.
3. Save it, then choose **Import file**.
4. Select the generated `lab-inventory.json` from the printed import directory.
5. Choose **Upload & import**, wait for the result, and inspect its processed/duplicate/rejected/failed counts.
6. Open a discovered device and check its profile, identifiers, observations, services and findings.

Both scan and inventory observations should be available on combined device profiles. If **Intelligence → identity** shows a probable match between a scanned IP/hostname record and a richer inventory record, compare the identifiers and source evidence. Choose **Same asset (merge)** only for a supported pair. Already confident matches combine automatically. Additional unresolved records or relationship placeholders can temporarily increase the asset count.

Check owner, firmware/vendor context and `DS-IOT-*` configuration findings. These policy findings can have no assigned CVSS; use their explanation and contextual risk. A version inferred from a banner is not a complete firmware audit.

## 4. Import historical evidence and train the anomaly model

Add **Historical inventory** as a **Generic observations (JSON)** source. Import `baseline-history.json` from the generated folder through **Import file → Upload & import**.

This file contains dated observations over a past interval so DEEPSIGHT can record trends and change vectors. The import runs synchronously and can take several minutes. Keep the dialog open until it reports its result; an attempt or a spinning control is not a completed import.

After success:

1. Open **Overview** and inspect the trend, asset types and findings.
2. Open `app-server-01` and inspect **History**, **Services**, **Relationships** and **Risk**.
3. Open **Intelligence → models** and read the collected vector count.
4. As administrator, choose **Retrain anomaly model on platform data** and confirm the action.
5. Inspect the resulting active version and its training origin/metrics.

At least 15 collected vectors are needed for platform data to participate in retraining. Retraining on an empty database uses bootstrap data. Model output is a reason to review a change, not proof of an attack.

## 5. Import current inventory and scanner exports

Create each source below using **Add integration**, then upload the corresponding file from the generated `current/` directory. Source names identify operational data origins. Use the same integration again for the matching changed file later.

| Source name | Connector | Current file | Configuration |
|---|---|---|---|
| CMDB inventory | Host inventory (CSV) | `current/cmdb.csv` | Default file configuration. |
| Corporate network scan | Nmap scan (XML) | `current/network-scan.xml` | Default file configuration. |
| VMware inventory | Generic observations (JSON) | `current/vcenter.json` | Default file configuration. |
| AWS inventory | AWS EC2 inventory (JSON) | `current/aws.json` | Default file configuration. |
| Azure inventory | Azure VM inventory (JSON) | `current/azure.json` | Default file configuration. |
| OCI inventory | Oracle Cloud instances (JSON) | `current/oci.json` | Default file configuration. |
| Kubernetes inventory | Kubernetes nodes/pods (JSON) | `current/kubernetes.json` | `{"cluster_name":"prod-k8s"}` |
| Application inventory | Generic observations (JSON) | `current/applications.json` | Default file configuration. |
| Device management inventory | Generic observations (JSON) | `current/devices.json` | Default file configuration. |
| Vulnerability scanner | Vulnerability scan results (CSV/JSON) | `current/vulnerabilities.csv` | Default file configuration. |
| Perimeter inventory | Generic observations (JSON) | `current/perimeter.json` | Default file configuration. |

Check the generated `manifest.json` for file-to-connector mappings. Generic JSON, cloud JSON and scanner JSON structures differ despite sharing an extension. Select the matching connector.

Inspect a successful run for each source, then visit:

- **Overview:** asset types, exposure, findings and top contextual risks.
- **Assets:** services, software, identifiers and source observations.
- **Infrastructure:** connected graph nodes, relationship basis and recent changes.
- **Intelligence → catalog:** CVEs, published scores and historical KEV information.
- **Intelligence → identity:** any proposed uncertain match awaiting review.

## 6. Collect an HTTP source and prepare notifications

The launcher prints an HTTP base URL reachable from the application server. Do not replace it with `localhost`; HTTP destinations reject loopback and metadata addresses.

Add **Asset API** as an **HTTP API collector (JSON)** source. Set its configuration to the printed inventory URL with the generic mapper:

```json
{"url":"<printed base URL>/inventory","mapper":"generic_json","timeout":5}
```

Replace the placeholder with the actual URL. Save the integration, run **Test**, then **Collect**. Inspect its completed run and corresponding observations. Set a positive collection schedule if you want to show a later automatic run; leave worker and scheduler enabled.

Before importing changed findings, add **Security alerts** as an **Outbound finding webhook** integration with:

```json
{"url":"<printed base URL>/webhook"}
```

Keep secrets empty for this isolated receiver. **Test** checks the URL; it sends no event. New eligible critical or KEV findings queue notifications. Repeated evidence is deduplicated. The receiver must exist before the new eligible evidence is ingested.

Delivery status is available at `/api/webhooks/deliveries`; jobs are at `/api/jobs`. Use `/api/docs` with your signed-in Bearer token for these advanced API views. The receiver's `/receipts` endpoint lets you inspect accepted payloads on the private lab address.

## 7. Assign and triage work

Open **Work queue**, read “Why this needs attention,” and choose a high-priority finding.

1. Review the finding's published or policy description, source evidence, freshness and contextual factors.
2. Enter an owner such as **Payments team**, a due date and remediation guidance.
3. Set `in_progress` and choose **Save workflow**.
4. Return to the queue, filter by owner and save the filter as **Payments remediation**.
5. Select two open findings and use **Bulk triage** to apply an owner and state. Reopen a finding to verify the saved workflow.
6. On a suitable open finding, exercise `accepted_risk` or `false_positive` with its own reason, approver and future expiry. Save and inspect the recorded exception.

An exception records a decision; it is not a verified fix. A ticket URL records a reference and does not create a ticket or send a message. Choose **What if this finding is fixed?** on an open finding to inspect the calculated risk change. A zero reduction can be valid when another finding dominates the asset score.

## 8. Import changed evidence and review anomalies

For every source in the current-file table, use **Import file** again and upload the matching filename from `drift/`. Do not create another integration for its changed snapshot.

The changed snapshots introduce service/exposure/configuration changes such as exposed AJP on `app-server-01`, SMBv1 and IoT management drift. Refresh **Overview**, **Infrastructure** and **Intelligence → anomalies** after successful imports.

On `app-server-01`, compare **History**, **Services** and **Risk** with prior observations. Look for a model alert with its score, threshold and contributors. Use **True positive**, **False positive** or **Reviewed** to record an appropriate review outcome. A legitimate but unusual change can be a true-positive anomaly; the decision does not establish malicious activity.

Wait for the worker to dispatch eligible alerts, then inspect `/api/webhooks/deliveries` and the private receiver. If none are delivered, check receiver reachability, integration enabled state, eligible new findings and job/error output. A failed or merely queued attempt is not a delivered alert.

## 9. Review identities and dependencies

Open **Intelligence → identity**. Compare the proposed observation/candidate pair and confidence with source evidence. Choose **Same asset (merge)** for a supported pair, then **Revert decision** to practice correcting it. Choose **Separate** for an unsupported match.

In **Infrastructure**, select `ci-server-01` or another connected asset. Inspect related assets, edge labels and inferred-link controls. On an asset's Overview tab, inspect **Impact if compromised**. These panels describe recorded dependencies, not a proven attack path.

## 10. Investigate and ask the assistant

From `app-server-01` or one of its findings, choose **Start investigation**. Add a note such as:

> Reviewed network and scanner observations. A new service exposure requires remediation and a follow-up assessment.

Choose **Ask assistant** from the sidebar. Try:

1. “Why has the risk of app-server-01 increased?”
2. “What is connected to ci-server-01?”
3. “What changed in the last 24 hours?”

Follow the answer's references to stored records. The built-in evidence mode works without an external key. The assistant cannot patch, scan or close findings on your behalf.

Return to the investigation, select an outcome, write a conclusion and choose **Validate & close**. Confirm the timeline, attribution and closed status. Closing a case does not verify its underlying vulnerabilities; the next step does that separately.

## 11. Import a fresh assessment and verify a finding

The prepared clean assessment targets `CVE-2021-44228` on `orders-worker-aws-02`. Refresh its timestamp **after** the latest changed finding evidence was imported:

```bash
python3 scripts/prepare_imports.py --output data/deepsight-lab/imports --verification-only
```

Use the actual folder printed for your deployment. This refreshes the assessment file only and makes no database decision.

1. Add **Verification scan** as a **Generic observations (JSON)** integration.
2. Import the regenerated `clean-assessment.json` through **Import file → Upload & import**.
3. Open `orders-worker-aws-02` in **Assets → Observations**.
4. Open the newest processed record from **Verification scan**. Check its timestamp, complete assessment scope and empty findings list. Note its observation ID.
5. Open the target Log4j finding and optionally save `pending_verification`.
6. Enter the observation ID in **Verification observation ID** and choose **Verify and close**.
7. Confirm resolved status and stored before/after verification evidence.

The file rehearses a scoped assessment; it does not patch a live device. A missing CVE row in a CSV or a closed TCP port cannot establish a complete vulnerability assessment. Verification rejects old evidence, the wrong asset, missing scope, or results that still report the finding.

## 12. Search, export and inspect administration

Use **Global search** for `app-server-01`, a finding code and the investigation title. Follow the matching detail links.

On **Reports**, export each category as **HTML**, **CSV** and **JSON**. The categories cover infrastructure inventory, identity reconciliation, vulnerabilities, contextual risk, changes, anomalies, posture and investigations. Inspect their rows, sources, scope and limitations. The investigation report gains content only after a case is created.

On **Administration → users**, create a readonly or manager account with a password of at least 12 characters. Sign out, sign in as that account and verify appropriate read/review permissions. Return to the administrator for collections and final checks.

On **Administration → audit**, inspect records attributed to the acting account. On **system**, inspect API/database and scheduler status; `/api/health` provides the worker readiness check. A **Lifecycle sweep** can update old unseen assets and does not scan them.

## 13. Feature completion checklist

| Feature | Normal trigger | Evidence to show |
|---|---|---|
| Empty first start | Start a separate new environment. | No collected assets, findings, integrations or investigations. |
| Live discovery | Add TCP source → Test → Collect. | Four reachable devices, service evidence and a successful run. |
| Import and correlation | Add inventory source → Import file. | Combined profiles, source observations and identity decisions where needed. |
| Vendor/cloud/container/scanner formats | Upload each matching `current/` export. | Source-specific observations and successful run history. |
| IoT intelligence | Live collection plus device inventory metadata. | Configuration findings and contextual factors. |
| CVE/KEV/exposure/risk | Scanner/current evidence, then changed exports. | CVSS versus contextual risk and recorded evidence basis. |
| Trends and change history | Historical observations followed by current/changed snapshots. | Dated trends, service/configuration changes and score history. |
| Graph and impact | Relationship/Kubernetes imports. | Connected nodes, edge confidence/basis and impact panels. |
| Anomaly model and review | Baseline → retrain → changed import → review. | Threshold, contributors and feedback status. |
| Identity and correction | Review probable pair → merge/separate/revert. | Recorded evidence and reversible decision. |
| Queue and filters | Save workflow → filter/save → bulk triage. | Prioritization reasons, saved query and changed ownership/state. |
| Exceptions | Accepted risk/false positive with reason, approver and future expiry. | Recorded exception without a false claim of verified remediation. |
| What-if | Open finding → What if this finding is fixed? | Calculated score change and limitation. |
| Assessment freshness | Import recent complete scoped assessment. | Source, timestamp and assessed finding codes. |
| Verified closure | Import clean record → use its observation ID in Verify and close. | Resolved finding and verification evidence. |
| Investigation | Start case → note → conclusion/outcome → validate. | Timeline, attribution and closed case. |
| Assistant | Ask evidence-based questions after imports. | Grounded response and references. |
| Search | Existing name, CVE or case title. | Matching records and working links. |
| Reports | Export after evidence and a case exist. | All eight categories in three formats. |
| Users/roles/audit | Create account, sign in and perform permitted actions. | Appropriate controls and attributed audit records. |
| HTTP/schedules/jobs | Add HTTP source → Test → Collect/schedule. | Successful observations and completed work. |
| Notifications | Add receiver integration before eligible new findings. | Delivered status and receiver receipts. |

## Additional feature prerequisites

NVD and EPSS imports, custom relationship edits, jobs, metrics and notification delivery records are API functions rather than extra presentation screens. The [User manual](USER_MANUAL.html) describes their routes and required evidence. Optional package exports are in `package-scans/`, and local intelligence fixtures are in `intelligence/`; check `manifest.json` for their connector/API mapping.

Live **Sync CISA KEV** requires internet access and the remote service. Optional LLM assistant mode requires a valid `ANTHROPIC_API_KEY` and a reachable service; the evidence mode remains usable offline. Backup, restore and retention should be exercised in a separate disposable environment rather than by deleting active evidence merely to populate a screen.

No finding, anomaly or optional field should be invented to fill a blank panel. An unassigned CVSS on a configuration policy or missing firmware data has a specific source explanation. When a required feature is empty, use the checklist's trigger and confirm its run/evidence succeeded.

## Finish or repeat

Stop the environment with the command printed by `scripts/start_lab.py`. Stopping preserves its data. Use a fresh named deployment and free port for a new empty run. The operational interface remains unchanged; repeat the same ordinary scan, import, analyst and report actions.

For an optional automated rehearsal of those same APIs:

```bash
python3 scripts/run_scenario.py --url http://localhost:8001 --imports data/deepsight-lab/imports
```

Use the printed URL and import directory. This is an explicit test action that performs collections/imports and analyst decisions; the default launcher does not do it. Its evidence output can be retained as a validation record.
