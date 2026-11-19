# Operator exercise files

These exports describe a fictional organization and deliberately vulnerable lab devices.
They are supplied for a presentation rehearsal and are not observations of your production
infrastructure. Package imports are controlled scanner-export fixtures. The EPSS file preserves the
FIRST API measurement and date retrieved on 19 November 2026; see lab/epss-snapshot.json.
Refresh from FIRST when current intelligence is required. The clean assessment represents the planned
verification exercise, not an actual patch of a production resource.

Use the normal Integrations screens to scan and import. Select connectors using manifest.json.
Import baseline-history.json as Generic observations; retrain in Intelligence → Models, then
import current/ and drift/ files using the same named sources. Device inventory is mapped to
the addresses in scan-config.json. Refresh only clean-assessment.json after the latest finding
evidence: python3 scripts/prepare_imports.py --output <this folder> --verification-only.

The application contains no extra presentation dashboard or control page.
