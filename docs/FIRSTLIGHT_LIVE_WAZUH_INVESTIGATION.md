# FIRSTLIGHT live Wazuh investigation

This path queries a **configured real Wazuh Indexer** and investigates the returned alerts. It is separate from `scripts/firstlight_track1_demo.py`, whose inputs are fictional training events.

## Safety contract

- Read-only query against the configured Wazuh Indexer; no target URL is accepted from CLI arguments.
- TLS is required by default. The connector rejects redirects and bounds the query, response size, page size, timeout, index pattern, and allowed agent IDs.
- Set credentials only in the trusted server environment or secret manager. Never put them in the command line, browser, source control, or chat.
- At least one explicit Wazuh agent ID must be configured in `FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS`.
- The command seals each returned source event, verifies its integrity, runs deterministic investigation rules, and writes a JSON report with Wazuh document identity and source-record SHA-256.
- This standalone CLI **does not** isolate endpoints, revoke sessions, block network traffic, or trigger a response action. Its report's response section remains proposal-only. The separate authenticated FIRSTLIGHT workspace has a guarded live-response panel and durable approval API; see [live response integrations](FIRSTLIGHT_LIVE_RESPONSE.md).

## Configure

Set these server-side environment variables in a restricted environment:

- `FIRSTLIGHT_WAZUH_INDEXER_URL` — HTTPS base URL for your Wazuh Indexer, including port if required.
- `FIRSTLIGHT_WAZUH_INDEXER_USERNAME` — dedicated read-only Indexer account.
- `FIRSTLIGHT_WAZUH_INDEXER_PASSWORD` — password for that account.
- `FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS` — comma-separated IDs explicitly authorized for this investigation (required).
- `FIRSTLIGHT_WAZUH_INDEX_PATTERN` — optional; defaults to `wazuh-alerts-*`.
- `FIRSTLIGHT_WAZUH_TIMEOUT_SECONDS` — optional; defaults to 8, maximum 30.

Do not set `FIRSTLIGHT_WAZUH_ALLOW_HTTP=true` outside an isolated disposable lab. Prefer a trusted TLS certificate rather than disabling verification.

## Run against actual telemetry

From the repository root, after installing the project's Python dependencies:

```bash
python scripts/firstlight_live_wazuh_investigation.py \
  --since 2026-10-20T00:00:00Z \
  --until 2026-10-20T23:59:59Z \
  --limit 100 \
  --output artifacts/firstlight-live-wazuh-report.json
```

Choose a time window appropriate to the lab. The example date is illustrative; it is not a claim that the Indexer has data for that date. The command exits non-zero on missing/invalid configuration, provider errors, malformed records, an empty result window, or failed evidence validation. No synthetic fallback is used.

For a report to stdout, omit `--output`. Treat reports as security-sensitive because they can contain internal host and alert details; store them only in an access-controlled location.

## What the report proves—and does not prove

The report records the source provider, query window, Wazuh index/document IDs, source timestamps, source-record hashes, and FIRSTLIGHT evidence-integrity results. It can demonstrate a real ingestion-to-investigation path **only when run successfully against a real configured Indexer**. Unit tests use mocked provider responses and verify the workflow contract; they do not establish live connectivity or prove that a production tenant has been tested.

Wazuh rule levels and FIRSTLIGHT heuristic matches are triage signals, not calibrated probabilities or independent proof of compromise. Correlation is not causation. Verify the finding with endpoint, identity, and network telemetry before containment.

## Remaining gates for a real end-to-end SOC response

1. Run this CLI in an authorized Wazuh lab and preserve redacted output, exact commit SHA and report hash.
2. For durable ingestion, run the separate Wazuh worker and verify source-object persistence, checkpoint advancement, duplicate handling and restart recovery against the same self-hosted case.
3. Test the guarded workspace response lifecycle against an authorized disposable Microsoft tenant/device/account; verify provider-side completion and recovery/unisolation.
4. Run tenant-isolation and role checks against the self-hosted PostgreSQL deployment with separate test workspaces and users.
5. Complete backup/restore drills for the database, evidence directory and response ledger.
6. Run clean-install tests and verify the exact candidate SHA in the deployment environment before claiming production readiness.

See also [FIRSTLIGHT live response integrations](FIRSTLIGHT_LIVE_RESPONSE.md), [Wazuh integration](FIRSTLIGHT_WAZUH_INTEGRATION.md), and [implementation status](FIRSTLIGHT_IMPLEMENTATION_STATUS.md).
