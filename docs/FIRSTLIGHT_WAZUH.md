# FIRSTLIGHT live Wazuh investigation connector

## Purpose and boundaries

FIRSTLIGHT can query alerts from a configured Wazuh Indexer/OpenSearch REST endpoint and run the same deterministic investigation engine over the returned records. The connector is read-only: it does not modify Wazuh, persist a SATARK case, isolate endpoints, block traffic, or revoke sessions. This API path is an integration capability, not proof that a production Wazuh environment has been connected or validated.

Wazuh Indexer exposes a REST API for querying indexed data. Configure a dedicated account with read-only access limited to the alert indices required by the project. Follow the official Wazuh Indexer API documentation and RBAC guidance:
- https://documentation.wazuh.com/current/user-manual/indexer-api/index.html
- https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html
- https://documentation.wazuh.com/current/user-manual/api/rbac/index.html

## Server-side environment

Set these variables in the API service's secret manager/environment, never in browser code or committed files:

| Variable | Required value |
| --- | --- |
| `FIRSTLIGHT_WAZUH_INDEXER_URL` | HTTPS origin for the Wazuh Indexer, optionally with a fixed base path; no credentials, query or fragment |
| `FIRSTLIGHT_WAZUH_INDEXER_USERNAME` | Dedicated read-only indexer username |
| `FIRSTLIGHT_WAZUH_INDEXER_PASSWORD` | Secret for that read-only account |
| `FIRSTLIGHT_WAZUH_INDEX_PATTERN` | Optional index pattern; defaults to `wazuh-alerts-*` |
| `FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS` | Required comma-separated allowlist of 1–100 authorized Wazuh agent IDs |
| `FIRSTLIGHT_WAZUH_SYNC_TOKEN` | Random bearer token of at least 32 characters for the integration API |
| `FIRSTLIGHT_WAZUH_TENANT_ID` | UUID of the one tenant configured to own this source |
| `FIRSTLIGHT_WAZUH_TIMEOUT_SECONDS` | Optional timeout from 1–30 seconds; defaults to 8 |
| `FIRSTLIGHT_WAZUH_ALLOW_HTTP` | Optional explicit opt-in for isolated local labs only; HTTPS is required by default |

Do not use an administrator/indexer superuser credential. Do not set `FIRSTLIGHT_WAZUH_ALLOW_HTTP=true` in a shared or production environment. Install and trust the correct TLS certificate rather than disabling certificate validation.

## Read-only fetch endpoint

`GET /api/v1/integrations/wazuh/alerts?tenant_id=<configured-tenant-uuid>&limit=100`

Send `Authorization: Bearer <FIRSTLIGHT_WAZUH_SYNC_TOKEN>`. Optional `since` is an ISO-8601 timestamp. The response reports `persisted: false` and includes source provenance fields. It returns one bounded page and does not establish a durable ingestion checkpoint.

## Live fetch-and-investigate endpoint

`POST /api/v1/integrations/wazuh/investigate?tenant_id=<configured-tenant-uuid>&limit=100`

Send the same bearer token. Optional `since` is an ISO-8601 timestamp. The endpoint fetches actual records from the configured Indexer, creates a stable case identifier for the returned alert IDs, binds each normalized record to a SHA-256 digest, and runs the canonical deterministic investigation engine. Optional local Ollama analysis remains advisory.

A successful response has `mode: "live_read_only_investigation"`, includes the fetched evidence and findings, and explicitly states `persisted: false`. An empty query returns zero events and no investigation; it must not be interpreted as a successful detection or a clean security verdict. Authentication, tenant binding, configured agent allowlisting, bounded query size, TLS defaults, timeouts, and no-redirect behavior are enforced by the connector/API.

## Runbook

1. Deploy the API into a network segment that can reach the Indexer over verified TLS.
2. Create a dedicated read-only Indexer role/account, restricted to the relevant alert indices, and an explicit agent ID allowlist.
3. Store all credentials/tokens in the API host's secret manager.
4. From an authorized test client, call the alerts endpoint with the configured tenant UUID and a small limit. Confirm the response includes genuine source document IDs, index names, timestamps, rule IDs and source-record digests.
5. Call the investigate endpoint for the same tenant and time range. Verify that its evidence IDs correspond to the source events and that findings cite those IDs.
6. Record the Wazuh document IDs, request time, API revision, result counts and sanitized workflow logs as the acceptance evidence. Do not place secrets or raw sensitive logs in the repository.
7. Test bad token, wrong tenant, invalid agent allowlist, unreachable Indexer, TLS failure, timeout, empty results and malformed source records.
8. Keep the system in read-only mode until a separate, independently reviewed response-adapter workflow has been tested in a disposable environment with explicit target-bound approval and provider-side verification.

## Integrity and accuracy limitations

The Indexer source digest is computed over the received source JSON; it is useful for identifying whether the normalized record later changes, but it is not a digital signature from Wazuh. The event digest generated for the investigation is computed after retrieval and does not prove the upstream event's truthfulness or independent immutability. Rule severity and FIRSTLIGHT heuristic findings are leads, not verdicts. An alert's absence in one page is not proof that the environment is clean.

The integration API does not currently persist investigation cases, maintain a durable cursor, schedule polling, or execute response actions. Those require separately tested storage, checkpoint/replay behavior, tenant authorization, audit retention, and provider-side integration. Do not describe these as completed.
