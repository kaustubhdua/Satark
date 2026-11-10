# FIRSTLIGHT Wazuh investigation API

## Read-only preview

The FastAPI service exposes an authenticated, bounded Wazuh query:

- `GET /api/v1/integrations/wazuh/alerts?tenant_id=<uuid>&limit=100&since=<ISO-8601>`
- `POST /api/v1/integrations/wazuh/investigate?tenant_id=<uuid>&limit=100&since=<ISO-8601>`

Send `Authorization: Bearer <FIRSTLIGHT_WAZUH_SYNC_TOKEN>`. The page size is capped, and the configured tenant must exactly match `FIRSTLIGHT_WAZUH_TENANT_ID`. The connector queries only configured agent IDs over verified TLS and rejects redirects.

These endpoints are **read-only previews**. They do not persist a case, full source snapshot, or durable checkpoint. The workspace UI labels the result as a preview; an analyst must explicitly save the selected events to a persistent case. Use the persistent worker when full source-object preservation and scheduled ingestion are required.

## Required private runtime configuration

- `FIRSTLIGHT_WAZUH_INDEXER_URL` — HTTPS Wazuh Indexer base URL.
- `FIRSTLIGHT_WAZUH_INDEXER_USERNAME` / `FIRSTLIGHT_WAZUH_INDEXER_PASSWORD` — dedicated read-only account.
- `FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS` — explicit comma-separated agent allowlist.
- `FIRSTLIGHT_WAZUH_SYNC_TOKEN` — random bearer token of at least 32 characters.
- `FIRSTLIGHT_WAZUH_TENANT_ID` — configured SATARK workspace UUID.
- Optional index pattern, timeout and page-size settings as described in [Wazuh integration](FIRSTLIGHT_WAZUH_INTEGRATION.md).

Keep all values in the private API/worker environment. Never put Indexer credentials or sync tokens in browser code, source control, or logs.

## Persistent Wazuh worker

The self-hosted worker writes to the same SATARK database and private evidence directory as the API. It does not require Supabase or a service-role key. Required SATARK settings:

- `SATARK_DATABASE_URL` (PostgreSQL for multi-worker production; SQLite for local development).
- `SATARK_EVIDENCE_DIR` (persistent private filesystem path shared by API and worker).
- `FIRSTLIGHT_WAZUH_TENANT_ID`, `FIRSTLIGHT_WAZUH_CASE_ID`, `FIRSTLIGHT_WAZUH_ACTOR_ID`.
- `FIRSTLIGHT_WAZUH_INITIAL_SINCE` on first run if no checkpoint exists.
- The Wazuh Indexer URL, read-only credentials and allowed agent IDs.

For local Compose, use the opt-in `wazuh` profile only after verifying the workspace, case, actor membership and test alert:

```bash
docker compose -f docker-compose.local.yml build firstlight-api firstlight-wazuh-worker
docker compose -f docker-compose.local.yml --profile wazuh run --rm firstlight-wazuh-worker python firstlight_wazuh_worker.py --once
docker compose -f docker-compose.local.yml --profile wazuh up -d firstlight-wazuh-worker
```

The worker uses a bounded overlap window, duplicate-safe source identity, local source-object hashes and a durable checkpoint. It rechecks tenant/case membership around writes. The shared `satark_data` volume must be mounted by both API and worker.

## Acceptance probes

`scripts/accept_firstlight_wazuh_live.py` checks a real read-only API query. `scripts/accept_firstlight_worker_live.py` writes evidence/checkpoint state and must only be run against an explicitly authorized test case. It requires the three write opt-ins documented in the script. Never run a write probe against a production incident or a shared unrelated environment.

Mocked tests do not prove live Wazuh field mapping, TLS trust, Indexer permissions, alert availability, worker recovery or deployment networking. Record the real test endpoint, agent allowlist, exact commit, redacted output and source digest for acceptance.

Official references:
- https://documentation.wazuh.com/current/user-manual/indexer-api/index.html
- https://documentation.wazuh.com/current/user-manual/api/rbac/index.html
