# FIRSTLIGHT Wazuh integration (initial connector)

This change adds a bounded, read-only connector for alerts already indexed by Wazuh.
It is the first integration milestone, not a claim that the full production ingestion
and persistent case lifecycle are complete.

## Data path

1. Wazuh agents collect configured endpoint events and the Wazuh manager applies its rules.
2. The Wazuh Indexer stores alert documents.
3. FIRSTLIGHT's server-side Python connector queries the Indexer using a dedicated read-only account.
4. Alerts are normalized to stable event IDs and include source/index/document provenance plus a SHA-256 digest of the indexed source record.
5. The authenticated FIRSTLIGHT endpoint returns one bounded page for integration testing.

The API preview endpoint itself **does not persist events or maintain a checkpoint**. A separate persistent worker now writes normalized alerts into an existing authorized SATARK case and records a durable cursor, provided the checkpoint migration is applied and the worker is configured. The migration has now been applied and verified on the approved nihdhoom project, which is shared with Nirdhoom and Saathi; only SATARK tables, indexes and grants were changed. The worker and live integration remain unverified against a real Wazuh server.

## Server-side configuration

Set these only in the private runtime that hosts firstlight_api.py (never in a NEXT_PUBLIC_* variable):

- FIRSTLIGHT_WAZUH_INDEXER_URL: HTTPS URL of the Wazuh Indexer/OpenSearch REST API, reachable from the API runtime.
- FIRSTLIGHT_WAZUH_INDEXER_USERNAME: dedicated read-only Indexer username.
- FIRSTLIGHT_WAZUH_INDEXER_PASSWORD: corresponding secret.
- FIRSTLIGHT_WAZUH_SYNC_TOKEN: independently generated random bearer token of at least 32 characters for the FIRSTLIGHT endpoint.
- FIRSTLIGHT_WAZUH_INDEX_PATTERN: optional index pattern, default wazuh-alerts-*.
- FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS: required comma-separated allowlist of 1–100 authorized Wazuh agent IDs. Both the preview API and worker filter on this list; do not leave it empty or use a broad all-tenant agent list in a multi-tenant deployment.
- FIRSTLIGHT_WAZUH_TIMEOUT_SECONDS: optional timeout from 1 to 30 seconds, default 8.
- FIRSTLIGHT_WAZUH_ALLOW_HTTP: optional lab-only opt-in to HTTP. Prefer HTTPS with certificate verification; never enable this for a public network.

Use a least-privilege Indexer role restricted to read access on the required Wazuh alert indices. Do not reuse an administrator account. Keep the Indexer private and do not expose it directly to the browser or public internet. The connector uses the standard Python TLS trust store; install the correct CA certificate in the runtime if the lab uses a private CA instead of disabling certificate verification.

## Endpoint

GET /api/v1/integrations/wazuh/alerts?limit=100&since=2026-10-20T00:00:00Z

Required header:

Authorization: Bearer <FIRSTLIGHT_WAZUH_SYNC_TOKEN>

- limit is bounded to 1–500.
- since is optional and must be an ISO-8601 timestamp with an explicit timezone.
- Returns normalized event records and provenance.
- Does not persist results; treat this endpoint as a read-only connector preview.
- Requires a strong token even if FIRSTLIGHT_API_TOKEN is unset.

## Local validation

Install the dependencies from firstlight-api-requirements.txt and run:

```sh
python -m pip install -r firstlight-api-requirements.txt pytest
pytest -q tests/test_firstlight_api.py tests/test_firstlight_engine.py tests/test_firstlight_wazuh.py
```

The connector tests use mocked HTTP responses; they do not require a live Wazuh server and do not prove a real deployment is reachable.

## Before calling this production-ready

- [ ] Provision an isolated Wazuh lab and enroll only an authorized test endpoint.
- [ ] Verify the exact Indexer endpoint, TLS trust, role permissions and credentials.
- [ ] Run the API endpoint against real, benign test alerts.
- [ ] Validate durable checkpointing, duplicate-safe storage and retry/recovery behavior with a controlled live Wazuh event.
- [ ] Verify raw source artifact persistence and canonical event records end-to-end with verified tenant-scoped authorization.
- [ ] Deploy and verify the worker on a private persistent runtime; do not rely on a Vercel request to poll continuously.
- [ ] Add end-to-end tests for source alert → connector → persistent case → investigation → report.
- [ ] Verify production deployment SHA and run an authorized smoke test.
- [ ] Keep live response disabled until the durable approval and response adapter have been separately audited and tested.


## Persistent worker (new, not yet live-validated)

The worker is intended to run on a persistent private host, separate from Vercel requests. It pages through a bounded time window, saves events into the existing satark_evidence table, relies on the database's evidence-insert audit trigger, and advances a cursor only after every page is saved. A five-minute overlap (configurable) helps catch delayed alerts; database uniqueness makes replays duplicate-safe. A window exceeding the Indexer's 10,000-result pagination cap fails without advancing the cursor.

Before enabling it:

1. The approved target is Supabase project `nihdhoom` (project ref `igqgtlmnwssjaoxkkzbm`), a shared project. The migration was applied only after inspecting the SATARK schema, migration history, foreign keys, existing Wazuh evidence and index-name conflicts. No Nirdhoom or Saathi tables were altered.
2. The migration `supabase/migrations/20261020023851_satark_wazuh_ingestion_checkpoints.sql` is applied and verified. The checkpoint table has forced RLS, no policies, and no `anon` or `authenticated` privileges; it is intentionally service-role-only. Supabase's RLS-without-policy lint finding is expected for this private table.
3. Create or select an existing case in the target tenant, and verify the configured actor is an owner, responder or analyst in that tenant.
4. Supply the following private environment variables to the persistent worker:
   - SUPABASE_URL
   - SUPABASE_SERVICE_ROLE_KEY (server-side only; never in Vercel browser/client config)
   - FIRSTLIGHT_WAZUH_TENANT_ID
   - FIRSTLIGHT_WAZUH_CASE_ID
   - FIRSTLIGHT_WAZUH_ACTOR_ID
   - FIRSTLIGHT_WAZUH_INITIAL_SINCE (required on first run; explicit ISO-8601 timestamp with timezone)
   - The Wazuh Indexer settings listed above, including FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS
   - Optional FIRSTLIGHT_WAZUH_PAGE_SIZE (1–500, default 100), FIRSTLIGHT_WAZUH_OVERLAP_SECONDS (0–3600, default 300), FIRSTLIGHT_WAZUH_POLL_SECONDS (15–3600, default 60)
5. Run one controlled poll first with python firstlight_wazuh_worker.py --once. Inspect the case evidence and server-generated audit event before enabling recurring polling.
6. Run the worker continuously under a service supervisor/container on the private host. Keep the Indexer and Supabase service-role credentials out of logs and source control.

The worker explicitly verifies the target case/tenant and the actor's membership before writing. The connector also filters every index query to FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS, and its durable cursor is namespaced by the allowlist hash so changing the scope does not reuse another scope's checkpoint. Its Supabase service-role credential bypasses RLS, so the worker must remain a trusted, private component. The workspace UI also offers a bounded alert preview, but that preview intentionally does not include or preserve the full indexed source snapshot; use the persistent worker when source-object preservation is required. Never use this pattern in browser code or a public endpoint.

## What remains unverified

- No live Wazuh host, Indexer credentials, Supabase credentials or authorized test endpoint were available to this change.
- The SQL migration has been applied to the approved shared `nihdhoom` project after schema inspection. The checkpoint table and duplicate-protection index are verified; tenant isolation and database audit behavior still need a controlled live test using authorized test identities.
- The worker's mocked tests do not prove real Wazuh field mappings, indexer role permissions, TLS trust, Supabase schema compatibility or production availability.
- The Next.js UI does not yet provide a dedicated Wazuh source setup/status panel.
- The integration is not production-ready until CI passes, a benign live alert is ingested, and recovery/authorization tests pass.


## Next.js workspace integration

The FIRSTLIGHT workspace now includes a **Load real Wazuh alerts** action. It calls a Next.js server route that authenticates the user's Supabase session, then proxies a bounded alert page to the private FIRSTLIGHT API. The browser never receives the Wazuh Indexer credentials or the connector sync token. Loaded alerts are labeled as Wazuh source records and retain source metadata/digests; the analyst must explicitly save them to a persistent case.

For this proxy, set FIRSTLIGHT_API_URL and FIRSTLIGHT_WAZUH_SYNC_TOKEN in the server-side Next.js/Vercel environment, and configure the same sync token plus the Wazuh Indexer settings in the private FIRSTLIGHT API runtime. The Wazuh Indexer itself must remain private. If the Next.js/Vercel runtime cannot reach the private FIRSTLIGHT API, use the authenticated UI from the deployment/network that can reach the API; do not expose the Indexer to solve a network-routing problem.

For local Docker Compose, add the same private values to an untracked local .env file and start the worker only after the migration and target IDs have been verified:

```sh
docker compose -f docker-compose.local.yml build firstlight-api firstlight-wazuh-worker
docker compose -f docker-compose.local.yml run --rm firstlight-wazuh-worker python firstlight_wazuh_worker.py --once
docker compose -f docker-compose.local.yml --profile wazuh-worker up -d firstlight-wazuh-worker
```

The worker is optional and will not start in the default profile. Never commit the .env file or service-role credentials.
