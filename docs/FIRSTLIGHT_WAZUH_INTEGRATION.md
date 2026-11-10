# FIRSTLIGHT Wazuh integration (self-hosted)

## Architecture

FIRSTLIGHT has two Wazuh paths:

1. **Read-only preview:** the authenticated Next.js workspace proxies one bounded page from the private FIRSTLIGHT API. It does not save full source objects or checkpoints.
2. **Persistent worker:** a private Python worker polls the configured Indexer, normalizes alerts, checks tenant/case/actor authorization, stores source snapshots under `SATARK_EVIDENCE_DIR`, inserts evidence metadata into the SATARK database, and advances a durable checkpoint only after the page is persisted.

Both paths are optional. The default SATARK File Guard remains offline and does not depend on Wazuh.

## Required configuration

Set these only in the API/worker secret environment:

- `FIRSTLIGHT_WAZUH_INDEXER_URL`
- `FIRSTLIGHT_WAZUH_INDEXER_USERNAME`
- `FIRSTLIGHT_WAZUH_INDEXER_PASSWORD`
- `FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS` (required allowlist)
- `FIRSTLIGHT_WAZUH_TENANT_ID`
- `FIRSTLIGHT_WAZUH_SYNC_TOKEN` (at least 32 random characters; API preview/proxy only)
- `FIRSTLIGHT_WAZUH_CASE_ID` and `FIRSTLIGHT_WAZUH_ACTOR_ID` (persistent worker)
- `FIRSTLIGHT_WAZUH_INITIAL_SINCE` (first worker run when no checkpoint exists)

The worker uses the self-hosted SATARK database configuration:

- `SATARK_DATABASE_URL` — PostgreSQL is recommended for concurrent production workers; SQLite is suitable for local single-instance use.
- `SATARK_EVIDENCE_DIR` — persistent private directory shared with the API container.

Optional controls include `FIRSTLIGHT_WAZUH_INDEX_PATTERN`, `FIRSTLIGHT_WAZUH_TIMEOUT_SECONDS`, `FIRSTLIGHT_WAZUH_PAGE_SIZE`, `FIRSTLIGHT_WAZUH_OVERLAP_SECONDS` and `FIRSTLIGHT_WAZUH_POLL_SECONDS`.

Use HTTPS with certificate verification. Do not set the lab-only HTTP override outside a disposable isolated environment. The Indexer account should be read-only and scoped to the required alert indices/agents.

## Local Compose

Add values to an untracked root `.env` file. The Compose stack supplies the API URL internally and mounts the same persistent data volume for the API and worker.

Run one controlled poll:

```bash
docker compose -f docker-compose.local.yml build firstlight-api firstlight-wazuh-worker
docker compose -f docker-compose.local.yml --profile wazuh run --rm firstlight-wazuh-worker python firstlight_wazuh_worker.py --once
```

Only after reviewing the resulting case evidence and checkpoint should recurring polling be enabled:

```bash
docker compose -f docker-compose.local.yml --profile wazuh up -d firstlight-wazuh-worker
```

Do not expose the Wazuh Indexer publicly to make a remote web runtime reach it. Run the API/worker in the network that can reach the Indexer or use an authenticated private network path.

## Integrity and recovery

- The worker uses a bounded query window and overlap to catch delayed alerts.
- It preserves the normalized source snapshot and its SHA-256 under the private evidence root.
- Duplicate source documents are idempotent.
- The checkpoint advances only after all records in the window are durably written; a failed poll does not advance it.
- A query window exceeding the Indexer pagination cap fails closed.
- The API and worker must share the same database and evidence directory. Back up both; a database-only backup is incomplete.

## What must still be validated in an authorized lab

- Real Indexer TLS trust and least-privilege role behavior.
- Real agent allowlist filtering and timestamp/field mapping.
- Successful poll → persisted source objects → evidence rows → checkpoint → restart recovery.
- Worker behavior on empty windows, delayed alerts, malformed records, duplicate pages, storage full and Indexer timeout.
- Tenant/case membership and case ownership with real test identities.
- UI preview behavior through the same-origin proxy.

Unit tests and mocked connectors do not establish live provider connectivity or production readiness.

## Self-hosted Wazuh lab

The supported lab baseline is Wazuh 4.14.10. The official Wazuh Docker deployment can run the Manager, Indexer and Dashboard on a private lab host. SATARK includes a pinned bootstrap helper:

```bash
bash scripts/bootstrap_wazuh_lab.sh "$HOME/wazuh-docker"
```

The helper checks Docker Compose and the Indexer kernel map-count prerequisite, clones the official Wazuh Docker repository at `v4.14.10`, and generates the upstream TLS certificates. Do not upgrade this integration to Wazuh 5.x: that release removes the 4.x `PUT /active-response` endpoint and uses a different event-driven response workflow. The live-response adapter verifies the Manager version is 4.14.x before sending any command. It deliberately does not start the stack or expose ports. Rotate all upstream default passwords before starting it. Keep the Manager API (55000), Indexer (9200), and Dashboard (443) on a private network; never publish the Manager API to the public internet.

Official upstream deployment guide: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html

## Guarded endpoint response

FIRSTLIGHT can submit two fixed Wazuh built-in Active Response commands through the Manager API:

- `firewall-drop` for a validated IPv4 address.
- `disable-account` for a validated local account name.

Configure `FIRSTLIGHT_WAZUH_MANAGER_API_URL`, `FIRSTLIGHT_WAZUH_MANAGER_USERNAME`, `FIRSTLIGHT_WAZUH_MANAGER_PASSWORD`, optional `FIRSTLIGHT_WAZUH_MANAGER_CA_BUNDLE`, and `FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS` in the private API environment. The response agent list is a separate explicit allowlist and must contain only disposable lab agent IDs. The disable-account action additionally requires FIRSTLIGHT_WAZUH_ACCOUNT_DISABLE_AGENT_IDS, a separate list of disposable Linux/macOS agents only; the executable is not available on Windows. The account must be restricted to the minimum Wazuh API permission required to call Active Response. TLS verification is mandatory for network endpoints.

Live response remains disabled unless `SATARK_ENABLE_LIVE_RESPONSE=true` is set in the trusted API runtime. The UI/API requires a requester, a distinct approver, a third executor, an exact confirmation phrase, and an independent verification attestation. Do not enable this in a production environment before lab verification and a reviewed reversal procedure.

Active Response API reference: https://documentation.wazuh.com/4.14/user-manual/api/reference.html
