# FIRSTLIGHT — Incident investigation and response workspace

FIRSTLIGHT is SATARK's incident-response workspace. It turns authorized telemetry and user-provided evidence into an explainable case timeline, integrity assessment, deterministic findings, investigation report, and human-reviewed response workflow.

## Working local/self-hosted workflow

1. Sign in to the SATARK self-hosted application and select a workspace.
2. Create or load a case. Workspace membership and role checks are enforced by the Python backend.
3. Add evidence by importing bounded JSON/CSV events, uploading a private original, or loading a bounded Wazuh alert preview. For persistent Wazuh ingestion, configure the private worker.
4. Verify evidence hashes and source metadata. Integrity mismatch evidence is quarantined from trusted finding references.
5. Run the deterministic Python investigation, review the event timeline, rule IDs, evidence references, severity rationale, uncertainty and evidence gaps.
6. Save evidence, findings and a reproducible report snapshot to the self-hosted database. Queue a durable investigation job when the case needs background processing.
7. Record analyst notes and case activity. The durable audit history is stored by the self-hosted backend; browser-only activity is not presented as the authoritative ledger.
8. If an authorized organization configures the optional Wazuh Manager API integration, request a case-bound response approval. A different operator approves it, a third operator executes it after exact target confirmation, and a fourth distinct operator records independent provider-console verification.

## Components

- **Python engine:** deterministic rules, evidence prioritization, timeline reconstruction, correlation, report generation and bounded agent orchestration.
- **FastAPI service:** authenticated SATARK persistence API, investigation API, Wazuh preview and guarded response API.
- **Self-hosted persistence:** SQLAlchemy with PostgreSQL for multi-user deployments or SQLite for local development; private evidence files remain under `SATARK_EVIDENCE_DIR`.
- **Workers:** durable investigation jobs and optional Wazuh polling/checkpoint worker.
- **Web workspace:** Next.js UI with same-origin server-side API proxy. Session cookies are HttpOnly; browser code does not receive database credentials.
- **Optional local model:** Ollama specialists can add advisory analysis in both synchronous and durable background investigations. Deterministic results remain available without a model, paid AI API or hosted model. To enable, set FIRSTLIGHT_MODEL_AGENTS_ENABLED=true, start the optional Ollama profile, and pull the configured local model. Agent results are advisory and never replace deterministic findings.

## Wazuh integration

The read-only API preview is an operator-triggered bounded query. It does not persist the full source event. The persistent Wazuh worker uses a configured read-only Indexer identity, an explicit agent allowlist, a selected tenant/case/actor, a durable ingestion checkpoint, and local evidence-object storage. It is opt-in and should run only on a private host that can reach the Indexer and SATARK database.

See [Wazuh integration](FIRSTLIGHT_WAZUH_INTEGRATION.md) and [Wazuh API acceptance](FIRSTLIGHT_WAZUH_API.md).

## Guarded live response

The browser now has a case-scoped response panel backed by the durable local response ledger. Supported actions are Wazuh Active Response: block one validated IPv4 address with firewall-drop or disable one validated local account with disable-account on one explicitly allowlisted agent. The feature is **disabled by default** and never triggered by AI. It requires private Wazuh Manager API credentials, explicit server feature enablement, fixed command allowlisting, four-eyes approval, a third executor, exact target confirmation, at-most-once submission, and separate independent verification.

A provider submission is not proof of completed containment. SATARK records an operator attestation after the operator verifies state in the provider console; it does not claim an automatic provider-side verification.

See [live response controls](FIRSTLIGHT_LIVE_RESPONSE.md) and [response executor design](FIRSTLIGHT_RESPONSE_EXECUTOR.md).

### Optional local model setup

```bash
# Set FIRSTLIGHT_MODEL_AGENTS_ENABLED=true and FIRSTLIGHT_OLLAMA_MODEL in .env
docker compose -f docker-compose.local.yml --profile ai up -d ollama
docker compose -f docker-compose.local.yml exec ollama ollama pull qwen2.5:3b
```

The API and durable investigation worker use the internal Ollama service URL. If Ollama is unavailable or the model call fails, the worker records an agent error and still completes deterministic analysis. No hosted model or API key is used.

## Safety and limits

- No sample incident is preloaded into the production FIRSTLIGHT workspace. Unit-test fixtures are isolated to tests and are never operational telemetry.
- Hashes establish byte consistency against a stored digest, not original source authenticity or truthfulness.
- Rule matches and optional model findings are triage leads, not proof of compromise or calibrated probabilities.
- No shell command, malware execution, network block, or automatic endpoint action is inferred from AI output.
- Wazuh Active Response affects the selected enrolled endpoint when enabled and correctly configured. Use only a disposable lab agent with a tested reversal/recovery path.
- Wazuh integrations require a real, authorized self-hosted environment; mock tests do not prove live connectivity.
- Audit hash chains are tamper-evident against ordinary application changes, not privileged-host administrators. Export/anchor them independently for stronger evidence.

## Local run

Install dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip install -r firstlight-api-requirements.txt
```

Run the web application and API using the repository's local Compose configuration, or run the API directly:

```bash
export FIRSTLIGHT_API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
mkdir -p "$PWD/data/evidence"
export SATARK_DATABASE_URL="sqlite:///$PWD/data/satark.db"
export SATARK_EVIDENCE_DIR="$PWD/data/evidence"
export FIRSTLIGHT_RESPONSE_DB="$PWD/data/firstlight-response.sqlite3"
export FIRSTLIGHT_API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
alembic upgrade head
uvicorn firstlight_api:app --host 127.0.0.1 --port 8788
```

For the Next.js app, configure server-only `SATARK_API_INTERNAL_URL` to the private API origin; the same-origin proxy forwards the user's HttpOnly session cookie. Configure `FIRSTLIGHT_API_TOKEN` only for token-protected investigation/Wazuh endpoints and `FIRSTLIGHT_WAZUH_SYNC_TOKEN` for the Wazuh connector. Never expose these values through `NEXT_PUBLIC_*`. The default Android File Guard does not require this service.

## Validation

```bash
python -m unittest discover -s tests -p "test_firstlight*.py" -v
python -m unittest discover -s tests -p "test_satark_backend*.py" -v
```

The test suite covers deterministic engine behavior, bounded ingestion, persistence contracts, worker processing, approval state transitions, four-eyes controls, at-most-once response execution, recovery-to-unknown, and mocked provider submission. Physical Wazuh acceptance still requires authorized lab infrastructure.
