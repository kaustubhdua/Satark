# FIRSTLIGHT implementation status

Last reviewed: 2026-10-20

This status describes repository-backed behavior, not planned features or unverified live integrations.

## Current verified release-gate status (2026-10-20)

- The Wazuh checkpoint migration is applied to the approved shared Supabase project `nihdhoom` after inspecting the existing SATARK schema, migration history, foreign keys, existing Wazuh evidence, and index conflicts. The checkpoint table has forced RLS with no `anon`/`authenticated` privileges; the duplicate-protection index is present. No Nirdhoom or Saathi tables/data were modified.
- The live project currently has zero SATARK tenants, cases, memberships, evidence records, and ingestion checkpoints. The private `satark-evidence` bucket exists with a 4 MiB object limit. Do not create fake production tenant/case/user records to bypass this gate.
- The investigation API now fails closed when `FIRSTLIGHT_API_TOKEN` is missing or shorter than 32 characters. The Next.js proxy requires the strong token even for local HTTP. The worker and authenticated source-download route enforce the bucket's 4 MiB object limit.
- Added a versioned deterministic rule registry (`firstlight_rules.py`, version `1.0.0`) with stable rule IDs, cautious candidate ATT&CK mappings and rule limitations. Its API container copy and CI path triggers were updated.
- FIRSTLIGHT API CI and CodeQL passed on the prior fully tested Wazuh-integration head; the broader CI and browser/accessibility smoke also passed there. An isolated database run then exposed a stale contract test that read the live migration-history no-op file instead of the canonical durable-approval schema. The test now targets `202610200001_satark_durable_approvals.sql`; a fresh isolated migration run is required on the current head before merge.
- Vercel deployment status cannot currently be verified through the connected Vercel API (deployment-list access returned 403 and the previously recorded deployment ID was not found). The prior build-rate-limit report remains unresolved. The real Wazuh endpoint/credentials and authorized SATARK tenant/case/actor are not configured; the live SATARK tables currently have zero tenants, memberships, cases, evidence records, checkpoints and approvals, so real end-to-end ingestion remains blocked.

## Implemented in the prototype

- Synthetic account-compromise training case with fictional indicators.
- SHA-256 sealing and verification of normalized evidence records.
- Interactive integrity/tamper challenge that flags changes against the stored digest.
- The Next.js FIRSTLIGHT workspace quarantines records with a detected hash mismatch from local findings and finding references; regression tests cover tampered-only, mixed, and trusted evidence.
- Deterministic detection and correlation rules with evidence-linked findings.
- Timestamp-based timeline reconstruction for supplied events.
- Explicit evidence gaps and uncertainty labels.
- Human approval/rejection of response proposals in simulation only.
- Session-local hash-chained audit events and JSON report export.
- JSON/CSV event import with validation and artifact hashing.
- Evidence triage ranking by volatility, text relevance, timestamp recency and integrity status (deterministic heuristic; not a calibrated risk score).
- A versioned investigation result (`schema_version: 1.1`) with a six-stage, evidence-grounded execution trace: integrity, triage, detection/correlation, timeline reconstruction, verification/gaps, and response planning. Each stage reports deterministic mode, input/output counts, and only evidence IDs from the current case. The Streamlit UI now displays this trace.
- Explicit orchestration metadata states that model-driven independent agents are not enabled; the trace is an honest deterministic multi-stage baseline, not a claim of autonomous LLM collaboration.
- A shared FastAPI endpoint (`POST /api/v1/cases/investigate`) now wraps the canonical `firstlight_engine.py` implementation. The Next.js API route proxies to it when `FIRSTLIGHT_API_URL` is configured, and the FIRSTLIGHT findings panel can run the shared Python engine and show its integrity summary, findings, gaps and stage trace.
- The local Docker Compose stack now includes the shared FIRSTLIGHT API service. The web UI uses a matching canonical evidence-hash format so the backend can detect a changed record without silently re-sealing it.
- API tests cover health status, verified records, tamper detection, duplicate IDs and token enforcement; a dedicated GitHub Actions workflow runs the Python API/engine tests. CI results still need to be observed.

## Follow-up implementation update (2026-10-20)

- Persistent save retries now compare existing evidence fields and the original browser digest before treating an HTTP 409 as an idempotent retry. Conflicting content fails closed instead of being silently skipped.
- The save flow no longer silently truncates an evidence set above 500 records. A failure after earlier writes is reported as a partial save; retries must verify each conflicting record before proceeding.
- Finding conflicts are checked against the persisted finding key, title, severity, detail, evidence references and source before being treated as identical retries.
- Added `firstlight_agents.py`: opt-in independent local Ollama calls for integrity review, timeline analysis and detection analysis. Each gets a bounded read-only evidence projection, has no executable tools, must return a strict Pydantic schema, and has evidence IDs checked against the current case. Agent findings are advisory; deterministic results remain authoritative.
- Integrated the optional agent output into the shared API response. The default remains deterministic-only. Set `FIRSTLIGHT_MODEL_AGENTS_ENABLED=true` and configure a reachable private/local Ollama endpoint plus `FIRSTLIGHT_OLLAMA_MODEL` to opt in. This is not an independent-model ensemble: the specialist calls use the same configured model, and there are no live collection or response tools.
- Added Python agent-contract tests and CI coverage for the agent module. Added browser-source contract tests for duplicate handling and agent guardrails.
- These are code and test changes, not verified test results. No local repository runtime is available in this session to execute the Python/npm suites. The GitHub status wrapper currently returns no workflow runs for these push commits, so it does not establish that CI passed.
- The most recent production deployment lookup still reports an earlier SHA than the latest source changes. Exact latest-commit deployment, tenant-isolation credentials/results, browser/accessibility results and production smoke checks remain unverified.
- Durable authenticated approval records and a safe, audited response-execution adapter remain incomplete. Existing session decisions must not be treated as durable approval or as proof that a live action occurred.

## Latest hardening update (2026-10-20)

- Added a shared streaming JSON parser at `web/src/lib/read-bounded-json.ts`. It checks declared lengths as an early rejection, counts actual streamed bytes, cancels oversized streams, rejects invalid UTF-8/JSON, and only parses after the limit is satisfied.
- Applied it to evidence-record, finding, and report write APIs, which previously relied on `Content-Length` plus `request.json()`; chunked requests now have an actual byte cap in these routes too.
- Added a source-contract regression test covering the shared parser and all three route integrations.
- These changes are committed to `main`; the latest source-contract tests and full CI/build results have **not** yet been observed. A source-contract test is not a substitute for runtime tests.
- Latest Vercel status observed for the write-route changes was still `pending` on their individual commits; the newest test commit had no reported combined status yet. Production deployment SHA and browser behavior remain unverified.

## Partially implemented

| Capability | Current state | What is still missing |
|---|---|---|
| Multi-agent investigation | Six bounded deterministic stages now expose a versioned trace with case-specific input/output counts and evidence references; UI labels the stages accurately. | Independent model agents, schema-validated tool calls, shared run state, retry policy, per-agent evaluation, and bounded tool permissions. |
| Suspicious activity detection | A small set of explainable rules and keyword checks; results link to evidence IDs. | Broader coverage, rule evaluation on validated live telemetry, test corpus, false-positive/negative evaluation and rule/version management. |
| Evidence prioritization | New transparent heuristic ranks supplied records and flags integrity mismatches for quarantine/review. | Domain-validated weights, analyst-configurable policy, source-specific volatility decay, prioritization metrics and UI parity in the Next.js workflow. |
| Timeline reconstruction | Sorts supplied timestamps and shows relationships/gaps. | Clock-skew handling, provenance/confidence per event, cross-source entity resolution and causal-relationship validation. |
| Evidence integrity | Hashes protect against accidental/after-sealing changes relative to a stored baseline. | Trusted collector identity, signed manifests, independently anchored hashes, trusted timestamps and durable chain of custody. |
| Case storage | A Supabase-backed evidence upload API and case-workspace components exist behind configuration/auth requirements. | End-to-end persisted FIRSTLIGHT case lifecycle, verified tenant policies, durable audit writes, retention and recovery tests. |
| Live response adapters | Opt-in Microsoft Defender device isolation and Entra session revocation adapters exist separately. | Safe integration into FIRSTLIGHT's authenticated approval workflow, real-tenant testing, durable approval/result records and recovery drills. |
| Frontend/backend parity | The Next.js UI proxies to a shared FastAPI endpoint backed by `firstlight_engine.py`; Streamlit calls that same engine module directly. Local Compose includes the API service. | Configure the shared service for each deployment, persist case/audit state, and verify end-to-end behavior in CI and on the deployed environment. |

## Not implemented / not verified

- Live endpoint collector for active processes, connections, memory, and volatile system state.
- Autonomous LLM agents that independently plan and call investigation tools.
- Real-time ingestion or streaming telemetry pipeline.
- Production-grade forensic chain of custody or independently immutable audit anchoring.
- A fully connected persistent case lifecycle across create/import/investigate/approve/export.
- Live response initiated from FIRSTLIGHT's own approval interface.
- Firewall/network appliance blocking.
- Verified integration against a dedicated Microsoft test tenant.
- Production readiness or forensic certification.

## Recommended implementation order

1. **Shared investigation service contract:** define one versioned input/output schema and connect both UIs to the same engine/service.
2. **Persistent case and audit lifecycle:** authenticated case ownership, tenant-scoped access, durable event writes, protected manifests and retention.
3. **Agent orchestration:** add bounded, auditable tool calls only after service contracts and persistence are stable; keep deterministic rules as a fallback and require human review for consequential actions.
4. **Telemetry collector:** build an opt-in, least-privilege collector with signed collection manifests, strict egress controls and a disposable test environment.
5. **Live-response integration:** connect existing adapters only after approvals, durable audit, tenant authorization, rollback and integration tests are in place.
6. **Validation and release:** fix failing CI checks, run desktop/mobile smoke tests, verify the exact deployed SHA and document a controlled demo checklist.

## Safety and interpretation notes

- The current priority score is a deterministic triage hint, not a probability or claim of maliciousness.
- A hash mismatch raises review urgency; it does not prove who changed the record or make the record safe to use.
- All response actions in the FIRSTLIGHT prototype remain simulated unless a separate, explicitly enabled integration is configured. Do not present them as live actions without a verified test record.


## Wazuh connector milestone (branch: feat/firstlight-wazuh-ingestion)

- Added a bounded, read-only Wazuh Indexer/OpenSearch connector using server-side HTTPS configuration, a dedicated Indexer username/password, default TLS certificate verification, a fixed configurable index-pattern allowlist, bounded timeouts, response-byte limits, and a maximum page size of 500.
- Normalizes alerts to stable event IDs and preserves index/document provenance, source timestamps, rule/agent metadata, and a SHA-256 digest of the source record. Oversized nested alert data is represented by a bounded truncation marker and digest.
- Added an authenticated endpoint at GET /api/v1/integrations/wazuh/alerts. It requires a separate FIRSTLIGHT_WAZUH_SYNC_TOKEN of at least 32 characters even when the general investigation API token is unset.
- Added connector normalization, configuration, bounds, authentication, and mocked HTTP tests; wired them into the FIRSTLIGHT API CI workflow.
- Fixed Dockerfile.firstlight-api to copy firstlight_agents.py, ai_provider.py, and firstlight_wazuh.py. Without these modules, the container could fail at import time or when optional model agents are used.
- Added docs/FIRSTLIGHT_WAZUH_INTEGRATION.md with configuration and setup guidance.

**Explicitly incomplete:** this connector currently fetches one page only. It does not persist events, maintain durable checkpoints, schedule polling, enqueue jobs, create a case, or complete a Wazuh-to-persisted-case-to-investigation-to-report lifecycle. No live Wazuh credentials or server were available, and CI has not yet been observed for this branch. Do not call this integration production-ready until real lab and end-to-end verification pass.


## Persistent Wazuh worker implementation update

- Added firstlight_wazuh_worker.py to run outside Vercel. It validates the configured case/tenant and an owner/responder/analyst actor, reads a durable checkpoint, queries a bounded Wazuh Indexer time window, saves normalized events to the existing SATARK evidence table using duplicate-safe inserts, and advances the checkpoint only after all pages complete.
- Added a new migration for a service-role-only ingestion checkpoint table and a worker container definition.
- The worker uses an overlap window for delayed events and refuses to advance the cursor if it reaches the Indexer's 10,000-result pagination cap. It uses HTTPS and rejects redirects for privileged Supabase REST requests.
- Added mocked worker tests for paging, idempotent persistence behavior, checkpoint advancement/failure handling, and rejection of an unauthorized actor.
- The API CI workflow now includes connector and worker tests and builds both container images.

**Still not verified:** the worker has not been run against a real Wazuh Indexer; live endpoint enrollment, real tenant isolation, restart recovery and production deployment remain unverified. The migration is applied to the approved shared `nihdhoom` project, not a dedicated database. The Wazuh preview endpoint does not persist data; persistence is done by the separate worker only after its prerequisites are met. Keep the PR unmerged until checks and review pass.


## Wazuh UI and persistence follow-up

- Added an authenticated Next.js server-side proxy for the read-only Wazuh API. It validates the Supabase user session, keeps the connector token server-side, bounds query size and response bytes, rejects redirects, and does not expose Wazuh credentials to the browser.
- Added a FIRSTLIGHT workspace action to load one bounded page of real Wazuh alerts, preserve source metadata and raw timestamp provenance, and review/save them through the existing persistent case workflow.
- Updated the persistent case panel and export to preserve evidence metadata and the browser-verifiable digest for worker-ingested Wazuh records.
- Added a partial unique index to prevent the same Wazuh index/document identity from being inserted twice into one case by the worker and UI paths.

**Still unverified:** no real Wazuh credentials or endpoint were used. The migration has been applied to the approved shared SATARK/Nirdhoom/Saathi Supabase project with SATARK-only changes; a dedicated SATARK database was not created. Latest rule-registry/container CI is pending, Vercel is blocked by its build-rate limit, and end-to-end behavior must be tested with a real authorized lab endpoint and SATARK case before production use.


## Durable investigation queue milestone (2026-10-20)

- Added a SATARK-only Postgres job table with tenant/case foreign keys, requester identity, idempotency key, retry ceiling, lease, versioned result, and SHA-256 result digest. Authenticated analysts/responders/owners may enqueue/read jobs through RLS; only the trusted service-role worker can claim or finish jobs.
- Added atomic `FOR UPDATE SKIP LOCKED` claiming, lease expiry/reclaim, retry limits, and terminal failure when a worker's final lease expires. Completion rejects oversized results and malformed digests.
- Applied the additive migration to the existing shared `nihdhoom` Supabase project after checking its SATARK-only scope. The live table has RLS and FORCE RLS enabled, and the expected member-read/analyst-enqueue policies are present. Migration version recorded by Supabase is `20261020031055`; the repository migration path matches it. The queue currently contains zero jobs.
- Added `firstlight_investigation_worker.py`, a non-root worker image, and an opt-in Docker Compose profile. The worker rechecks the case and requester membership, loads bounded persisted evidence, runs deterministic investigation, writes idempotent finding/report snapshots, and marks the job successful only after persistence. It does not execute response actions and does not require Ollama for deterministic results.
- Added authenticated Next.js `POST/GET /api/firstlight/jobs` routes. Enqueue uses a caller-provided stable idempotency key and Supabase user JWT/RLS; status reads are also user-scoped. The persistent case workspace now exposes a **Run durable investigation** action and polls the durable job state for up to one minute.
- Added Python and web contract tests and extended FIRSTLIGHT API CI to test the job worker and build its container.

**Not yet release-verified:** the new code still needs the latest GitHub Actions runs to complete. No authorized SATARK tenant/case/membership exists in the connected project, so no real job can be queued safely yet. The worker has not been deployed to a private persistent host. Live Wazuh, Ollama readiness, backup restoration, and end-to-end tenant-isolation checks remain blocked by missing authorized test infrastructure. This milestone is repository implementation plus live schema validation, not a claim of production readiness.


## Follow-up hardening (2026-10-20)

- Applied the previously missing durable approval schema to the approved shared Supabase project, then enforced a database CHECK constraint that permits only `simulation.*` action keys with `action_payload.mode = 'simulation'`. The table has RLS and FORCE RLS enabled, member-read/request policies, immutable action parameters, non-self-approval, expiry checks, one-time consumption RPC, and transactional hash-chain audit entries. Live verification found zero approval rows and zero non-simulation rows.
- Reconciled the approval migration filenames with the exact versions recorded in live Supabase migration history (`20261020035814`, `20261020035832`, `20261020035848`, `20261020040028`). Added an explicit ACL migration revoking direct execution of the approval trigger function from API roles; live ACL inspection confirmed the trigger-only function no longer grants EXECUTE to anon/authenticated/service_role.
- Tightened the approval API to accept only the explicit simulation action namespace and require a simulation-mode payload before it attempts persistence. Live response remains disabled; approval records do not execute endpoint actions.
- Fixed the Wazuh worker container to include the deterministic engine and versioned rule registry that its runtime imports. Docker image build success alone had not caught this runtime-import omission.
- Wired the optional FIRSTLIGHT API Ollama configuration to the local Compose service using `OLLAMA_BASE_URL`, `FIRSTLIGHT_OLLAMA_MODEL`, and an opt-in `FIRSTLIGHT_MODEL_AGENTS_ENABLED=false` default. The model remains advisory and deterministic findings do not depend on it.
- Redacted Wazuh worker error output to stable error categories so provider exception text, URLs, or credentials cannot be copied into logs/checkpoints. Added a regression test for secret-bearing exceptions.

**Still blocked from a genuine end-to-end release:** no authorized Wazuh Indexer endpoint/credentials or enrolled lab agent is configured; the live shared project has no SATARK tenant/case/member/actor records; real Supabase tenant-isolation tests need dedicated least-privilege test identities; Vercel reports a build-rate-limit failure and the deployed commit for this branch is not verified. No evidence-object backup/restore drill, real Wazuh-to-UI smoke test, or real response executor has been verified. Keep live response disabled and do not mark this branch production-ready.
