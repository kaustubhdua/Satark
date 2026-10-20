# FIRSTLIGHT implementation status

Last reviewed: 2026-10-20 (UTC)

## Current source and release status

- Latest runtime-code baseline reviewed: `1acf9e1392f3d0110f01cf1a2eed7a4a70946894` (PR #180, revalidate Wazuh worker membership around privileged writes). Subsequent merges #181 and #182 were documentation-only; no runtime code changed after that code baseline.
- PR #174 merged with the policy-rebind migration after its exact-head CI, CodeQL, isolated Supabase migration validation, web validation, and browser/accessibility smoke passed. The post-merge checks on `7f426fe793ab78375094111b7fed8462e669e018` passed; later source changes mean the current main CI and CodeQL must be rechecked before release.
- PR #173 is merged: successful empty Wazuh query windows advance the durable checkpoint to the drained window boundary, while failed polls preserve the prior cursor. Its API regression tests, CodeQL, web validation, and browser/accessibility smoke passed.
- PR #177 added cross-tenant read/write denial coverage for case notes, investigation jobs, and approvals; its 50-assertion pgTAP suite, CodeQL, and isolated migration validation passed. PR #178 added policy contract checks and a production-smoke marker guard; its isolated migration validation and production-smoke contract check passed.
- PR #180 is merged with per-poll, per-page, and checkpoint-boundary membership revalidation for the long-running Wazuh worker. Its FIRSTLIGHT API CI passed; current-main CI and CodeQL are still running at this review.
- The latest observed Vercel production deployment is `dpl_4HRahKGhrAGeEKQdqB2AhRcH4GUJ`, READY and aliased as `satark-rose.vercel.app` / `satark-jyc-website.vercel.app`, at source SHA `1b6a2dee26498ef6eef5f28ba58062264ff98d07` (main after PR #177). It predates runtime-code baseline `1acf9e1392f3d0110f01cf1a2eed7a4a70946894`, including the worker membership fix and the current production-smoke contract. Production smoke run `39375823346` failed because the live `/` response did not contain the expected homepage marker; production behavior is not verified. The Vercel project has SSO protection enabled for all non-custom domains, and its only configured domains are the two `vercel.app` aliases above; the smoke failure may therefore be a protection/login response rather than a stale HTML build. The owner must provide an approved public custom domain or configure a scoped deployment-protection bypass for the smoke workflow; do not disable SSO globally. The direct Vercel deployment API returned HTTP 403, and the Vercel bot reports `api-deployments-free-per-day` (over 100 deployments in 24 hours). Do not bypass the permission boundary or repeatedly retry while quota is exhausted; wait for the quota window to reset or have the project owner resolve it through the authorized Git integration. A READY preview is not proof of production release.
- The current Vercel environment-variable inventory contains Supabase settings, Upstash settings, and optional Ollama settings, but no `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer credentials, or private worker-host configuration. No authorized Wazuh lab endpoint or SATARK tenant/case/member/actor is available.
- Read-only inspection of the approved shared Supabase project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) confirms all 11 SATARK tables have RLS enabled and currently contain zero rows. The project also hosts Nirdhoom and Saathi; do not reset it or create fake production data.
- A read-only live policy audit confirms six approval, case-note, and investigation-job policies still reference `public.satark_has_membership`, whose EXECUTE grant is revoked for authenticated users. These operations can fail closed until migration `20261020051000` is applied. The checkpoint table's no-policy advisor finding is intentional: `anon` and `authenticated` have no table privileges, and the private worker uses service-role access.
- Migration history still needs the guarded operator repair described in `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`. The expected pending repository migrations after that repair are now two: `20261020050000_satark_foreign_key_support_indexes.sql` and `20261020051000_satark_rebind_membership_policies.sql`. Do not run a broad `supabase db push`; confirm the linked project and exact dry-run first.
- **Release decision: NO-GO for production use** despite passing code checks: migration history must be reconciled and the exact pending-migration dry-run verified; the current approved main SHA must be deployed and verified after the Vercel quota clears; required API/Wazuh configuration and a private worker must be provisioned; and an authorized real end-to-end ingestion-to-report test plus recovery/backup verification must succeed. Keep live response actions disabled.

This status describes repository-backed behavior and explicitly lists external configuration gates; passing CI does not prove live-provider or production readiness.

## Earlier verified release-gate status (2026-10-20; pre-PR #174)

- The Wazuh checkpoint migration is applied to the approved shared Supabase project `nihdhoom` after inspecting the existing SATARK schema, migration history, foreign keys, existing Wazuh evidence, and index conflicts. The checkpoint table has forced RLS with no `anon`/`authenticated` privileges; the duplicate-protection index is present. Its no-policy advisor notice is intentional because only the private worker/service role should access it. No Nirdhoom or Saathi tables/data were modified.
- Read-only table inspection confirms the live project currently has zero rows in all 11 SATARK data tables, including tenants, memberships, cases, evidence, ingestion checkpoints, investigation jobs, case notes, and approvals. The private `satark-evidence` bucket exists with a 4 MiB object limit. Do not create fake production tenant/case/user records to bypass this gate.
- The investigation API fails closed when `FIRSTLIGHT_API_TOKEN` is missing or shorter than 32 characters. The Next.js proxy requires the strong token even for local HTTP. The worker and authenticated source-download route enforce the bucket's 4 MiB object limit. PR #170 also fixes local Compose Supabase auth configuration; its recorded API CI, general CI, Web CI, CodeQL and browser/accessibility smoke checks passed. Its tenant-isolation job reported success but skipped the live-account test step.
- Added a versioned deterministic rule registry (`firstlight_rules.py`, version `1.0.0`) with stable rule IDs, cautious candidate ATT&CK mappings and rule limitations. Its API container copy and CI path triggers were updated.
- The Wazuh integration is merged in PR #160; its FIRSTLIGHT API CI, CodeQL, general CI, Web CI, and isolated migration validation passed on that PR head. PR #161 and PR #164 storage-policy cleanup checks passed; PR #167's object-key regression test and PR #168's SATARK foreign-key indexes also passed their exact-head CI, Web CI, CodeQL and isolated migration checks.
- Vercel currently has an older production deployment at SHA `21abd4c7466cb7490ae1acb372d04008f72e40d5`; the latest available deployment is a READY preview for branch `feat/firstlight-wazuh-rebased` at SHA `a6ad65ea910c40362bb9005febb447893776002f`. A new deployment attempt was blocked by HTTP 402 `api-deployments-free-per-day` with a 24-hour retry window; the runtime-error API returned 403. The production environment inventory lacks `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN` and Wazuh Indexer configuration. No authorized Wazuh endpoint/credentials or SATARK test tenant/case/actor exists; all 11 SATARK data tables currently contain zero rows, so real end-to-end ingestion remains blocked.

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
- API tests cover health status, verified records, tamper detection, duplicate IDs and token enforcement. PR #160's recorded FIRSTLIGHT API CI and general CI passed, including the relevant worker and container build checks; live provider execution remains a separate gate.

## Follow-up implementation update (2026-10-20)

- Persistent save retries now compare existing evidence fields and the original browser digest before treating an HTTP 409 as an idempotent retry. Conflicting content fails closed instead of being silently skipped.
- The save flow no longer silently truncates an evidence set above 500 records. A failure after earlier writes is reported as a partial save; retries must verify each conflicting record before proceeding.
- Finding conflicts are checked against the persisted finding key, title, severity, detail, evidence references and source before being treated as identical retries.
- Added `firstlight_agents.py`: opt-in independent local Ollama calls for integrity review, timeline analysis and detection analysis. Each gets a bounded read-only evidence projection, has no executable tools, must return a strict Pydantic schema, and has evidence IDs checked against the current case. Agent findings are advisory; deterministic results remain authoritative.
- Integrated the optional agent output into the shared API response. The default remains deterministic-only. Set `FIRSTLIGHT_MODEL_AGENTS_ENABLED=true` and configure a reachable private/local Ollama endpoint plus `FIRSTLIGHT_OLLAMA_MODEL` to opt in. This is not an independent-model ensemble: the specialist calls use the same configured model, and there are no live collection or response tools.
- Added Python agent-contract tests and CI coverage for the agent module. Added browser-source contract tests for duplicate handling and agent guardrails.
- These deterministic/optional-agent changes are merged. PR #160's recorded API CI, general CI, Web CI, CodeQL and isolated migration validation passed. Model agents remain opt-in and advisory; the production Ollama configuration and behavior have not been verified.
- The most recent production deployment lookup still reports an earlier SHA than the latest source changes. Exact latest-commit deployment, tenant-isolation credentials/results, browser/accessibility results and production smoke checks remain unverified.
- Durable approval records, decision/consumption RPCs, and policy guards exist in the database schema. The remaining gap is verified integration with a response executor and FIRSTLIGHT UI, plus real-tenant/recovery testing. Existing session decisions are not durable approvals, and no live action may be claimed without a verified execution record.

## Latest hardening update (2026-10-20)

- Added a shared streaming JSON parser at `web/src/lib/read-bounded-json.ts`. It checks declared lengths as an early rejection, counts actual streamed bytes, cancels oversized streams, rejects invalid UTF-8/JSON, and only parses after the limit is satisfied.
- Applied it to evidence-record, finding, and report write APIs, which previously relied on `Content-Length` plus `request.json()`; chunked requests now have an actual byte cap in these routes too.
- Added a source-contract regression test covering the shared parser and all three route integrations.
- These changes are committed to `main`; merged PR #160 and PR #170 checks passed on their exact PR heads. This does not establish that the current `main` SHA is deployed or that production browser behavior is verified.
- Current `main` is not verified in production. The latest observed production deployment is older than `main`; the connected Vercel integration previously returned HTTP 403 for production-deployment permission, and runtime-error inspection was also denied. Production browser/API behavior remains unverified.

## Partially implemented

| Capability | Current state | What is still missing |
|---|---|---|
| Multi-agent investigation | Six bounded deterministic stages expose a versioned evidence-grounded trace. Optional Ollama specialist calls for integrity, timeline, and detection analysis exist behind an explicit opt-in and strict schema/evidence-ID validation. | Independent model ensemble, tool-using agents, shared run state, retry policy, per-agent evaluation, calibrated performance metrics, and production Ollama validation. |
| Suspicious activity detection | Versioned deterministic rule registry and explainable correlation rules link findings to evidence IDs; synthetic tests and evaluation corpus exist. | Broader coverage, evaluation on validated live telemetry, representative false-positive/negative measurements, and continuous rule/version governance. |
| Evidence prioritization | New transparent heuristic ranks supplied records and flags integrity mismatches for quarantine/review. | Domain-validated weights, analyst-configurable policy, source-specific volatility decay, prioritization metrics and UI parity in the Next.js workflow. |
| Timeline reconstruction | Sorts supplied timestamps and shows relationships/gaps. | Clock-skew handling, provenance/confidence per event, cross-source entity resolution and causal-relationship validation. |
| Evidence integrity | Hashes protect against accidental/after-sealing changes relative to a stored baseline. | Trusted collector identity, signed manifests, independently anchored hashes, trusted timestamps and durable chain of custody. |
| Case storage | Supabase-backed tenant/case/evidence/report storage, case assignment and notes, durable investigation jobs, approval records, audit events, and storage policies exist in code. | Reconcile live migration history, configure a real authorized test tenant/member, verify create/import/investigate/approve/export end-to-end, and run retention/backup/recovery drills. |
| Live response adapters | Opt-in Microsoft Defender device-isolation and Entra session-revocation adapters exist separately; durable approval and consumption controls are present in the database. | Safe authenticated UI-to-executor integration, real-tenant validation, durable execution-result linkage, idempotent retry/rollback behavior, and recovery drills. Keep live actions disabled until these gates pass. |
| Frontend/backend parity | The Next.js UI proxies to a shared FastAPI endpoint backed by `firstlight_engine.py`; Streamlit calls that same engine module directly. Local Compose includes the API service. | Configure the shared service for each deployment, persist case/audit state, and verify end-to-end behavior in CI and on the deployed environment. |

## Not implemented / not verified

- Live endpoint collector for active processes, connections, memory, and volatile system state.
- Autonomous LLM agents that independently plan and call investigation tools.
- Real-time ingestion or streaming telemetry pipeline.
- Production-grade forensic chain of custody or independently immutable audit anchoring.
- A production-verified fully connected persistent case lifecycle across create/import/investigate/approve/export (the components exist in code, but live configuration and end-to-end verification remain outstanding).
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


## Wazuh connector milestone (historical initial connector; superseded by PR #160)

- Added a bounded, read-only Wazuh Indexer/OpenSearch connector using server-side HTTPS configuration, a dedicated Indexer username/password, default TLS certificate verification, a fixed configurable index-pattern allowlist, bounded timeouts, response-byte limits, and a maximum page size of 500.
- Normalizes alerts to stable event IDs and preserves index/document provenance, source timestamps, rule/agent metadata, and a SHA-256 digest of the source record. Oversized nested alert data is represented by a bounded truncation marker and digest.
- Added an authenticated endpoint at GET /api/v1/integrations/wazuh/alerts. It requires a separate FIRSTLIGHT_WAZUH_SYNC_TOKEN of at least 32 characters even when the general investigation API token is unset.
- Added connector normalization, configuration, bounds, authentication, and mocked HTTP tests; wired them into the FIRSTLIGHT API CI workflow.
- Fixed Dockerfile.firstlight-api to copy firstlight_agents.py, ai_provider.py, and firstlight_wazuh.py. Without these modules, the container could fail at import time or when optional model agents are used.
- Added docs/FIRSTLIGHT_WAZUH_INTEGRATION.md with configuration and setup guidance.

**Historical limitation:** this initial connector alone fetches one page and does not persist events or maintain checkpoints. PR #160 adds the separate persistent worker, durable checkpointing, authenticated case workflow, investigation queue, and associated tests. PR #160's recorded checks passed; no real Wazuh endpoint/credentials or authorized SATARK case were available, so the end-to-end lifecycle remains unverified.


## Persistent Wazuh worker implementation update

- Added firstlight_wazuh_worker.py to run outside Vercel. It validates the configured case/tenant and an owner/responder/analyst actor, reads a durable checkpoint, queries a bounded Wazuh Indexer time window, saves normalized events to the existing SATARK evidence table using duplicate-safe inserts, and advances the checkpoint only after all pages complete.
- Added a new migration for a service-role-only ingestion checkpoint table and a worker container definition.
- The worker uses an overlap window for delayed events and refuses to advance the cursor if it reaches the Indexer's 10,000-result pagination cap. It uses HTTPS and rejects redirects for privileged Supabase REST requests.
- Added mocked worker tests for paging, idempotent persistence behavior, checkpoint advancement/failure handling, and rejection of an unauthorized actor.
- The API CI workflow now includes connector and worker tests and builds both container images.

**Still not verified:** the worker has not been run against a real Wazuh Indexer; live endpoint enrollment, real tenant isolation, restart recovery and production deployment remain unverified. The migration is applied to the approved shared `nihdhoom` project, not a dedicated database. The Wazuh preview endpoint does not persist data; persistence is done by the separate worker only after its prerequisites are met. This connector is merged in PR #160 and its checks passed; live endpoint and credential validation remain a release gate.


## Wazuh UI and persistence follow-up

- Added an authenticated Next.js server-side proxy for the read-only Wazuh API. It validates the Supabase user session, keeps the connector token server-side, bounds query size and response bytes, rejects redirects, and does not expose Wazuh credentials to the browser.
- Added a FIRSTLIGHT workspace action to load one bounded page of real Wazuh alerts, preserve source metadata and raw timestamp provenance, and review/save them through the existing persistent case workflow.
- Updated the persistent case panel and export to preserve evidence metadata and the browser-verifiable digest for worker-ingested Wazuh records.
- Added a partial unique index to prevent the same Wazuh index/document identity from being inserted twice into one case by the worker and UI paths.

**Still unverified:** no real Wazuh credentials or endpoint were used. The migration has been applied to the approved shared SATARK/Nirdhoom/Saathi Supabase project with SATARK-only changes; a dedicated SATARK database was not created. The rule-registry/container changes passed the PR #160 checks, but the available Vercel deployment is a preview for a feature-branch SHA rather than verified production on current main. End-to-end behavior must be tested with a real authorized lab endpoint and SATARK case before production use.


## Durable investigation queue milestone (2026-10-20)

- Added a SATARK-only Postgres job table with tenant/case foreign keys, requester identity, idempotency key, retry ceiling, lease, versioned result, and SHA-256 result digest. Authenticated analysts/responders/owners may enqueue/read jobs through RLS; only the trusted service-role worker can claim or finish jobs.
- Added atomic `FOR UPDATE SKIP LOCKED` claiming, lease expiry/reclaim, retry limits, and terminal failure when a worker's final lease expires. Completion rejects oversized results and malformed digests.
- Applied the additive migration to the existing shared `nihdhoom` Supabase project after checking its SATARK-only scope. The live table has RLS and FORCE RLS enabled, and the expected member-read/analyst-enqueue policies are present. Migration version recorded by Supabase is `20261020031055`; the repository migration path matches it. The queue currently contains zero jobs.
- Added `firstlight_investigation_worker.py`, a non-root worker image, and an opt-in Docker Compose profile. The worker rechecks the case and requester membership, loads bounded persisted evidence, runs deterministic investigation, writes idempotent finding/report snapshots, and marks the job successful only after persistence. It does not execute response actions and does not require Ollama for deterministic results.
- Added authenticated Next.js `POST/GET /api/firstlight/jobs` routes. Enqueue uses a caller-provided stable idempotency key and Supabase user JWT/RLS; status reads are also user-scoped. The persistent case workspace now exposes a **Run durable investigation** action and polls the durable job state for up to one minute.
- Added Python and web contract tests and extended FIRSTLIGHT API CI to test the job worker and build its container.

**Not yet release-verified:** PR #160's recorded GitHub Actions checks passed, but no authorized SATARK tenant/case/membership exists in the connected project, so no real job can be queued safely. The worker has not been deployed to a private persistent host. Live Wazuh, Ollama readiness, backup restoration, and end-to-end tenant-isolation checks remain blocked by missing authorized test infrastructure. This is repository implementation plus live schema validation, not a claim of production readiness.


## Follow-up hardening (2026-10-20)

- Applied the previously missing durable approval schema to the approved shared Supabase project, then enforced a database CHECK constraint that permits only `simulation.*` action keys with `action_payload.mode = 'simulation'`. The table has RLS and FORCE RLS enabled, member-read/request policies, immutable action parameters, non-self-approval, expiry checks, one-time consumption RPC, and transactional hash-chain audit entries. Live verification found zero approval rows and zero non-simulation rows.
- Reconciled the approval migration filenames with the exact versions recorded in live Supabase migration history (`20261020035814`, `20261020035832`, `20261020035848`, `20261020040028`). Added an explicit ACL migration revoking direct execution of the approval trigger function from API roles; live ACL inspection confirmed the trigger-only function no longer grants EXECUTE to anon/authenticated/service_role.
- Tightened the approval API to accept only the explicit simulation action namespace and require a simulation-mode payload before it attempts persistence. Live response remains disabled; approval records do not execute endpoint actions.
- Fixed the Wazuh worker container to include the deterministic engine and versioned rule registry that its runtime imports. Docker image build success alone had not caught this runtime-import omission.
- Wired the optional FIRSTLIGHT API Ollama configuration to the local Compose service using `OLLAMA_BASE_URL`, `FIRSTLIGHT_OLLAMA_MODEL`, and an opt-in `FIRSTLIGHT_MODEL_AGENTS_ENABLED=false` default. The model remains advisory and deterministic findings do not depend on it.
- Redacted Wazuh worker error output to stable error categories so provider exception text, URLs, or credentials cannot be copied into logs/checkpoints. Added a regression test for secret-bearing exceptions.

**Still blocked from a genuine end-to-end release:** no authorized Wazuh Indexer endpoint/credentials or enrolled lab agent is configured; the live shared project has no SATARK tenant/case/member/actor records; real Supabase tenant-isolation tests need dedicated least-privilege test identities; Vercel's deployment quota currently blocks a fresh deploy and the production SHA is older than main. No evidence-object backup/restore drill, real Wazuh-to-UI smoke test, or real response executor has been verified. Keep live response disabled and do not mark this branch production-ready.

## Follow-up hardening verified in source and shared schema (2026-10-20)

- Durable approval records are constrained to the `simulation.*` action namespace and `action_payload.mode = 'simulation'`. RLS/FORCE RLS, member-read/request policies, immutable request parameters, non-self-approval, expiry checks, one-time consumption, and transactional hash-chain audit entries are present. Read-only live inspection found zero approval rows and no non-simulation approval rows.
- Approval migration filenames were reconciled with the live history versions `20261020035814`, `20261020035832`, `20261020035848`, and `20261020040028`. The trigger-only approval guard function no longer grants EXECUTE to `anon`, `authenticated`, or `service_role`.
- The approval API accepts only the explicit simulation action namespace and requires a simulation-mode payload before persistence. No live endpoint action is enabled by these approval records.
- The FIRSTLIGHT worker image includes the deterministic engine and versioned rule registry imported at runtime. Worker exceptions are reduced to stable error categories so provider exception text, URLs, and credentials are not copied into logs/checkpoints; regression coverage exercises secret-bearing exceptions.
- Local Compose wires optional Ollama configuration through `OLLAMA_BASE_URL` and `FIRSTLIGHT_OLLAMA_MODEL`, with `FIRSTLIGHT_MODEL_AGENTS_ENABLED=false` by default. Model assistance remains advisory and is not required for deterministic findings.

## Latest verification and remaining live gate (2026-10-20)

- PR #173 is merged: successful empty Wazuh polling windows advance the durable checkpoint to the completed query-window boundary; failed polls preserve the previous cursor. Its FIRSTLIGHT API tests, CodeQL, web validation, and browser/accessibility smoke passed.
- PR #174 is merged with migration `20261020051000_satark_rebind_membership_policies.sql` and 43 pgTAP assertions. Its exact-head isolated clean-database migration workflow passed, as did post-merge `main` CI (including browser/accessibility and tenant-isolation jobs), CodeQL, and clean-database migration/security regression on `7f426fe793ab78375094111b7fed8462e669e018`.
- A read-only live audit still finds six approval, case-note, and investigation-job policies referencing the revoked public membership wrapper. Migration `20261020051000` has **not** been applied to the hosted database. Authenticated users lack EXECUTE on the public wrapper, so affected operations can fail closed until the controlled migration-history repair and SATARK-only push are completed.
- The migration repair procedure is documented in `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`. The connected Supabase tools do not expose `supabase migration repair`; run it only from a trusted CLI environment after confirming the linked project ID and exact dry-run. After PR #174, the expected pending migrations are the SATARK support-index migration `20261020050000` and policy rebind `20261020051000`. Stop if the dry-run lists anything else.
- The no-policy advisor notice for `satark_ingestion_checkpoints` is intentional: read-only ACL inspection confirms `anon` and `authenticated` have no table privileges, while the private worker uses service-role access. Do not add user-facing policies to this checkpoint table.
- Live SATARK tables still contain zero tenants, memberships, cases, evidence records, jobs, and approvals. No authorized Wazuh endpoint/credentials or real test actor/case is configured. The tenant-isolation workflow passed its CI job, but its real-account test step is skipped when dedicated least-privilege test credentials are unavailable; this is not evidence of live tenant-isolation success.
- The latest observed production deployment is older than `main`. The connected Vercel integration denied production-deployment permission with HTTP 403; an earlier deployment attempt also hit the free-plan daily deployment quota. Do not bypass either permission/quota gate. Production readiness remains **NO-GO** until the hosted migration repair is completed, the exact deployed SHA is verified, and a real authorized Wazuh-to-case-to-investigation-to-report flow plus worker recovery/backup restoration is demonstrated.
