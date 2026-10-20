# FIRSTLIGHT implementation status

Last reviewed: 2026-10-20

This status describes repository-backed behavior, not planned features or unverified live integrations.

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
- PR #160 (FIRSTLIGHT/Wazuh ingestion) and PR #161 (migration-history reconciliation) passed CI, Web CI, CodeQL and isolated migration validation on their exact heads. PR #164 (invalid object-key regression and canonical storage-policy contract test) is merged as `a48869941d5ca277a4499a86e93907fdfa1b18e8`; its exact-head checks passed. Current-main production deployment remains blocked by Vercel's HTTP 402 `api-deployments-free-per-day` limit, so do not equate PR-head CI with a production release.
- The latest production deployment remains older than current `main` (recorded source SHA `21abd4c7466cb7490ae1acb372d04008f72e40d5`). Vercel rejected a deployment attempt with HTTP 402 `api-deployments-free-per-day` and a 24-hour retry window. Exact-main deployment, production alias mapping, browser/accessibility smoke and live tenant-isolation credentials/results remain unverified.
- Durable approval records and simulation-only action constraints are implemented in the merged migrations. Live response execution remains intentionally disabled; session or simulation decisions are not proof that a live action occurred.

## Latest hardening update (2026-10-20)

- Added a shared streaming JSON parser at `web/src/lib/read-bounded-json.ts`. It checks declared lengths as an early rejection, counts actual streamed bytes, cancels oversized streams, rejects invalid UTF-8/JSON, and only parses after the limit is satisfied.
- Applied it to evidence-record, finding, and report write APIs, which previously relied on `Content-Length` plus `request.json()`; chunked requests now have an actual byte cap in these routes too.
- Added a source-contract regression test covering the shared parser and all three route integrations.
- The bounded JSON parser and route integration are in `main`; exact PR-head CI for the later hardening and storage changes passed, but the current `main` production build/deployment has not been verified because Vercel returned the quota error above. A source-contract test is not a substitute for runtime tests.
- Latest production deployment source SHA remains older than `main`; Vercel's deployment attempt returned HTTP 402 `api-deployments-free-per-day`. Production browser behavior and alias mapping remain unverified.

## Verified live storage-policy status (2026-10-20)

- Applied migration `20261020044018_satark_storage_policy_private_helper_rebind` after isolated migration validation.
- Read-only post-apply queries confirm both `satark_evidence_object_insert` and `satark_evidence_object_read` use `satark_private.has_membership`; neither references the public wrapper.
- Authenticated can execute the private helper; authenticated and anon cannot execute the public wrapper; authenticated cannot execute the audit-trigger function as an RPC.
- No evidence rows or synthetic tenant/case/member records were created. The shared project currently has zero SATARK tenants, cases, memberships and evidence records.
- The live migration history is missing versions `202610200004` and `20261020042000`; follow the migration-history repair instructions in `docs/DEPLOYMENT_SIGNOFF.md` before any future linked migration push.

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
