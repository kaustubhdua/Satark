# Track 1 — SATARK engineering release audit

**Audit date:** 2026-10-20  
**Repository:** `kaustubhdua/Satark`  
**Scope:** Agentic AI for Cybersecurity — detect, analyse, investigate, and respond  
**Decision:** **NO-GO for claims of a fully operational real-world SOC; conditional GO only for a clearly labelled prototype demonstration after the deployed revision is verified.**

This is an evidence-based release gate, not a presentation document. It deliberately distinguishes code present in the repository from behaviors that have actually been verified against real infrastructure.

## Verified from repository source

- The project contains a Next.js workspace, a Python FIRSTLIGHT investigation API/engine, deterministic finding logic, evidence SHA-256 checks, tenant-scoped Supabase persistence paths, approval records, and CI/CodeQL workflows.
- The supporting local analysis path is deterministic by default and can use a self-hosted Ollama model. A model's interpretation is not a detection ground truth.
- FIRSTLIGHT's built-in incident is explicitly synthetic. The legacy FIRSTLIGHT response UI is a simulation and does not itself isolate a real endpoint or revoke a real session.
- A separate opt-in Microsoft Defender/Entra adapter is documented, but the repository documentation explicitly says it has not been live-tested against a tenant and is not wired to the current simulated approval UI.
- The production smoke workflow includes configuration checks for FIRSTLIGHT investigation and Wazuh proxy paths. A configured proxy is not proof that real telemetry was ingested, correlated, or responded to.
- The tenant-isolation integration suite uses ordinary test users and intentionally exercises cross-tenant access. It requires a dedicated non-production Supabase project and credentials; a skipped test is not a pass.
- The production runbook identifies unresolved release gates around exact deployed SHA verification, tenant isolation, migration reconciliation, shared rate limiting, hosting controls, and production verification.

## Track 1 capability status

| Capability | Repository evidence | Release status |
| --- | --- | --- |
| Detect | Local deterministic rules and analysis evaluation corpus exist. The FIRSTLIGHT scenario contains synthetic events. | Implemented as prototype detection; real-world detection quality is not established. |
| Analyse | Deterministic analysis plus optional local Ollama interpretation. | Available, but model behavior and accuracy need target-environment evaluation. |
| Investigate | Evidence-linked findings, integrity checks, timeline/gaps, Python investigation endpoint, and persistent case workflow exist in source. | Source-level capability present; end-to-end deployed workflow not proven by this audit. |
| Respond | Approval records and an opt-in Microsoft adapter exist. The demo UI's response actions are simulated. | Real response is **not release-verified**; do not claim autonomous live containment. |
| Evidence integrity | SHA-256 verification and hash-chained audit structures exist. | Integrity comparison is supported; independent provenance, durable anchoring, and certified chain of custody are not established. |
| Multi-tenant security | Supabase RLS tests and setup guide exist. | **Unverified until the dedicated integration test passes against isolated test tenants.** |
| Deployment | Production smoke workflow exists. | **Unverified until a successful run checks the exact deployed revision and required routes.** |

## Required blockers before describing SATARK as a real operational agent

1. **Real telemetry proof:** configure a dedicated Wazuh test environment and show a genuine event arriving through the authenticated server-side proxy. Preserve source event identifiers and timestamps; record ingestion, parsing, detection, and investigation outcomes. Do not substitute the built-in synthetic scenario for this test.
2. **End-to-end trace:** demonstrate one real test event traversing telemetry ingestion → deterministic detection → evidence-linked investigation → persisted approval → approved response adapter → provider-side state verification → final report. If any stage is simulated, label it explicitly.
3. **Tenant isolation:** provision the dedicated non-production Supabase project and test identities described in `docs/SUPABASE_TENANT_TEST_SETUP.md`. Run the integration suite and require a successful, non-skipped result. Reconcile migration history in that isolated project before any production migration.
4. **Response adapter verification:** in a disposable Microsoft tenant and endpoint/account, test the adapter with least-privilege permissions, explicit target-bound approval, provider-side confirmation, and a documented recovery/unisolation path. Do not enable it on production targets as part of a demo.
5. **Production release identity:** run the production smoke workflow and record the expected Git SHA and deployed revision. A public URL returning HTTP 200 is not sufficient if the revision is stale or protected routes were not exercised.
6. **Security controls:** verify server-managed authentication/session handling, RLS and storage policies, global rate/concurrency/cost limits, body/time limits, egress restrictions, secrets management, and retention/deletion behavior in the actual hosting environment.
7. **Repeatable evaluation:** run the local analysis evaluation and report the corpus size, labels, precision/recall/F1, false positives, latency, and limitations. Current synthetic-corpus metrics are regression diagnostics, not evidence of real-world accuracy.
8. **Clean reproducibility:** run the repository's Python tests, FIRSTLIGHT API/engine tests, web typecheck/tests/build, CodeQL, and browser smoke on the same candidate commit; archive the run URLs and outcomes.

## Additional implementation delivered in this audit branch

The branch now adds a server-side `POST /api/v1/integrations/wazuh/investigate` path. It reads a bounded page from the configured Wazuh Indexer, requires a dedicated integration bearer token and exact tenant binding, preserves source provenance fields, computes a digest over each normalized event, and passes the records through the canonical deterministic FIRSTLIGHT investigation engine. The path is read-only and explicitly returns `persisted: false`; it does not fabricate an event when the query is empty, and it does not claim upstream authenticity based on a digest generated after retrieval.

Added regression coverage for the integration endpoint's response contract, missing authentication, cross-tenant denial, empty results, and page-size bounds. The CI command now includes the existing Wazuh connector tests and the new endpoint tests. Added `docs/FIRSTLIGHT_WAZUH.md` with server-side environment setup, least-privilege guidance, endpoint usage, and limitations.

These are source changes and regression tests, **not evidence of a live Wazuh connection**. The tests use a mocked connector response only to validate the API contract; live acceptance still requires the owner's real Wazuh test environment and sanitized source event IDs. The integration remains read-only, non-persistent, and without live containment.

## Environment-dependent items that cannot be completed from source changes alone

The audit session has no supplied Wazuh endpoint/credentials, disposable Microsoft tenant credentials, dedicated Supabase tenant test secrets, or confirmation of production deployment access. These must be supplied/configured by the repository owner in the appropriate secret stores and test environments. Never commit those credentials.

A code change cannot truthfully manufacture real telemetry, a successful tenant-isolation result, a provider-side containment result, or a verified production SHA. Until the evidence above exists, keep the release decision at **NO-GO for real-world operational claims**.

## Sign-off record

- Candidate commit: fill with the exact commit under test.
- Wazuh event ID and ingestion trace: pending real test.
- Supabase tenant isolation workflow URL: pending dedicated test fixtures.
- Microsoft adapter provider-side verification: pending disposable tenant test.
- Production smoke workflow URL and deployed SHA: pending successful exact-revision run.
- CI / Web CI / CodeQL run URLs: pending candidate-commit verification.
- Decision: **NO-GO for production/real-world operational claims; prototype-only until the blockers are evidenced.**
