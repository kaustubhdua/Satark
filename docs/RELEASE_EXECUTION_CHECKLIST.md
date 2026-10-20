# SATARK / FIRSTLIGHT release execution checklist

Candidate repository: `kaustubhdua/Satark`, branch `main`.

**Current decision: NO-GO for production readiness.** Use this as an evidence checklist. A blank or blocked item is not a pass.

## Current evidence (2026-10-20 UTC)

- PR #160 persistent Wazuh ingestion and investigation workflow merged; FIRSTLIGHT API CI, CI, Web CI, CodeQL and isolated migration validation passed on its PR head.
- PR #159 evidence-storage policy fix merged; CI, CodeQL, isolated migration validation, tenant-isolation integration and browser/accessibility smoke passed on its PR head.
- PR #161 migration-history reconciliation merged; CI, CodeQL and isolated migration validation passed on its PR head.
- PR #165 makes the superseded storage insert migration inert and documents the operator repair procedure. Its exact-head CI, CodeQL and isolated migration checks must pass before merge.
- The live SATARK storage policies and helper ACLs were verified read-only. The shared project has zero SATARK tenants, cases, memberships and evidence records.
- Live migration history records `20261020042449` and `20261020044018`; versions `20261020042000` and `20261020043000` are missing. Follow [the migration repair runbook](SUPABASE_MIGRATION_HISTORY_REPAIR.md) and use the linked Supabase CLI from a trusted environment.
- Latest production deployment is `dpl_5ounvL24fTLUDLMV7pAYGs2Avg4V`, source SHA `21abd4c7466cb7490ae1acb372d04008f72e40d5`; current main is newer. A READY preview exists for branch `feat/firstlight-wazuh-rebased`, SHA `a6ad65ea910c40362bb9005febb447893776002f`, but it is not production.
- Vercel rejected a new deployment with HTTP 402 `api-deployments-free-per-day` and a retry-after of 86400 seconds. Resolve this through the account/plan owner; do not bypass limits or change billing/security settings automatically.
- The connected Vercel runtime-error API returned 403. Production runtime error inspection remains unavailable.
- A names/targets-only Vercel environment inventory found no `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer endpoint/credentials, or worker service-role configuration. Existing secret values were not decrypted. Provision the required server-side configuration through the project owner before attempting live connector tests.
- No authorized Wazuh endpoint/credentials, SATARK test tenant/case/actor, or private persistent worker host is configured. Real end-to-end ingestion and recovery are therefore not verified.

## Release gates

### Source and migrations
- [ ] PR #165 exact-head CI, CodeQL and isolated migration validation all pass.
- [ ] Review and merge #165 only after those checks pass.
- [ ] Run `supabase migration list --linked` from the trusted, correctly linked checkout.
- [ ] Repair only versions `20261020042000` and `20261020043000` as applied, following the runbook; verify the linked list afterward.
- [ ] Confirm the canonical `20261020044018` policy remains present and both policies still use `satark_private.has_membership`.
- [ ] Do not run a broad `supabase db push` before the migration history is reconciled.
- [ ] Review dependency/security findings and ensure the current main revision is covered by the intended CI checks.

### Deployment
- [ ] Have the Vercel account/plan owner resolve the deployment quota block.
- [ ] Deploy the exact current main SHA to preview; record deployment ID, URL, environment, source SHA and timestamp.
- [ ] Run desktop/mobile browser and accessibility smoke on that exact preview.
- [ ] Promote to production only after preview validation and explicit release approval.
- [ ] Verify the production alias maps to the deployment containing the exact approved SHA.
- [ ] Inspect runtime errors and request logs using authorized project access.
- [ ] Verify environment-variable names and scopes without printing secrets; ensure server-only tokens are never exposed via `NEXT_PUBLIC_*` variables.

### Real Wazuh integration and persistence
- [ ] Provision an authorized Wazuh lab/indexer endpoint and dedicated least-privilege credentials with TLS verification.
- [ ] Provision a separate approved SATARK test tenant, case and owner/responder/analyst actor; do not create synthetic records in the shared project just to pass a test.
- [ ] Verify one bounded page of real alerts through the authenticated connector.
- [ ] Verify worker paging, duplicate suppression, durable checkpoint advancement, overlap window, 10,000-result ceiling behavior and safe error redaction.
- [ ] Kill/restart the worker during ingestion and verify retry, idempotency and checkpoint recovery.
- [ ] Verify raw source evidence digest/provenance and role-scoped download; viewers must not access raw Wazuh snapshots.
- [ ] Queue a durable investigation and verify findings, evidence references, timeline, gaps, report digest and persisted status.
- [ ] Verify cross-tenant read/write attempts are denied with dedicated test identities.

### Operations and response safety
- [ ] Deploy the Wazuh and investigation workers to a private persistent host; do not rely on Vercel request lifetimes for workers.
- [ ] Configure health monitoring, structured redacted logs, alerting and restart policy.
- [ ] Run backup and restore drills for case/evidence metadata, audit records, checkpoints and job state.
- [ ] Keep model agents opt-in and advisory; verify deterministic mode works when Ollama is absent or fails.
- [ ] Keep response actions simulation-only. Do not enable real containment until durable approval, independent authorization, one-time consumption, audit, rollback and lab recovery are reviewed and tested.

### Final acceptance
- [ ] Record all test commands, outcomes, artifact links and timestamps.
- [ ] Update `docs/DEPLOYMENT_SIGNOFF.md` only with evidence observed on the exact candidate/deployment.
- [ ] Have the deployment owner explicitly sign off or document the remaining blockers.

## Product boundary

SATARK/FIRSTLIGHT is an evidence-led incident investigation and triage prototype, not a certified forensic product, EDR replacement, or autonomous containment system. Hashes detect changes relative to a stored digest but do not independently prove collector identity or chain of custody. A green CI run is not a substitute for a verified deployment SHA, real provider integration, tenant isolation, and operational recovery.
