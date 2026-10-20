# SATARK / FIRSTLIGHT release execution checklist

Candidate repository: `kaustubhdua/Satark`, branch `main`.

**Current decision: NO-GO for production readiness.** Use this as an evidence checklist. A blank or blocked item is not a pass.

## Current evidence (2026-10-20 UTC)

- PR #160 persistent Wazuh ingestion and investigation workflow merged; FIRSTLIGHT API CI, CI, Web CI, CodeQL and isolated migration validation passed on its PR head.
- PR #159 evidence-storage policy fix merged; CI, CodeQL, isolated migration validation, tenant-isolation integration and browser/accessibility smoke passed on its PR head.
- PR #161 migration-history reconciliation, PR #164 duplicate-migration removal, PR #167 object-key regression coverage, PR #168 SATARK foreign-key support indexes, and PR #170 local Compose Supabase auth configuration are merged; recorded checks passed on their respective PR heads. On PR #170, the tenant-isolation job succeeded but skipped the live-account test step.
- PR #164 removed the unrecorded duplicate `20261020043000` migration and merged strict object-key regression coverage. PR #165 is stale after that merge and must not be merged as-is.
- The live SATARK storage policies and helper ACLs were verified read-only. The shared project has zero SATARK tenants, cases, memberships and evidence records.
- Live migration history records `20261018114039`, `20261020042449` and `20261020044018`; versions `202610200004`, `20261020042000`, and `20261020050000` are missing. A read-only index check confirmed the five SATARK support indexes from `20261020050000_satark_foreign_key_support_indexes.sql` are absent. The unrecorded `20261020043000` migration file was removed by PR #164 and should not be repaired. Follow [the migration repair runbook](SUPABASE_MIGRATION_HISTORY_REPAIR.md) and use the linked Supabase CLI from a trusted environment.
- Latest project-scoped deployment listing identifies READY production deployment `dpl_5YfZ4vrLfMw9XYjbayKZkJwubrAL` at source SHA `08983cd9c88b1cab91ea800577b2ddc291549250`. Current main is `e7dd7deceb4eebd7d538ed70b6a083383a8b069b`, one commit ahead of production.
- An earlier Vercel deployment attempt returned HTTP 402 `api-deployments-free-per-day`. A fresh attempt to deploy current main returned HTTP 403 because the connected integration lacks permission to create a production deployment. Resolve this through the account owner; do not bypass permissions, limits, or billing/security settings.
- The connected Vercel runtime-error API returned 403. Production runtime error inspection remains unavailable.
- A names/targets-only Vercel environment inventory found no `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer endpoint/credentials, or worker service-role configuration. Existing secret values were not decrypted. Provision the required server-side configuration through the project owner before attempting live connector tests.
- No authorized Wazuh endpoint/credentials, SATARK test tenant/case/actor, or private persistent worker host is configured. Real end-to-end ingestion and recovery are therefore not verified.

## Release gates

### Source and migrations
- [x] PR #164 object-key contract and regression tests are merged with required checks passing.
- [ ] Do not merge stale PR #165; use the migration-history repair steps below for the two actual missing versions.
- [ ] Run `supabase migration list --linked` from the trusted, correctly linked checkout.
- [ ] Repair only versions `202610200004` and `20261020042000` as applied, following the runbook; verify the linked list afterward.
- [ ] Confirm `supabase db push --dry-run --linked` shows only `20261020050000_satark_foreign_key_support_indexes.sql` pending; stop if any other migration appears, then apply the single approved SATARK-only migration and verify all five indexes.
- [ ] Confirm the canonical `20261020044018` policy remains present and both policies still use `satark_private.has_membership`.
- [ ] Do not run a broad `supabase db push` before the migration history is reconciled.
- [ ] Review dependency/security findings and ensure the current main revision is covered by the intended CI checks.

### Supabase security and performance advisor
- [x] Confirm the checkpoint-table no-policy INFO finding is intentional: forced RLS, no anon/authenticated table privileges, service-role-only worker access.
- [x] Review the four SATARK SECURITY DEFINER RPCs flagged by the advisor; they use an empty search path and explicit auth/tenant-role/approval checks. Keep regression coverage for those guards.
- [ ] After the documented migration-history repair and approved migration push, re-run the advisor and confirm the five SATARK foreign-key index findings from PR #168 are cleared.
- [ ] Do not change Nirdhoom/Saathi functions or remove unused indexes as part of SATARK cleanup.

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
