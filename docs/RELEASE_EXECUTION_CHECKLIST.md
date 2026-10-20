# SATARK / FIRSTLIGHT release execution checklist

Candidate repository: `kaustubhdua/Satark`, branch `main`.

**Current decision: NO-GO for production readiness.** Use this as an evidence checklist. A blank or blocked item is not a pass.

## Current evidence (2026-10-20 UTC)

- PR #160 persistent Wazuh ingestion and investigation workflow merged; FIRSTLIGHT API CI, CI, Web CI, CodeQL and isolated migration validation passed on its PR head.
- PR #159 evidence-storage policy fix merged; CI, CodeQL, isolated migration validation, tenant-isolation integration and browser/accessibility smoke passed on its PR head.
- PR #161 migration-history reconciliation, PR #164 duplicate-migration removal, PR #167 object-key regression coverage, PR #168 SATARK foreign-key support indexes, and PR #170 local Compose Supabase auth configuration are merged; recorded checks passed on their respective PR heads. On PR #170, the tenant-isolation job succeeded but skipped the live-account test step.
- PR #164 removed the unrecorded duplicate `20261020043000` migration. PR #173 fixed empty-window checkpoint advancement; PR #174 added the SATARK policy-rebind migration `20261020051000`; PR #177 added cross-tenant read/write tests; PR #178 added policy contract tests and the production-smoke marker guard; PR #180 added worker membership revalidation around privileged writes. Exact-head isolated migration validation passed for PRs #174, #177 and #178, and PR #180's FIRSTLIGHT API CI passed.
- Latest runtime-code baseline reviewed is `1acf9e1392f3d0110f01cf1a2eed7a4a70946894`; subsequent main merges #181 and #182 were docs-only. FIRSTLIGHT API CI passed for the code baseline; a main CI run was cancelled during the docs-only merges, so obtain a fresh successful CI result for `git rev-parse origin/main` before release.
- The live SATARK tables still have zero tenants, cases, memberships, evidence records, jobs, and approvals. A read-only policy audit finds six non-storage policies on approvals, case notes, and investigation jobs still calling the revoked public membership wrapper; PR #174 fixes these in repository code, but the new migration is not yet applied to the hosted database.
- Live migration history records `20261018114039`, `20261020042449` and `20261020044018`; versions `202610200004`, `20261020042000`, `20261020050000`, and the new `20261020051000` migration need the guarded runbook procedure. A read-only index check confirmed the five SATARK support indexes from `20261020050000_satark_foreign_key_support_indexes.sql` are absent. The unrecorded `20261020043000` migration file was removed by PR #164 and should not be repaired. Follow [the migration repair runbook](SUPABASE_MIGRATION_HISTORY_REPAIR.md) and use the linked Supabase CLI from a trusted environment.
- The latest known READY production deployment is `dpl_4HRahKGhrAGeEKQdqB2AhRcH4GUJ` at source SHA `1b6a2dee26498ef6eef5f28ba58062264ff98d07`, aliased as `satark-rose.vercel.app` and `satark-jyc-website.vercel.app`. It predates the worker fix in PR #180 and current main `ac602e537c4571e7c56a828c4b3038905140a883`.
- Vercel has reported HTTP 402 `api-deployments-free-per-day` (more than 100 deployments in 24 hours), and the connected deployment API has separately returned HTTP 403 for deployment permission. Resolve the quota/permission through the project owner; do not bypass permissions, limits, or billing/security settings.
- The last production smoke run `39375823346` failed because the live `/` response did not contain the expected homepage marker. Treat the production alias as unverified until the exact approved SHA is deployed and the smoke workflow passes.
- The Vercel project has SSO protection for all non-custom domains and only `vercel.app` aliases configured. Before retrying smoke, provide an approved public custom domain or a scoped deployment-protection bypass secret for CI; do not disable SSO globally.
- The connected Vercel runtime-error API returned 403. Production runtime error inspection remains unavailable.
- A names/targets-only Vercel environment inventory found no `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer endpoint/credentials, or worker service-role configuration. Existing secret values were not decrypted. Provision the required server-side configuration through the project owner before attempting live connector tests.
- No authorized Wazuh endpoint/credentials, SATARK test tenant/case/actor, or private persistent worker host is configured. Real end-to-end ingestion and recovery are therefore not verified.

## Release gates

### Source and migrations
- [x] PR #164 object-key contract and regression tests are merged with required checks passing.
- [x] PR #173 empty-window checkpoint fix and PR #180 Wazuh worker membership-revalidation fix are merged; PR #174's policy-rebind migration and PR #177/#178 security-contract tests passed isolated migration validation before merge.
- [ ] Record `git rev-parse origin/main`; confirm CI and CodeQL finish successfully for that exact SHA before treating it as the release candidate.
- [ ] Run `supabase migration list --linked` from the trusted, correctly linked checkout.
- [ ] Repair only versions `202610200004` and `20261020042000` as applied, following the runbook; verify the linked list afterward.
- [ ] Confirm `supabase db push --dry-run --linked` shows exactly `20261020050000_satark_foreign_key_support_indexes.sql` and `20261020051000_satark_rebind_membership_policies.sql` pending in version order; stop if any other migration appears, then apply only those two SATARK-only migrations.
- [ ] Verify all five support indexes exist and all six approval/case-note/investigation-job policies use `satark_private.has_membership`; confirm `authenticated` and `anon` cannot execute `public.satark_has_membership`.
- [ ] Do not run a broad `supabase db push` before the migration history is reconciled.
- [ ] Review dependency/security findings and ensure the current main revision is covered by the intended CI checks.

### Supabase security and performance advisor
- [x] Confirm the checkpoint-table no-policy INFO finding is intentional: forced RLS, no anon/authenticated table privileges, service-role-only worker access.
- [x] Review the four SATARK SECURITY DEFINER RPCs flagged by the advisor; they use an empty search path and explicit auth/tenant-role/approval checks. Keep regression coverage for those guards.
- [ ] After the documented migration-history repair and approved migration push, re-run the advisor and confirm the five SATARK foreign-key index findings from PR #168 are cleared.
- [ ] Do not change Nirdhoom/Saathi functions or remove unused indexes as part of SATARK cleanup.

### Deployment
- [ ] Have the Vercel account/plan owner resolve the `api-deployments-free-per-day` quota block; the direct deployment API also returned HTTP 403, so use only the authorized Git integration after the quota clears.
- [ ] Deploy the exact current main SHA from `git rev-parse origin/main` to preview after quota clearance; record deployment ID, URL, environment, source SHA and timestamp.
- [ ] Run desktop/mobile browser and accessibility smoke on that exact preview.
- [ ] Promote to production only after preview validation and explicit release approval.
- [ ] Verify the production alias maps to the deployment containing the exact approved SHA recorded above.
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
