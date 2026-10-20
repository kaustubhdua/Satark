# SATARK / FIRSTLIGHT deployment sign-off

Last reviewed: 2026-10-20 UTC

**Decision: NO-GO for production readiness.** This is an evidence record, not a promise that a missing check passed. CI proves the checked repository paths only; live-provider and production deployment behavior require separate proof.

## Candidate and deployment identity

- Canonical repository: [kaustubhdua/Satark](https://github.com/kaustubhdua/Satark)
- Latest runtime-code baseline reviewed: `1acf9e1392f3d0110f01cf1a2eed7a4a70946894` (PR #180, Wazuh worker membership revalidation). Documentation-only release-evidence PRs #181, #182 and #183 followed; current `main` at this review is `e2b6f003d50521c7fa2e83c2c3b2a81192af309c`. PRs #173, #174, #177, #178 and #180 are merged. PR #174/#177/#178 isolated migration/security checks passed; PR #180's FIRSTLIGHT API CI passed on its exact head; PR #183 CI and CodeQL passed. A main CI run was cancelled during successive documentation-only merges, so this record does not claim a successful full CI run on the exact current-main SHA. The tenant-isolation integration job reports success but skips the live-account test when dedicated credentials are unavailable.
- Latest verified READY production deployment: `dpl_4HRahKGhrAGeEKQdqB2AhRcH4GUJ`, source SHA `1b6a2dee26498ef6eef5f28ba58062264ff98d07`, URL `satark-9ip804b4a-jyc-website.vercel.app`, aliases `satark-rose.vercel.app` and `satark-jyc-website.vercel.app`. It predates runtime-code baseline `1acf9e1392f3d0110f01cf1a2eed7a4a70946894`, including the worker membership fix and the production-smoke contract.
- Production smoke run `39375823346` failed because the live `/` response did not contain the expected homepage marker. The Vercel project has SSO protection enabled for all non-custom domains and only the two `vercel.app` aliases configured, so the response may be a protection/login page rather than the app. A direct deployment API attempt returned HTTP 403; the Vercel bot also reports `api-deployments-free-per-day` (over 100 deployments in 24 hours), and runtime-error inspection returned 403. Do not bypass quota or deployment permission; the project owner must clear the quota and provide an approved public custom domain or a scoped smoke-bypass secret without disabling SSO globally.
- Deployment is currently blocked by the daily deployment quota (`api-deployments-free-per-day`) and direct deployment API HTTP 403. Do not bypass billing/rate limits or change project settings automatically.
- The connected Vercel runtime-error endpoint returned 403 for this project; current production runtime errors could not be independently inspected.
- Production alias: [https://satark-rose.vercel.app](https://satark-rose.vercel.app). Alias runtime behavior and runtime-error inspection remain unverified; the unauthenticated production smoke failed its homepage marker check and the aliases are protected by SSO.
- Vercel environment inventory (names/targets only; secret values were not decrypted) lists eight variables: `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `SATARK_OLLAMA_BASE_URL`, `SATARK_OLLAMA_MODEL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_PUBLISHABLE_KEY`, and `SUPABASE_URL`. No `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, or Wazuh Indexer URL/credentials are present. No `SUPABASE_SERVICE_ROLE_KEY` is present in Vercel; keep it on the private worker host, not in Vercel. The production connector/worker cannot be assumed configured.

## Verified repository checks

- PR #160 (persistent Wazuh ingestion and investigation workflows): merged; FIRSTLIGHT API CI, CI, Web CI, CodeQL, and isolated Supabase migration validation passed on its PR head.
- PR #159 (SATARK evidence-storage policy helper): merged; CI, CodeQL, isolated migration validation, tenant-isolation integration, and browser/accessibility smoke passed on its PR head.
- PR #173 (Wazuh checkpoint advancement), PR #174 (six policy rebind), PR #177 (cross-tenant denial tests), PR #178 (policy contract tests and production-smoke marker contract), and PR #180 (worker membership revalidation): merged; their relevant API, isolated migration, CI, browser/accessibility, and CodeQL checks passed on exact PR heads. These checks do not prove live Wazuh connectivity or current production behavior.
- PR #161 (storage migration history): merged; CI, CodeQL, and isolated migration validation passed on its validated head.
- PR #164 (remove unrecorded storage-policy migration duplicate): CI, Web CI, CodeQL, and isolated migration validation passed on its exact head.
- PR #167 (strict evidence-upload object-key regression test): CI, Web CI, browser/accessibility smoke, tenant-isolation integration, and CodeQL passed; merged as `cf5be5927a572999841741e1129019b4f7823628`.
- PR #168 (SATARK foreign-key support indexes): CI, Web CI, browser/accessibility smoke, tenant-isolation integration, CodeQL, and isolated migration validation passed; merged as `92dcca3c748ac54e1da526da331be23ac404487a`.
- PR #167 (strict evidence upload object-key contract): CI, Web CI and CodeQL passed and the test-only PR is merged.
- These are PR-head checks, not proof that the current production deployment runs that SHA.

## Verified hosted database facts

Read-only queries against the shared Supabase project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) confirm:
- `satark_evidence_object_insert` and `satark_evidence_object_read` call `satark_private.has_membership`, enforce tenant/case ownership, and scope raw Wazuh snapshots to owner/responder/analyst while allowing viewers to read ordinary evidence.
- Authenticated can execute the private membership helper; authenticated and anon cannot execute the public membership wrapper.
- Authenticated cannot execute the audit-trigger function as an RPC.
- All 11 SATARK data tables have RLS enabled and zero rows; there are no tenants, cases, memberships, evidence records, jobs, notes, or approvals. No synthetic production records were created.

The live migration history records `20261018114039`, `20261020042449` and `20261020044018`, but not `202610200004`, `20261020042000`, `20261020050000`, or the new `20261020051000_satark_rebind_membership_policies.sql`. The canonical storage policy is recorded under `20261020044018`; the unrecorded `20261020043000` migration file was removed by PR #164 and should not be repaired as a local migration. See [SUPABASE_MIGRATION_HISTORY_REPAIR.md](SUPABASE_MIGRATION_HISTORY_REPAIR.md). A trusted operator must reconcile versions `202610200004` and `20261020042000` with the Supabase CLI, then verify the dry-run shows exactly `20261020050000_satark_foreign_key_support_indexes.sql` and `20261020051000_satark_rebind_membership_policies.sql` pending before applying those SATARK-only migrations. The six approval/case-note/investigation-job policies still call the revoked public membership wrapper in the live database; those operations can fail closed until PR #174's migration is applied.

## Supabase advisor review

A read-only advisor run on 2026-10-20 reported one INFO finding for `satark_ingestion_checkpoints` (RLS enabled without policies). This is intentional: the table is forced-RLS and has no `anon` or `authenticated` table privileges; the persistent worker uses the server-side service role. The advisor also reported SECURITY DEFINER RPC warnings across the shared project. The four SATARK RPCs inspected (`satark_authorize_response_action`, `satark_consume_response_approval`, `satark_decide_approval`, and `satark_list_assignable_members`) have an empty search path and explicit authentication/tenant-role/approval checks; retain the regression tests and review these guards whenever the functions change. Other warnings include Nirdhoom/Saathi functions and were not modified in this SATARK task.

The performance advisor identified five SATARK foreign-key columns without covering indexes. PR #168 added those indexes to the repository and passed isolated migration validation, but the migration has not been applied to the shared project because migration-history repair is still pending. Re-run the advisor after the approved linked migration push; do not remove unused indexes solely because the current SATARK tables have zero rows.

## Release gates

| Gate | Status | Required evidence |
|---|---|---|
| Exact current main deployed to production | BLOCKED | Vercel quota cleared, authorized deployment path available, and source SHA matched to current main |
| Production alias points to that deployment | NOT VERIFIED | Alias metadata tied to deployment ID and exact SHA; production smoke currently fails and aliases are SSO-protected |
| Current production runtime errors inspected | BLOCKED | Vercel runtime-error access restored or another authorized source used |
| Storage policy ACL and tenant/case scope | PASS (read-only inspection) | Current live policy definitions and function grants queried |
| Migration history reconciled | BLOCKED | CLI repair for versions 202610200004 and 20261020042000, followed by linked migration-list verification |
| Isolated database migrations and RLS tests | PASS on PR #159/#160/#161/#164 heads | Exact-head workflow results on the merged PRs |
| Real Wazuh Indexer connection | NOT RUN | Authorized lab endpoint, dedicated least-privilege credentials, verified TLS, bounded query and real alert fixture |
| Persisted Wazuh-to-case-to-investigation-to-report workflow | BLOCKED | Authorized SATARK tenant/case/actor and successful end-to-end run with checkpoint/restart/idempotency verification |
| Worker operational recovery | NOT RUN | Private persistent host, restart/retry test, monitoring and backup/restore drill |
| Response execution | SIMULATION ONLY | Live containment remains disabled; any future enablement needs durable human approval, scoped authorization, rollback and an approved lab |
| Desktop/mobile and production browser smoke on current main | BLOCKED | Exact-SHA deployment plus accessible public custom domain or scoped smoke bypass and successful browser/accessibility evidence |

## Required next steps

1. In a trusted CLI environment, repair migration-history versions `202610200004` and `20261020042000` as applied only after verifying the existing schema objects, as documented in `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`; do not execute their historical SQL.
2. Run `supabase db push --dry-run --linked` against the confirmed project and stop unless exactly `20261020050000_satark_foreign_key_support_indexes.sql` and `20261020051000_satark_rebind_membership_policies.sql` are pending. Apply only those SATARK-owned migrations, verify the migration list, indexes, policy helper references, and function ACLs.
3. Have the Vercel project owner clear the deployment quota and resolve direct deployment permission. Keep SSO enabled; provide an approved public custom domain or scoped protection-bypass secret for smoke testing. Deploy the exact current main SHA through the authorized Git integration and verify `/api/version` and deployment metadata.
4. Provision the FIRSTLIGHT API host and configure server-side `FIRSTLIGHT_API_URL`/`FIRSTLIGHT_API_TOKEN`; configure `FIRSTLIGHT_WAZUH_SYNC_TOKEN` only for the sync endpoint if used. Do not put service-role credentials in Vercel.
5. Provision an authorized Wazuh lab endpoint and a separate SATARK test tenant/case/actor; run the private worker with its service-role key only on the private host. Validate ingestion, checkpoint advancement, revocation handling, restart recovery, deduplication, source downloads, investigation, report export, and tenant isolation.
6. Complete monitoring, backup/restore and recovery drills. Keep live response disabled until a separately reviewed and tested approval/execution workflow exists.

## Sign-off

- Final status: **BLOCKED — implementation and several PR checks are verified, but current-main production deployment, live Wazuh end-to-end execution, migration-history repair, and operational recovery are not verified.**
- Human release owner: not assigned in this record.
- Rollback/restore drill: not verified.
- No claim of production readiness or forensic certification is made.
