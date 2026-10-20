# SATARK / FIRSTLIGHT deployment sign-off

Last reviewed: 2026-10-20 UTC

**Decision: NO-GO for production readiness.** This is an evidence record, not a promise that a missing check passed. CI proves the checked repository paths only; live-provider and production deployment behavior require separate proof.

## Candidate and deployment identity

- Canonical repository: [kaustubhdua/Satark](https://github.com/kaustubhdua/Satark)
- Latest main revision observed during this review: `e7dd7deceb4eebd7d538ed70b6a083383a8b069b` (PR #170 fixed local Compose Supabase authentication configuration). PRs #160, #159, #161, #164, #167, #168 and #170 have merged with their recorded required checks passing on their exact PR heads; the tenant-isolation integration job on PR #170 reported success but skipped the live-account test step.
- Latest production deployment returned by the project-scoped Vercel listing: `dpl_5YfZ4vrLfMw9XYjbayKZkJwubrAL`, source SHA `08983cd9c88b1cab91ea800577b2ddc291549250`, target `production`, state `READY`, URL `satark-goztgab4q-jyc-website.vercel.app`. Current `main` is now `e7dd7deceb4eebd7d538ed70b6a083383a8b069b`, one commit ahead.
- The project metadata and project-scoped deployment listing confirm that the deployment above is READY for production and tied to SHA `08983cd9c88b1cab91ea800577b2ddc291549250`; current main is ahead at `e7dd7deceb4eebd7d538ed70b6a083383a8b069b`. A direct attempt to create a production deployment of current main returned HTTP 403 because the connected integration lacks permission. The connected runtime-error API also returns 403 and direct browser smoke could not access the protected deployment.
- An earlier deployment attempt returned HTTP 402 `api-deployments-free-per-day`; the most recent explicit attempt to deploy current main returned HTTP 403 for missing production-deployment permission. Do not bypass billing/rate limits or change project settings automatically.
- The connected Vercel runtime-error endpoint returned 403 for this project; current production runtime errors could not be independently inspected.
- Production alias: [https://satark-rose.vercel.app](https://satark-rose.vercel.app). Deployment metadata shows the latest production target is one commit behind current main; alias runtime behavior could not be verified because connected browser/runtime-log access is blocked.
- Vercel environment inventory (names/targets only; secret values were not decrypted) lists eight variables: `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `SATARK_OLLAMA_BASE_URL`, `SATARK_OLLAMA_MODEL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_PUBLISHABLE_KEY`, and `SUPABASE_URL`. No `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer URL/credentials, or worker service-role configuration appeared in this inventory. The production connector/worker therefore cannot be assumed configured; values of existing variables were intentionally not inspected.

## Verified repository checks

- PR #160 (persistent Wazuh ingestion and investigation workflows): merged; FIRSTLIGHT API CI, CI, Web CI, CodeQL, and isolated Supabase migration validation passed on its PR head.
- PR #159 (SATARK evidence-storage policy helper): merged; CI, CodeQL, isolated migration validation, tenant-isolation integration, and browser/accessibility smoke passed on its PR head.
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
- SATARK currently has zero tenants, cases, memberships, and evidence records. No synthetic production records were created.

The live migration history records `20261018114039`, `20261020042449` and `20261020044018`, but not `202610200004`, `20261020042000`, or `20261020050000`. The canonical policy is already recorded under `20261020044018`; the unrecorded `20261020043000` migration file was removed by PR #164 and should not be repaired as a local migration. See [SUPABASE_MIGRATION_HISTORY_REPAIR.md](SUPABASE_MIGRATION_HISTORY_REPAIR.md). A trusted operator must reconcile only versions `202610200004` and `20261020042000` with the Supabase CLI, then verify a dry-run shows only `20261020050000_satark_foreign_key_support_indexes.sql` pending before applying that single SATARK-only migration. The exact sequence is in `SUPABASE_MIGRATION_HISTORY_REPAIR.md`. Migration `20261020044018` was applied after isolated validation and verified read-only; no migration-history repair or support-index migration has been performed.

## Supabase advisor review

A read-only advisor run on 2026-10-20 reported one INFO finding for `satark_ingestion_checkpoints` (RLS enabled without policies). This is intentional: the table is forced-RLS and has no `anon` or `authenticated` table privileges; the persistent worker uses the server-side service role. The advisor also reported SECURITY DEFINER RPC warnings across the shared project. The four SATARK RPCs inspected (`satark_authorize_response_action`, `satark_consume_response_approval`, `satark_decide_approval`, and `satark_list_assignable_members`) have an empty search path and explicit authentication/tenant-role/approval checks; retain the regression tests and review these guards whenever the functions change. Other warnings include Nirdhoom/Saathi functions and were not modified in this SATARK task.

The performance advisor identified five SATARK foreign-key columns without covering indexes. PR #168 added those indexes to the repository and passed isolated migration validation, but the migration has not been applied to the shared project because migration-history repair is still pending. Re-run the advisor after the approved linked migration push; do not remove unused indexes solely because the current SATARK tables have zero rows.

## Release gates

| Gate | Status | Required evidence |
|---|---|---|
| Exact current main deployed to production | BLOCKED | Vercel rate limit cleared, deployment created, and source SHA matched to current main |
| Production alias points to that deployment | NOT VERIFIED | Alias metadata tied to deployment ID and exact SHA |
| Current production runtime errors inspected | BLOCKED | Vercel runtime-error access restored or another authorized source used |
| Storage policy ACL and tenant/case scope | PASS (read-only inspection) | Current live policy definitions and function grants queried |
| Migration history reconciled | BLOCKED | CLI repair for versions 202610200004 and 20261020042000, followed by linked migration-list verification |
| Isolated database migrations and RLS tests | PASS on PR #159/#160/#161/#164 heads | Exact-head workflow results on the merged PRs |
| Real Wazuh Indexer connection | NOT RUN | Authorized lab endpoint, dedicated least-privilege credentials, verified TLS, bounded query and real alert fixture |
| Persisted Wazuh-to-case-to-investigation-to-report workflow | BLOCKED | Authorized SATARK tenant/case/actor and successful end-to-end run with checkpoint/restart/idempotency verification |
| Worker operational recovery | NOT RUN | Private persistent host, restart/retry test, monitoring and backup/restore drill |
| Response execution | SIMULATION ONLY | Live containment remains disabled; any future enablement needs durable human approval, scoped authorization, rollback and an approved lab |
| Desktop/mobile and production browser smoke on current main | NOT VERIFIED | Exact-SHA deployment plus browser/accessibility evidence |

## Required next steps

1. Do not merge stale PR #165 as-is; PR #164 removed the duplicate `20261020043000` migration and merged the strict object-key regression tests.
2. In a trusted CLI environment, run the migration-history repair documented in `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md` for versions `202610200004` and `20261020042000`; do not execute their historical SQL.
3. Resolve Vercel's deployment quota through the account/plan owner, then deploy current main to preview, smoke-test it, and only then promote to production with explicit approval.
4. Provision an authorized Wazuh lab endpoint and a separate SATARK test tenant/case/actor; validate real ingestion, checkpoint advancement, restart recovery, deduplication, source downloads, durable investigation, reports and tenant isolation.
5. Deploy the workers to a private persistent runtime and complete monitoring, backup/restore and recovery drills.
6. Keep live response disabled until a separately reviewed and tested approval/execution workflow exists.

## Sign-off

- Final status: **BLOCKED — implementation and several PR checks are verified, but current-main production deployment, live Wazuh end-to-end execution, migration-history repair, and operational recovery are not verified.**
- Human release owner: not assigned in this record.
- Rollback/restore drill: not verified.
- No claim of production readiness or forensic certification is made.
