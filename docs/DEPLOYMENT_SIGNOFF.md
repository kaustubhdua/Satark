# SATARK / FIRSTLIGHT deployment sign-off

Last reviewed: 2026-10-20 UTC

**Decision: NO-GO for production readiness.** This is an evidence record, not a promise that a missing check passed. CI proves the checked repository paths only; live-provider and production deployment behavior require separate proof.

## Candidate and deployment identity

- Canonical repository: [kaustubhdua/Satark](https://github.com/kaustubhdua/Satark)
- Latest main revision observed during this review: `d6acf5656129e78322aa5691cc74b7a77b3b1f96` (migration-history reconciliation PR #161). A follow-up to make superseded migration `20261020043000` inert is in PR #165 and is not yet merged.
- Production deployment: `dpl_5ounvL24fTLUDLMV7pAYGs2Avg4V`, source SHA `21abd4c7466cb7490ae1acb372d04008f72e40d5`, target `production`, URL `satark-r5lhz4upy-jyc-website.vercel.app`. This is older than current main.
- Latest available preview: `dpl_FwE4x7KHmi6awKAzLCCXUE5rq3nW`, branch `feat/firstlight-wazuh-rebased`, SHA `a6ad65ea910c40362bb9005febb447893776002f`, state READY, target `null`. This is a preview, not proof that main is deployed.
- Deployment attempt for current main was rejected by Vercel with HTTP 402 `api-deployments-free-per-day`, retry-after 86400 seconds. Do not bypass billing/rate limits or change project settings automatically.
- The connected Vercel runtime-error endpoint returned 403 for this project; current production runtime errors could not be independently inspected.
- Production alias: [https://satark-rose.vercel.app](https://satark-rose.vercel.app). Alias-to-current-main identity is not established.
- Vercel environment inventory (names/targets only; secret values were not decrypted) lists eight variables: `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `SATARK_OLLAMA_BASE_URL`, `SATARK_OLLAMA_MODEL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_PUBLISHABLE_KEY`, and `SUPABASE_URL`. No `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer URL/credentials, or worker service-role configuration appeared in this inventory. The production connector/worker therefore cannot be assumed configured; values of existing variables were intentionally not inspected.

## Verified repository checks

- PR #160 (persistent Wazuh ingestion and investigation workflows): merged; FIRSTLIGHT API CI, CI, Web CI, CodeQL, and isolated Supabase migration validation passed on its PR head.
- PR #159 (SATARK evidence-storage policy helper): merged; CI, CodeQL, isolated migration validation, tenant-isolation integration, and browser/accessibility smoke passed on its PR head.
- PR #161 (storage migration history): merged; CI, CodeQL, and isolated migration validation passed on its validated head.
- PR #165 (make superseded storage insert migration inert and document history repair): checks were still running at the time of review. Do not merge until its exact-head CI, CodeQL, and isolated migration validation all pass.
- These are PR-head checks, not proof that the current production deployment runs that SHA.

## Verified hosted database facts

Read-only queries against the shared Supabase project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) confirm:
- `satark_evidence_object_insert` and `satark_evidence_object_read` call `satark_private.has_membership`, enforce tenant/case ownership, and scope raw Wazuh snapshots to owner/responder/analyst while allowing viewers to read ordinary evidence.
- Authenticated can execute the private membership helper; authenticated and anon cannot execute the public membership wrapper.
- Authenticated cannot execute the audit-trigger function as an RPC.
- SATARK currently has zero tenants, cases, memberships, and evidence records. No synthetic production records were created.

The live migration history records `20261020042449` and `20261020044018`, but not `20261020042000` or `20261020043000`. The canonical policy is already recorded under `20261020044018`. See [SUPABASE_MIGRATION_HISTORY_REPAIR.md](SUPABASE_MIGRATION_HISTORY_REPAIR.md). A trusted operator must reconcile the exact missing history versions with the Supabase CLI before any future linked `db push`. No hosted migration was applied by this review.

## Release gates

| Gate | Status | Required evidence |
|---|---|---|
| Exact current main deployed to production | BLOCKED | Vercel rate limit cleared, deployment created, and source SHA matched to current main |
| Production alias points to that deployment | NOT VERIFIED | Alias metadata tied to deployment ID and exact SHA |
| Current production runtime errors inspected | BLOCKED | Vercel runtime-error access restored or another authorized source used |
| Storage policy ACL and tenant/case scope | PASS (read-only inspection) | Current live policy definitions and function grants queried |
| Migration history reconciled | BLOCKED | CLI repair for versions 20261020042000 and 20261020043000, followed by linked migration-list verification |
| Isolated database migrations and RLS tests | PASS on PR #159/#160/#161 heads; PR #165 pending | Exact-head workflow result for #165 |
| Real Wazuh Indexer connection | NOT RUN | Authorized lab endpoint, dedicated least-privilege credentials, verified TLS, bounded query and real alert fixture |
| Persisted Wazuh-to-case-to-investigation-to-report workflow | BLOCKED | Authorized SATARK tenant/case/actor and successful end-to-end run with checkpoint/restart/idempotency verification |
| Worker operational recovery | NOT RUN | Private persistent host, restart/retry test, monitoring and backup/restore drill |
| Response execution | SIMULATION ONLY | Live containment remains disabled; any future enablement needs durable human approval, scoped authorization, rollback and an approved lab |
| Desktop/mobile and production browser smoke on current main | NOT VERIFIED | Exact-SHA deployment plus browser/accessibility evidence |

## Required next steps

1. Finish PR #165 checks and merge only if CI, CodeQL, and isolated migration validation all pass.
2. In a trusted CLI environment, run the exact migration-history repair documented in `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`; do not alter other migration versions.
3. Resolve Vercel's deployment quota through the account/plan owner, then deploy current main to preview, smoke-test it, and only then promote to production with explicit approval.
4. Provision an authorized Wazuh lab endpoint and a separate SATARK test tenant/case/actor; validate real ingestion, checkpoint advancement, restart recovery, deduplication, source downloads, durable investigation, reports and tenant isolation.
5. Deploy the workers to a private persistent runtime and complete monitoring, backup/restore and recovery drills.
6. Keep live response disabled until a separately reviewed and tested approval/execution workflow exists.

## Sign-off

- Final status: **BLOCKED — implementation and several PR checks are verified, but current-main production deployment, live Wazuh end-to-end execution, migration-history repair, and operational recovery are not verified.**
- Human release owner: not assigned in this record.
- Rollback/restore drill: not verified.
- No claim of production readiness or forensic certification is made.
