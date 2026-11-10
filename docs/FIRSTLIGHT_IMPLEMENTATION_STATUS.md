# Current implementation addendum — 2026-11-11

This addendum describes the current self-hosted candidate branch fix/satark-firstlight-end-to-end-2026-11-11. It supersedes older Supabase-backed architecture notes below where they conflict; the historical notes are retained only for audit traceability.

## Current product state

- **SATARK Android File Guard:** native Android shell, embedded Python inspection engine, Share-to-SATARK, system file picker, SAF folder grants, bounded WorkManager scans, local scan history, local evidence export, and a pinned EMBER2024 APK training hash snapshot. The Android manifest has no Internet permission. Physical-device behavior and production signing remain separate acceptance gates.
- **SATARK self-hosted application backend:** SQLAlchemy persistence supports PostgreSQL or local SQLite; private evidence objects are stored under SATARK_EVIDENCE_DIR. The current runtime does not require Supabase. Local Compose uses a persistent satark_data volume.
- **FIRSTLIGHT deterministic engine:** evidence sealing/verification, deterministic rule registry, evidence prioritization, event timeline, correlation, gaps, bounded imports and report generation are implemented with tests.
- **FIRSTLIGHT authenticated workspace:** the Next.js workspace uses the same-origin server proxy and self-hosted SATARK session cookies. Cases, memberships, notes, evidence, findings, reports, approvals, audit events and investigation jobs are backed by the self-hosted API/database.
- **FIRSTLIGHT durable investigations:** API enqueue/status routes and a persistent worker process case evidence, save findings and report snapshots, and record result digests. The worker shares the API database and private evidence directory.
- **FIRSTLIGHT Wazuh:** bounded read-only preview plus an optional persistent private worker with agent allowlisting, source-object preservation, overlap windows and durable checkpoints. Real Indexer connectivity still requires operator credentials and a lab endpoint.
- **FIRSTLIGHT response:** the candidate branch integrates the durable SQLite response ledger into authenticated API routes and the persistent case UI. Requests are case-bound; approval requires a different operator; execution requires a third operator and exact target confirmation; provider submission is distinct from independent verification. The feature flag remains disabled by default. Mocked tests do not prove real Microsoft tenant connectivity.
- **Optional model analysis:** local Ollama specialists can run in direct and durable background investigations. Their output is advisory only; deterministic findings remain authoritative and no paid hosted AI API is required for core FIRSTLIGHT operation.

## Candidate changes in this branch

- Replaced the Android emulator smoke test's POSIX-shell loop with a bounded Python polling script. The previous GitHub Actions log showed the emulator booted, installed and launched SATARK successfully, then failed at shell parsing before checking the UI. The new script checks the accessibility hierarchy and fatal Python/Android crash markers.
- Added authenticated FIRSTLIGHT response status, request, decision, execute, verify and audit endpoints.
- Added a persistent case-scoped approval listing to the response ledger, provider action references, startup recovery of interrupted executions, and a Next.js operator panel.
- Added regression tests for disabled-by-default execution, four-eyes approval, third-party execution, independent operator attestation and audit-chain verification.
- Updated README and FIRSTLIGHT runbooks to describe the self-hosted backend instead of obsolete Supabase runtime configuration.

## Release gates still open

- Exact-head CI, CodeQL, Android build/emulator checks and web/browser tests must pass on the final candidate SHA.
- Run a clean local installation and a full SATARK/FIRSTLIGHT browser workflow against the exact candidate SHA.
- Validate Android share intents and SAF grants/revocation on real WhatsApp/Telegram and supported OEM devices; emulator smoke is not a substitute.
- Run an independently labelled real-file corpus evaluation and record detection coverage/false-positive metrics. EMBER metadata is not proof of antivirus performance.
- Run the Wazuh worker against an authorized lab Indexer with a real alert; verify persisted source bytes, checkpoint advancement, restart recovery and membership enforcement.
- Run the Microsoft response lifecycle only in an authorized disposable tenant/device/account. Verify provider-side state, recovery/unisolation and audit references. Do not enable the feature flag in production before that review.
- Run an isolated backup/restore drill covering the self-hosted database, evidence directory and response ledger.
- Configure production TLS, secrets, durable volumes, SMTP/MFA policy as required, backup retention, monitoring, signing and release disclosures.
- Verify the exact deployed revision and perform post-deploy smoke/recovery tests. A CI artifact or READY deployment alone is not proof of production readiness.

**Current decision:** implementation is substantially integrated, but production readiness remains NO-GO until the exact-head automated checks and externally dependent lab/operational gates above are evidenced. No real Microsoft action, Wazuh connection, production deployment, or physical-device test is claimed by this addendum.

---

## Historical audit log — superseded architecture snapshots

The records below preserve earlier October 2026 audit findings, including the former shared-Supabase architecture. They are historical evidence only and are not current deployment instructions. Use the 2026-11-11 addendum above and the current self-hosted runbooks for the present architecture.

# FIRSTLIGHT implementation status

## PR #217 audit continuation — 2026-10-21 UTC

This addendum is scoped to branch `ops/track1-readiness-audit`; it does not replace the main-branch baseline above.

- **Audit branch head before this documentation update:** `278a7acd1c8f9de4a1b79608035f09a50b5dedc7`.
- **Nirdhoom (SATARK schema work):** live catalog checks confirm SATARK approval RPC wrappers use `SECURITY INVOKER`, direct approval consumption is disabled for `anon`, `authenticated`, and `service_role`, membership-sensitive policies use `satark_private.has_membership`, and the five intended foreign-key support indexes exist. The security advisor reports one intentional worker-private checkpoint-table notice and nine SECURITY DEFINER warnings on unrelated Nirdhoom application functions; those unrelated functions were not changed.
- **Saathi (testing only):** `satark_rpc_hardening.test.sql` previously passed 30/30 assertions. `satark_security.test.sql` was also executed against Saathi with a transaction-scoped result-capture harness: all 50 assertions returned `ok`, with no `not ok` results. Post-run queries verified zero persistent test tenants, cases, evidence, findings, or storage objects, and the transaction-created `satark-evidence` bucket was absent after rollback. The capture table/grant were also rolled back.
- **Isolated migration/security CI:** [run 39479567883](https://github.com/kaustubhdua/Satark/actions/runs/39479567883) passed clean-database migration application, migration-state verification, and database security regression tests. Four SQL test files passed, 113 tests total.
- **FIRSTLIGHT API CI:** [run 39479567938](https://github.com/kaustubhdua/Satark/actions/runs/39479567938) passed 114 tests, built all three API/worker Docker images, and passed runtime import checks. [CodeQL](https://github.com/kaustubhdua/Satark/actions/runs/39479567808) and [Web CI](https://github.com/kaustubhdua/Satark/actions/runs/39479567718) also passed on that code candidate.
- **Exact-head verification after the latest documentation change:** fresh CI, CodeQL, Web CI, and isolated migration validation are running on `278a7acd1c8f9de4a1b79608035f09a50b5dedc7`; do not mark those checks complete until their runs finish.
- **Still blocked:** the application-level tenant-isolation CI job fails its preflight because the dedicated Saathi test-account Actions secrets are missing. Its actual authenticated RLS tests are skipped, not passed. The live Wazuh API and persistent-worker acceptance probes have not been run against authorized real telemetry. Microsoft Defender/Entra actions have not been executed against an authorized test tenant, and no durable case-bound response executor is released. No SATARK production deployment has been verified.
- **Current release decision:** NO-GO. Keep PR #217 draft and unmerged until exact-head checks finish, tenant isolation runs with dedicated least-privilege identities, live Wazuh evidence/checkpoint acceptance passes, and a case-bound response is verified against an authorized Microsoft test environment.
- **Research anchors:** [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) for incident response; [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html) for real alert access; [Supabase database testing](https://supabase.com/docs/guides/database/testing) and [RLS guidance](https://supabase.com/docs/guides/database/postgres/row-level-security); [Defender isolation API](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine) and [Graph revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0).

---

Last reviewed: 2026-10-20 (UTC; main SHA `cc250e13ef0cd9d5e8f77a832e87617365a65ddf`)

## Latest release-gate recheck — 2026-10-20 17:10 UTC

This section supersedes any older “latest SHA” wording below. The detailed historical notes remain for traceability.

- **Current main:** `cc250e13ef0cd9d5e8f77a832e87617365a65ddf`. This includes the merge of PR #216, which documents the operator-approved Saathi project scope for SATARK integration testing.
- **CI on current main:** run [39463290850](https://github.com/kaustubhdua/Satark/actions/runs/39463290850) failed only in the **Supabase tenant-isolation integration** job's “Check dedicated least-privilege test accounts” preflight. Python validation, Next.js web validation, and browser/accessibility smoke completed successfully. The actual tenant/RLS integration tests did **not** run because required test-account secrets were empty. This is BLOCKED by configuration, not a passing isolation test.
- **CodeQL on current main:** [run 39463290881](https://github.com/kaustubhdua/Satark/actions/runs/39463290881) succeeded.
- **Production smoke on current main:** [run 39463560886](https://github.com/kaustubhdua/Satark/actions/runs/39463560886) failed. Production must not be considered verified from this run.
- **Saathi test environment:** project ref `ibvgxgvcqcfnoyrlwywa` is the selected SATARK test environment by explicit operator approval. The approved scope does not authorize destructive resets or changes to Saathi-owned tables, Auth users, storage, secrets, or workflows. PR #216 documents the read-only baseline and required safe setup. No test identities, tenant fixtures, secrets, or schema changes were created by that documentation change.
- **Current decision:** NO-GO for claiming full release readiness. Next required operator steps are to provision the three dedicated ordinary test identities and distinct SATARK-only tenant fixtures, configure the repository Actions secrets listed in `docs/SAATHI_SATARK_TEST_ENVIRONMENT.md`, reconcile the live migration ledger against the repository, then rerun the exact-commit tenant-isolation tests without skipping. Production deployment identity and smoke verification remain separate gates.
- **Network/repository access limitation for this review:** a local Git clone attempt failed because the execution environment could not resolve `github.com`. This review therefore used the GitHub repository API and recorded workflow metadata; it did not claim a local clean-clone test run.

---


## Repository-wide Track 1 capability matrix — rechecked 2026-10-20 17:53 UTC

Review scope: the recursive Git tree at main SHA `cc250e13ef0cd9d5e8f77a832e87617365a65ddf`, the core FIRSTLIGHT Python modules, selected Next.js API routes/auth helpers, migration history repair notes, and workflow jobs for PR #217. This is a repository/API-based review, not a clean local checkout; the local runtime could not resolve github.com. Do not interpret source presence or a green unit-test job as proof of production integration.

| Area | Evidence/status | Remaining acceptance evidence |
|---|---|---|
| Entry points and architecture | **Implemented; partially verified.** Streamlit app (`satark.py`), shared FastAPI service (`firstlight_api.py`), deterministic engine/rules/ingestion modules, Wazuh connector/worker, optional Ollama analysis agents, and a separate Next.js analyst UI/API are present. | Run a fresh clone locally and trace a single scenario across all intended paths. Keep Streamlit, API, worker, and Next.js responsibilities documented as separate runtime entry points. |
| Reproducible baseline | **CI-tested, local clean install blocked.** PR #217 CI run [39469688235](https://github.com/kaustubhdua/Satark/actions/runs/39469688235): Python validation/regression, Next.js validation/build, and browser/accessibility smoke passed. | Run dependency install, tests, lint/type checks and build from a clean clone on a supported local host; preserve logs and exact SHA. |
| Capability inventory | **Partially documented; this table is the refreshed summary.** Existing status and release docs contain historical notes, some of which refer to older main SHAs. | Reconcile all historical status sections after a clean-clone audit; label each capability implemented-and-tested, implemented-but-untested, partial, simulated, missing, or externally blocked. |
| Event ingestion and normalization | **Implemented and unit-tested in CI.** `firstlight_ingest.py` provides bounded JSON/CSV parsing, field aliases, timestamp normalization, details limits and duplicate handling; Wazuh adapter/worker exists. | Demonstrate real Wazuh lab/export ingestion with preserved source provenance, late/malformed event behavior, and durable checkpoint recovery. |
| Deterministic detection/correlation | **Implemented; tested at unit/regression level.** `firstlight_rules.py` and `firstlight_engine.py` provide rule metadata, evidence-linked analysis and synthetic demo case. | Run labeled benign/suspicious scenarios and report measured precision, recall, false positives, correlation completeness and ATT&CK mapping review. |
| Agentic investigation | **Partially implemented.** Optional local Ollama specialists have bounded evidence, structured Pydantic output and no executable tools; deterministic investigation remains the fallback. | Demonstrate orchestrator state/deadlines/cancellation/retry bounds and a complete investigation from imported telemetry through persisted result. Record Ollama unavailable/timeout/malformed-output behavior. |
| Evidence integrity and reporting | **Implemented; CI regression-tested.** Canonical SHA-256 records, integrity results, evidence references and report/API paths exist. | Verify export manifests and chain-of-custody events end to end; deliberately tamper with stored/exported evidence and capture detection results. A hash proves byte consistency, not source authenticity. |
| Response/approval | **Simulation-only by design; partial release evidence.** Persistent approval APIs/migrations exist; live response actions are not authorized in this review. | Prove all approval states, expiry, replay/idempotency, authorization re-check at execution, outcome verification and recovery using isolated fixtures. No live containment until separately authorized and lab-scoped. |
| UI/backend authentication | **Implemented in code; browser/build tested.** Next.js routes validate Supabase user tokens and use server-side database access with caller bearer tokens. | Validate every case/evidence/report/approval route against real least-privilege accounts and two distinct tenants; UI smoke is not proof of RLS isolation. |
| Database/RLS/migrations | **Externally blocked / no-go.** Existing migrations and pgTAP contracts are present. Current CI's dedicated tenant-isolation preflight failed because required test account secrets are absent; actual tests were skipped. Live shared project migration ledger differs from repository history. | Use an isolated non-production test project or a carefully scoped, explicitly approved SATARK-only test setup; inspect migration list and dry-run, reconcile history, and run RLS/role tests without skips. Never reset or broadly migrate the shared Saathi project. |
| CI/security checks | **Partially verified.** Python and Next.js validation/browser jobs passed on PR #217; CodeQL run [39469688069](https://github.com/kaustubhdua/Satark/actions/runs/39469688069) passed. The overall CI is red because tenant-test credentials are missing. | Configure dedicated least-privilege test identities and tenant fixtures, then require the integration job to pass. Check dependency/security jobs and the exact release SHA. |
| Production/deployment | **Blocked / not verified.** Prior production smoke on base main failed ([39463560886](https://github.com/kaustubhdua/Satark/actions/runs/39463560886)); no production verification for PR #217's head SHA is established. | Resolve protected-domain/alias access and deployment quota through the owner-approved route, verify deployed SHA, then run smoke and recovery tests against that exact release. |
| Cost/offline requirement | **Core deterministic path is local/open-source-oriented; external integrations are optional.** Ollama and Wazuh require local operator setup; Supabase/Vercel deployment uses external services. | Demonstrate the synthetic end-to-end demo without paid AI APIs; disclose which hosted app/deployment capabilities still require configured services. |

### Current PR #217 verification

- CI run [39469688235](https://github.com/kaustubhdua/Satark/actions/runs/39469688235): Python validation/regression **passed**; Next.js validation/build **passed**; browser/accessibility smoke **passed**; tenant-isolation integration **failed at credential preflight** and the actual integration test step was skipped.
- CodeQL run [39469688069](https://github.com/kaustubhdua/Satark/actions/runs/39469688069): **passed**.
- PR #217 remains a documentation-only draft and does not fix the underlying tenant credentials, live migration mismatch, or production smoke failure.

### Release decision

**NO-GO for a fully verified submission/release.** The codebase has substantial existing foundations; the highest-risk gaps are operational proof, tenant-isolation tests, migration-history reconciliation, end-to-end telemetry-to-case acceptance, and exact-SHA deployment verification. Do not mark these complete until the corresponding evidence is recorded. No live database mutation, credential creation, response execution, production deployment, or destructive operation was performed in this review.

---

## Current source and release status

- Latest `main` SHA observed during the 2026-10-20 audit: `d4c5bbcdaf321107538bc9fc64fbbab0e6b0cce7`. Its CI run `39455018315` passed the Python validation, Next.js web validation, and production browser/accessibility smoke jobs; the Supabase tenant-isolation job failed at the credential preflight because all dedicated test-account values were empty, so the actual RLS tests were skipped. This is a release blocker, not a successful tenant-isolation result. Check CodeQL on this exact SHA before release.
- PR #174 merged with the policy-rebind migration after its exact-head CI, CodeQL, isolated Supabase migration validation, web validation, and browser/accessibility smoke passed. The post-merge checks on `7f426fe793ab78375094111b7fed8462e669e018` passed; later source changes mean the current main CI and CodeQL must be rechecked before release.
- PR #173 is merged: successful empty Wazuh query windows advance the durable checkpoint to the drained window boundary, while failed polls preserve the prior cursor. Its API regression tests, CodeQL, web validation, and browser/accessibility smoke passed.
- PR #177 added cross-tenant read/write denial coverage for case notes, investigation jobs, and approvals; its 50-assertion pgTAP suite, CodeQL, and isolated migration validation passed. PR #178 added policy contract checks and a production-smoke marker guard; its isolated migration validation and production-smoke contract check passed.
- PR #180 is merged with per-poll, per-page, and checkpoint-boundary membership revalidation for the long-running Wazuh worker. Its FIRSTLIGHT API CI passed; current-main CI and CodeQL are still running at this review.
- The latest observed READY production deployment is `dpl_Ean9MzChDZP2aGXP1HNwMkzVhJir`, aliased as `satark-rose.vercel.app` / `satark-jyc-website.vercel.app`, at source SHA `e2b6f003d50521c7fa2e83c2c3b2a81192af309c` (documentation-only main revision before PR #185). It predates the main SHA `7ed7c60fc56227e341fef16d43c5b005cc9bcb04` that most recently attempted deployment before the Vercel rate limit; main has since advanced, and no deployment of those later revisions is verified. The production smoke run `39377120818` failed because the live `/` response did not contain the expected homepage marker; the current main deployment attempt was separately rate-limited (`build-rate-limit`) on `7ed7c60fc56227e341fef16d43c5b005cc9bcb04`. The Vercel project reports SSO protection enabled for all non-custom domains, so the failed homepage marker may be a protection/login response rather than a stale HTML build. The connected Vercel tool can inspect the project and deployment metadata but returns HTTP 403 when listing alias mappings or fetching the protected alias, so the live alias target could not be independently verified. PR #188 adds support for a narrowly scoped `SATARK_VERCEL_PROTECTION_BYPASS` GitHub Actions secret, restricted to the two reported SATARK Vercel aliases; the owner must configure that secret or provide an approved public custom domain. Do not disable SSO globally, bypass deployment quotas, or repeatedly retry while the quota is exhausted. A READY deployment is not proof that the exact current main SHA is in production.
- The current Vercel environment-variable inventory contains Supabase settings, Upstash settings, and optional Ollama settings, but no `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer credentials, or private worker-host configuration. No authorized Wazuh lab endpoint or SATARK tenant/case/member/actor is available.
- Read-only inspection of the approved shared Supabase project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) confirmed the SATARK tables had RLS enabled and zero rows at the time of the earlier audit. The project also hosts Nirdhoom and Saathi; do not reset it or create fake production data. The 2026-10-21 audit applied only SATARK-scoped approval-RPC/ACL changes; no Nirdhoom application tables or user data were modified.
- A read-only live policy audit confirms six approval, case-note, and investigation-job policies still reference `public.satark_has_membership`, whose EXECUTE grant is revoked for authenticated users. These operations can fail closed until migration `20261020051000` is applied. The checkpoint table's no-policy advisor finding is intentional: `anon` and `authenticated` have no table privileges, and the private worker uses service-role access.
- Migration history still needs the guarded operator repair described in `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`. The live private-RPC implementation and approval-consumption ACL changes are now recorded in Nirdhoom as `20261020184208` and `20261020184213`; source reconciliation files were added. The existing support-index and policy-rebind migration state still needs a trusted CLI dry-run and repair review. Do not run a broad `supabase db push`; confirm the linked project and exact dry-run first.
- **Release decision: NO-GO for production use** despite passing code checks: migration history must be reconciled and the exact pending-migration dry-run verified; the current approved main SHA must be deployed and verified after the Vercel quota clears; required API/Wazuh configuration and a private worker must be provisioned; and an authorized real end-to-end ingestion-to-report test plus recovery/backup verification must succeed. Keep live response actions disabled.

This status describes repository-backed behavior and explicitly lists external configuration gates; passing CI does not prove live-provider or production readiness.

## Earlier verified release-gate status (2026-10-20; pre-PR #174)

- Earlier audit: the Wazuh checkpoint migration was applied to the approved shared Supabase project `nihdhoom` after inspecting the existing SATARK schema, migration history, foreign keys, existing Wazuh evidence, and index conflicts. The checkpoint table has forced RLS with no `anon`/`authenticated` privileges; the duplicate-protection index is present. Its no-policy advisor notice is intentional because only the private worker/service role should access it. The 2026-10-21 follow-up used Saathi as the designated test project and did not insert persistent SATARK fixtures.
- Read-only table inspection confirms the live project currently has zero rows in all 11 SATARK data tables, including tenants, memberships, cases, evidence, ingestion checkpoints, investigation jobs, case notes, and approvals. The private `satark-evidence` bucket exists with a 4 MiB object limit. Do not create fake production tenant/case/user records to bypass this gate.
- The investigation API fails closed when `FIRSTLIGHT_API_TOKEN` is missing or shorter than 32 characters. The Next.js proxy requires the strong token even for local HTTP. The worker and authenticated source-download route enforce the bucket's 4 MiB object limit. PR #170 also fixes local Compose Supabase auth configuration; its recorded API CI, general CI, Web CI, CodeQL and browser/accessibility smoke checks passed. Its tenant-isolation job reported success but skipped the live-account test step.
- Added a versioned deterministic rule registry (`firstlight_rules.py`, version `1.0.0`) with stable rule IDs, cautious candidate ATT&CK mappings and rule limitations. Its API container copy and CI path triggers were updated.
- The Wazuh integration is merged in PR #160; its FIRSTLIGHT API CI, CodeQL, general CI, Web CI, and isolated migration validation passed on that PR head. PR #161 and PR #164 storage-policy cleanup checks passed; PR #167's object-key regression test and PR #168's SATARK foreign-key indexes also passed their exact-head CI, Web CI, CodeQL and isolated migration checks.
- Vercel currently has an older production deployment at SHA `21abd4c7466cb7490ae1acb372d04008f72e40d5`; the latest available deployment is a READY preview for branch `feat/firstlight-wazuh-rebased` at SHA `a6ad65ea910c40362bb9005febb447893776002f`. A new deployment attempt was blocked by HTTP 402 `api-deployments-free-per-day` with a 24-hour retry window; the runtime-error API returned 403. The production environment inventory lacks `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN` and Wazuh Indexer configuration. No authorized Wazuh endpoint/credentials or SATARK test tenant/case/actor exists; all 11 SATARK data tables currently contain zero rows, so real end-to-end ingestion remains blocked.

## Latest validation after live acceptance probe addition

- FIRSTLIGHT API CI passed on commit `a36d9755962730463f9231f2eaa5ef347c695094` in [workflow run 39475104883](https://github.com/kaustubhdua/Satark/actions/runs/39475104883). The full shared API/engine pytest command passed, all three API/worker Docker builds succeeded, and runtime imports passed inside the images. This includes the live acceptance validator unit tests; it does **not** mean the live acceptance probe was run against Wazuh.
- CodeQL and general CI had not completed at the time of this status update. The Vercel status on the candidate SHA remains failed with the existing build-rate-limit condition. Keep the release gate closed until those results and the required real infrastructure tests are resolved.

## Latest CI after acceptance probes (2026-10-21)

- FIRSTLIGHT API CI passed on latest head `b5a88248546e26bda68766aea0de5dceec029e6e` in [workflow run 39478121042](https://github.com/kaustubhdua/Satark/actions/runs/39478121042): 114 tests passed, all three API/worker Docker images built, and runtime imports passed. This includes unit tests for both acceptance validators, not a live Wazuh or Supabase acceptance run.
- CodeQL was still running on the latest head at the last check. The clean-database migration/security workflow was running; its previous run completed all migration/security test steps successfully but was cancelled at the workflow level during concurrent updates. The general CI's Supabase tenant-isolation preflight remains an external release gate because dedicated least-privilege test credentials have not been configured; actual GitHub RLS tests are skipped for that reason.

## Live Supabase approval hardening and test results (2026-10-21)

- Applied `20261020052000_satark_private_approval_rpc_implementations.sql` and the follow-up approval-consumption ACL hardening to the live Nirdhoom Supabase project. The live migration history records the implementation at `20261020184208` and ACL hardening at `20261020184213`; source reconciliation migrations were added so the recorded versions are represented in Git. See `docs/SUPABASE_ACCEPTANCE_2026-10-21.md`.
- Re-queried the live catalogs in Nirdhoom and Saathi: the public approval/assignment wrappers are `SECURITY INVOKER`; the public and private approval-consumption functions are not executable by `anon`, `authenticated`, or `service_role`. Nirdhoom approval, case-note, and investigation-job membership policies now use the non-exposed `satark_private.has_membership` helper; five SATARK foreign-key support indexes are present.
- Used Saathi Supabase as the test environment. The checkpoint table is forced-RLS with no API-role grants; the Wazuh source-document uniqueness index exists. Updated `supabase/tests/satark_rpc_hardening.test.sql` passed **30/30 pgTAP assertions** on Saathi, and post-test row counts confirmed all SATARK test tables were empty after rollback.
- The Supabase security advisor's no-policy notice for `satark_ingestion_checkpoints` is intentional: the trusted worker uses service-role credentials, and no client policy should be added. Unrelated Nirdhoom application security-definer findings were left untouched.
- The latest isolated clean-database migration/security workflow passed: all migrations applied to a clean local Supabase instance, migration state verification passed, and all database security regression tests passed. CodeQL, FIRSTLIGHT API CI (114 tests), Web CI, Python tests, and browser/accessibility smoke checks passed on the current candidate.
- The only failing CI job is the app-level tenant-isolation integration preflight. Configure these protected GitHub Actions secrets with dedicated Saathi test identities and tenant IDs: `SATARK_TEST_SUPABASE_URL`, `SATARK_TEST_SUPABASE_PUBLISHABLE_KEY`, `SATARK_TEST_USER_A_EMAIL`, `SATARK_TEST_USER_A_PASSWORD`, `SATARK_TEST_TENANT_A_ID`, `SATARK_TEST_USER_B_EMAIL`, `SATARK_TEST_USER_B_PASSWORD`, `SATARK_TEST_TENANT_B_ID`, `SATARK_TEST_VIEWER_EMAIL`, `SATARK_TEST_VIEWER_PASSWORD`, and `SATARK_TEST_VIEWER_TENANT_ID`. Until then, the app-level RLS tests are skipped. These database tests do not prove live Wazuh ingestion or provider response.

## Persistent worker acceptance probe (2026-10-21)

- Added `scripts/accept_firstlight_worker_live.py` as an explicitly gated, real-write acceptance probe for the persistent Wazuh worker. It requires exact confirmation of the configured tenant and case IDs plus `FIRSTLIGHT_WAZUH_ACCEPTANCE_ALLOW_WRITES=I_AUTHORIZE_WRITES_TO_THIS_TEST_CASE`; it must be used only with a dedicated isolated test tenant/case.
- The probe runs one actual worker poll, reads the durable checkpoint and Wazuh evidence rows back, re-fetches up to ten preserved source objects, and verifies each object's bytes against its stored SHA-256 digest. It refuses to pass when the poll fetches zero real alerts, the checkpoint does not match, evidence is absent, or source-object verification fails. It performs no response action and creates no synthetic events.
- Added fail-closed unit tests and included them in FIRSTLIGHT API CI path filters and test command. The latest FIRSTLIGHT API CI run passed 114 tests, built all three API/worker Docker images, and passed runtime import checks. These are unit tests of acceptance logic, not a live Wazuh/Supabase ingestion run.
- Detailed scope and operator precautions are documented in `docs/FIRSTLIGHT_WAZUH_API.md`; the evidence-based release checklist is `docs/TRACK_1_COMPLETION_PLAN.md`.

## Reproducible live acceptance probe (2026-10-20)

- Added `scripts/accept_firstlight_wazuh_live.py` and regression tests in `tests/test_firstlight_wazuh_live_acceptance.py`. The probe calls the configured API and refuses an empty alert result; it never seeds events or uses the fictional demo case as a fallback.
- The probe checks the response mode, read-only/no-persistence contract, evidence ID binding, Wazuh source identity, index/document/source-snapshot provenance, canonical normalized-record SHA-256 values, and investigation/case ID binding.
- Added the acceptance-validator tests to FIRSTLIGHT API CI and documented safe execution in `docs/FIRSTLIGHT_WAZUH_API.md`. The probe itself has **not** been run against a real Wazuh tenant because this audit has no authorized live endpoint/credentials. Passing its unit tests is not live connectivity evidence.
- Corrected the `firstlight_api.py` module docstring to distinguish the caller-supplied case endpoint from the real, configured read-only Wazuh routes.

## Additional live Wazuh API path (2026-10-20)

- Added `POST /api/v1/integrations/wazuh/investigate`, an authenticated read-only path that queries the configured Wazuh Indexer, enforces the configured tenant UUID and bounded result count, computes evidence digests over normalized source records, and runs the canonical deterministic investigation engine. Optional model agents remain advisory.
- Added API contract tests for authentication, tenant mismatch, bounded page size, evidence/result shape, and empty results. The CI FIRSTLIGHT pytest command includes the new API tests plus the Wazuh connector, CLI investigation, guarded response CLI, and offline demo regression tests.
- Added `docs/FIRSTLIGHT_WAZUH_API.md` with environment variables, endpoint contract, least-privilege requirements and integrity limitations.

This is implementation plus regression coverage, not proof of live connectivity. The endpoint deliberately does not persist a case, create a durable checkpoint, or execute response actions. The API tests mock the connector response; live acceptance still requires a real authorized Wazuh Indexer and source event IDs. Do not describe the endpoint as production-ready until those tests and the dedicated tenant-isolation/release gates pass.

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

- Applied the previously missing durable approval schema to the approved shared Supabase project, then enforced a database CHECK constraint that permits only `simulation.*` action keys with `action_payload.mode = 'simulation'`. The table has RLS and FORCE RLS enabled, member-read/request policies, immutable action parameters, non-self-approval, expiry checks, and transactional hash-chain audit entries. As of 2026-10-21, direct approval consumption is intentionally disabled until a trusted executor exists. Live verification found zero approval rows and zero non-simulation rows.
- Reconciled the approval migration filenames with the exact versions recorded in live Supabase migration history (`20261020035814`, `20261020035832`, `20261020035848`, `20261020040028`). Added an explicit ACL migration revoking direct execution of the approval trigger function from API roles; live ACL inspection confirmed the trigger-only function no longer grants EXECUTE to anon/authenticated/service_role.
- Tightened the approval API to accept only the explicit simulation action namespace and require a simulation-mode payload before it attempts persistence. Live response remains disabled; approval records do not execute endpoint actions.
- Fixed the Wazuh worker container to include the deterministic engine and versioned rule registry that its runtime imports. Docker image build success alone had not caught this runtime-import omission.
- Wired the optional FIRSTLIGHT API Ollama configuration to the local Compose service using `OLLAMA_BASE_URL`, `FIRSTLIGHT_OLLAMA_MODEL`, and an opt-in `FIRSTLIGHT_MODEL_AGENTS_ENABLED=false` default. The model remains advisory and deterministic findings do not depend on it.
- Redacted Wazuh worker error output to stable error categories so provider exception text, URLs, or credentials cannot be copied into logs/checkpoints. Added a regression test for secret-bearing exceptions.

**Still blocked from a genuine end-to-end release:** no authorized Wazuh Indexer endpoint/credentials or enrolled lab agent is configured; the live shared project has no SATARK tenant/case/member/actor records; real Supabase tenant-isolation tests need dedicated least-privilege test identities; Vercel's deployment quota currently blocks a fresh deploy and the production SHA is older than main. No evidence-object backup/restore drill, real Wazuh-to-UI smoke test, or real response executor has been verified. Keep live response disabled and do not mark this branch production-ready.

## Follow-up hardening verified in source and shared schema (2026-10-20)

- Durable approval records are constrained to the `simulation.*` action namespace and `action_payload.mode = 'simulation'`. RLS/FORCE RLS, member-read/request policies, immutable request parameters, non-self-approval, expiry checks, and transactional hash-chain audit entries are present. Approval-consumption RPCs are intentionally not executable by API roles or service_role until a trusted response executor exists. Read-only live inspection found zero approval rows and no non-simulation approval rows.
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
