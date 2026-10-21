# SATARK Track 1 execution audit — 2026-10-22

**Release decision: NO-GO.** This is an evidence-backed status snapshot, not a declaration of completion. Do not promote production or enable real response until the blocked gates below pass on the exact release commit.

## Repository and truth boundary

This audit applies to `kaustubhdua/Satark`. NIRDHOOM and Saathi are separate applications; do not treat their repositories as the SATARK implementation. The SATARK README describes the current product as an evidence-led investigation/triage prototype. Its FIRSTLIGHT demo incident is synthetic, its session audit chain is not independently anchored chain-of-custody evidence, and optional Microsoft response adapters are not yet live-validated/connected to the simulated approval UI.

## Evidence observed

All timestamps are GitHub workflow timestamps in UTC.

| Check | Run | Observed result | Meaning |
|---|---|---|---|
| CI | [39517199459](https://github.com/kaustubhdua/Satark/actions/runs/39517199459) | Failed | Web/unit/type/build jobs passed; `Supabase tenant-isolation integration` failed at `Check dedicated least-privilege test accounts`. Authenticated tenant isolation is not proven. |
| CodeQL | [39517199461](https://github.com/kaustubhdua/Satark/actions/runs/39517199461) | Success | Static security scan passed for the commit used by this run; it does not prove runtime authorization. |
| Isolated Supabase migration validation | [39517199461](https://github.com/kaustubhdua/Satark/actions/runs/39517199461) | Success | Isolated migration/security workflow passed; this does not reconcile production migration history or prove live user isolation. |
| Production smoke | [39571936463](https://github.com/kaustubhdua/Satark/actions/runs/39571936463) | Failed | Public pages and unauthenticated API denial checks passed. The workflow then reported production Supabase configuration missing/mismatched for expected project `igqgtlmnwssjaoxkkzbm`. Its release checks also require current deployment SHA, configured FIRSTLIGHT proxies, and shared rate limiting. |
| Earlier production smoke | [39517311415](https://github.com/kaustubhdua/Satark/actions/runs/39517311415) | Failed | Same release area requires investigation; do not infer production readiness from HTTP 200 page responses. |

The current main commit referenced by the observed CI/production runs is `cf01474c9819e055a5e00657ecab680181366714`. Re-check the branch head before using this audit for a later release.

## Mandatory blockers

### 1. Authenticated tenant isolation — BLOCKED

The CI tenant-isolation job failed before it could run the dedicated least-privilege account checks. Configure test-only identities and repository secrets listed in `docs/TRACK_1_RELEASE_RUNBOOK.md`, ensure each identity has only the intended tenant membership/role, and rerun the job. The actual authenticated test step must pass; skipped tests, schema catalog checks, or a green unrelated workflow are not substitutes.

Required evidence:
- preflight passes against the isolated test project;
- tenant A can access only tenant A data;
- tenant B can access only tenant B data;
- cross-tenant read/write attempts are denied for every persisted resource;
- viewer writes and unauthorized approval actions are denied;
- membership revocation removes access;
- logs contain no passwords, JWTs or service-role keys.

### 2. Production configuration and deployment — BLOCKED

The production smoke run reached public routes and confirmed unauthenticated case/finding/report requests are denied, but it failed the production Supabase configuration check. The same smoke script checks that the deployed commit equals the intended main SHA, FIRSTLIGHT investigation and Wazuh server-side proxies are configured, and the shared limiter is usable. When the shared limiter is absent, `/api/analyze` correctly fails closed with HTTP 503; this is secure degradation, not a passing production feature.

Required actions:
- inspect the current Vercel production environment and set only verified, environment-appropriate values for the correct SATARK project;
- keep service-role keys and internal API tokens server-side;
- configure the shared rate limiter and verify the live request path;
- deploy the approved SHA only after CI/security gates pass;
- rerun production smoke and verify the deployed SHA, health/readiness, authentication, proxy behavior, and analysis behavior.

Do not copy NIRDHOOM or Saathi credentials into SATARK. Do not invent values or paste secrets into this report.

### 3. Live Wazuh telemetry and persistent ingestion — BLOCKED

The repository contains a bounded read-only Wazuh connector, live acceptance scripts and a persistent worker, but the integration documentation explicitly states that the worker/live integration has not been verified against a real Wazuh server.

Required actions:
- start an isolated Wazuh manager/indexer and a real Linux/Windows test endpoint for a bounded test session;
- use a least-privilege read-only indexer account and an explicit agent allowlist;
- generate authorized benign events and confirm the alerts exist in Wazuh;
- run `scripts/accept_firstlight_wazuh_live.py` and the worker acceptance script with non-production credentials;
- verify nonzero real alert count, source/index/document IDs, source timestamps, preserved source snapshot bytes, digests, durable checkpoint advancement, duplicate replay idempotency, late-event handling, and restart/recovery;
- retain a sanitized session manifest and logs, then shut the lab down.

A saved JSON fixture, a mocked provider, an HTTP 202, a zero-alert result, or a replayed capture cannot be described as live Wazuh acceptance.

### 4. Real response execution — BLOCKED

`docs/FIRSTLIGHT_RESPONSE_EXECUTOR.md` says the local executor foundation is not connected to the browser approval UI or existing Supabase approval RPCs. Keep response execution disabled.

Required actions:
- authenticate the operator server-side and derive tenant/case/actor/role from trusted context, not browser-supplied claims;
- connect the server-side executor to durable approval state and the two allowlisted action adapters;
- bind exact action, target, parameters, payload digest, requester, approver, expiry and idempotency key;
- consume approval atomically before executing; reject expiry, replay, altered payload and requester/approver conflicts;
- record provider submission separately from provider-side verification;
- test a harmless action in an authorized disposable tenant and independently read back the provider-side result;
- reconcile timeouts/unknown outcomes rather than blindly retrying;
- keep the approval-consumption RPC unavailable to public/API roles until reviewed acceptance passes.

### 5. Migration-history reconciliation — BLOCKED until reviewed

Do not reset production, blanket-push migrations, or edit the migration ledger to silence drift. Follow `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`: inspect linked migration list and dry-run, compare every pending version to the live schema, rehearse on a disposable database, then apply only a reviewed migration plan. Preserve the current approval/RLS hardening.

### 6. Evidence integrity and AI evaluation — NEEDS ACCEPTANCE EVIDENCE

Code and local tests cover deterministic evidence hashing and analysis workflows, but final acceptance must prove persisted evidence integrity and distinguish live data, replayed captures, synthetic training fixtures, deterministic rules and optional model interpretation.

Required actions:
- export persisted evidence and independently recompute hashes;
- demonstrate altered/truncated records fail verification;
- verify source provenance and evidence-linked finding references;
- run positive and negative detection controls on held-out benign/malicious samples, report false positives/negatives and limitations;
- verify the UI labels AI output as advisory and displays uncertainty/evidence gaps;
- retain test commands, exact commit SHA, CI run URLs and sanitized results.

## Offline-first execution plan

No machine must run 24×7 just to complete development and acceptance.

1. Run unit, web, static-analysis, migration-rehearsal and captured-record replay tests locally or in CI.
2. Provision isolated test identities and secrets; run authenticated tenant tests in CI.
3. Start the Wazuh lab only for the bounded live-telemetry acceptance session. Verify ingestion/checkpoint/replay/recovery and save evidence.
4. Start an authorized disposable provider lab only for response acceptance. Independently verify provider-side state.
5. Stop temporary infrastructure and verify no unneeded billable resources remain.
6. Deploy only after all release gates pass. Continuous production monitoring, if desired, is a separate operational requirement and does require an always-available service.

## Definition of done

SATARK is not release-ready until all are evidenced on the exact release commit:
- CI, Web CI, CodeQL and isolated migration validation pass;
- authenticated tenant/role isolation tests actually run and pass;
- production Supabase/proxy/shared-rate-limiter configuration is correct and production smoke passes;
- genuine Wazuh alerts traverse the persistent worker with source identity, digest, checkpoint and recovery verified;
- response execution is approval-bound, single-use, audited and independently verified in an authorized lab;
- schema/migration reconciliation is reviewed and reproducible;
- evidence integrity and detection positive/negative controls pass;
- deployed commit SHA, readiness, authentication and rollback/restore are verified;
- the final evidence bundle clearly separates real telemetry, replay, fixtures and synthetic demo data.

**Do not change any blocker to PASS without attaching the corresponding artifact or workflow evidence.**
