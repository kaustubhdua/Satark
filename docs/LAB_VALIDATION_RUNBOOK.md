# SATARK / FIRSTLIGHT Lab Validation Runbook

This runbook defines operator-executed tests needed to produce evidence for P1–P7. It does not claim any live integration passed. Run commands only against a dedicated non-production environment unless a section explicitly describes a read-only production check.

## Stop conditions

Stop without writes if the Supabase project reference is not exactly the approved target, if a migration dry-run contains unexpected migrations, if a provider target is not a lab endpoint, if credentials are missing, or if the expected test step is skipped. Never paste secret values into issue comments, logs, or evidence artifacts.

## 1. Establish an evidence bundle

Record these metadata fields in a private/internal CI artifact:
- repository URL and exact commit SHA;
- UTC start/end times and environment name;
- CI workflow/run URL;
- tool/runtime versions;
- test command and exit code;
- redacted provider/project identifiers;
- test counts and failure summaries.

Do not include passwords, bearer tokens, service-role keys, raw customer telemetry, or unredacted incident evidence. A green parent job is not evidence if the required integration step was skipped.

## 2. P1 — tenant isolation and database parity

### Prerequisites
- Dedicated non-production Supabase project, not the shared project nihdhoom.
- Separate tenant-A and tenant-B users plus a viewer identity, with test-only data.
- GitHub Actions secrets configured as documented in SUPABASE_TENANT_TEST_SETUP.md.
- No production service-role key in browser or test output.

### Execution
1. Verify the test URL/project reference belongs to the dedicated test project.
2. Run the repository's tenant-isolation integration workflow.
3. Confirm the exact step named Run real Supabase tenant and role isolation tests concluded success; skipped, missing, or failure is a gate failure.
4. Verify tenant A cannot read, insert, update, or delete tenant B records; tenant B cannot access tenant A; viewer writes are rejected; same-tenant permitted reads work.
5. Run the RPC-hardening pgTAP suite in the isolated test database and verify effective EXECUTE grants, function security mode, and schema exposure.
6. Capture only redacted summaries and assertion counts.

### Shared database migration guard
For shared project igqgtlmnwssjaoxkkzbm, first obtain operator confirmation that this exact project is intended. Inspect supabase migration list --linked, verify the expected missing versions against docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md, and perform supabase db push --dry-run --linked. Do not apply anything unless the dry-run contains exactly the reviewed SATARK migrations in the documented order and the operator approves. A migration-history repair changes metadata and is not equivalent to executing migration SQL.

## 3. P2 — Wazuh telemetry round trip

In an isolated lab, enroll one authorized Windows endpoint and one authorized Linux endpoint. Record agent IDs in a private artifact. Generate a harmless test event for each endpoint, verify the event arrives with source timestamp and provenance, and then verify:
- duplicate batch replay does not duplicate durable events;
- restart resumes from the persisted checkpoint;
- transient manager failure retries with bounded backoff;
- invalid credentials and oversized/malformed responses fail safely;
- cross-tenant access is rejected;
- telemetry staleness is reported as unknown/unhealthy rather than zero alerts.

Do not use destructive malware, real credentials, or production endpoints for this test.

## 4. P3 — detections and correlation

For every enabled rule, keep a versioned positive fixture, a benign negative fixture, boundary cases, and expected severity. Replay fixtures through the same pipeline used for real lab events. Require deterministic results, rule/source provenance, duplicate suppression, and explicit handling of late or missing events. Report false positives and misses on a labelled corpus; do not claim efficacy from synthetic positive fixtures alone.

## 5. P4 — evidence integrity

In the isolated test environment:
1. Create an evidence record and deterministic export.
2. Verify the canonical SHA-256 independently using a second implementation.
3. Alter one byte, truncate a file, remove an item, reorder the manifest, and substitute a different evidence ID; each mutation must be detected.
4. Verify audit-chain continuity and tenant/case isolation.
5. Confirm unauthorized users cannot read or export another tenant's evidence.
6. Confirm the export contains a manifest with algorithm, canonicalization version, object IDs, lengths, hashes, and creation metadata.

## 6. P5 — local AI evaluation

Use a pinned local model and a held-out, labelled evaluation set. Include sufficient-evidence cases, insufficient-evidence cases, benign lookalikes, misleading telemetry text, and prompt-injection attempts. Require structured schema validation and citations to supplied evidence IDs. Measure unsupported-claim rate, task quality, latency, peak memory, timeout behavior, and model-unavailable behavior. Never send test data to a hosted provider unless separately approved.

Set pass thresholds before looking at final evaluation results. Preserve the evaluation-set version and model/prompt manifest with the results.

## 7. P6 — response provider sandbox

Keep live containment disabled. Use a provider sandbox or mock server that models provider state. Test exact action/target/parameter hash binding, approval expiry, one-time approval consumption, replay, concurrent duplicate requests, changed parameters after approval, timeout with unknown outcome, and independent provider-state lookup. Record provider request IDs and observed final state. A successful HTTP response alone is not proof of completed containment.

## 8. P7 — backup, restore, and release

- Back up only the isolated test environment first.
- Restore into a fresh isolated target and verify row counts, evidence hashes, tenant boundaries, and migration version.
- Record measured RPO/RTO; do not report a restore drill as passed until the restored system is queried and integrity checks pass.
- Verify CI/security/dependency/secret scans on the exact release SHA.
- Verify the deployed production SHA from deployment metadata, not from the latest Git branch.
- Run safe smoke tests: unauthenticated requests reject, authenticated tenant-scoped reads work, viewer restrictions hold, and health/readiness accurately reflect dependencies.
- Confirm rollback instructions and the responsible operator before release.

## 9. Evidence status vocabulary

- PASS — test executed in the stated environment, all assertions passed, evidence artifact recorded for exact SHA.
- FAIL — test executed and one or more assertions failed.
- BLOCKED — environment, authorization, or credentials unavailable.
- SKIPPED — test did not execute; counts as BLOCKED for release.
- UNVERIFIED — no adequate evidence is recorded.

No P1 or release gate may be marked PASS solely because a workflow's aggregate conclusion is green when its required integration step was skipped.
