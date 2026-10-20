# SATARK / FIRSTLIGHT — P0–P8 execution and release gates

This checklist is the source of truth for completing the platform. A source file, green build, mocked provider, skipped test, or manually supplied attestation is not proof that a live capability works.

## Rules for claiming completion

- Mark a gate **PASS** only when its listed evidence is recorded for the exact commit/environment.
- Use **BLOCKED** when credentials, authorized infrastructure, provider accounts, or operator approval are required.
- Use **FAIL** for a test that ran and failed. A skipped test is never a pass.
- Never place secrets, session tokens, private customer data, or production evidence payloads in this document or CI logs.
- Do not change shared Supabase schema/data until the linked project is positively identified and a reviewed dry-run shows only the intended SATARK migrations.
- Do not execute response/containment actions against production while provider verification and human-approval safeguards remain unproven.
- Release decisions must bind evidence to the exact Git commit SHA and environment.

## Current known blockers (from the latest recorded repository/CI audit)

- [ ] Dedicated non-production Supabase identities and repository Actions secrets are configured; the real PostgREST/RLS tenant-isolation suite executes and passes. Previously the integration step was skipped because credentials were absent.
- [ ] Shared Supabase migration history, five support indexes, six policy helper bindings, and function ACLs are verified after a guarded repair. The project is shared with Nirdhoom and Saathi; no database reset or blind push.
- [ ] Production deployment identity, exact deployed commit, and production smoke tests are verified. Vercel previously reported a build-rate-limit failure; a merged PR is not proof of deployment.
- [ ] Real authorized Windows and Linux Wazuh endpoints are available for end-to-end ingestion.
- [ ] Local model runtime and held-out AI evaluation corpus are available.
- [ ] Response-provider test accounts/sandbox and an authorized operator for approval-bound integration tests are available.
- [ ] Backup target and isolated restore environment are available.

## P0 — Repository inventory

- [ ] Generate the machine-readable inventory from the exact release candidate.
- [ ] Review all App Router pages, API routes, server actions, background jobs, scheduled tasks, database migrations/tables/functions/policies, provider adapters, tests, workflows, and environment-variable references.
- [ ] Map every user-facing action to its endpoint/server action, authorization check, tenant scope, persistence side effect, provider side effect, and tests.
- [ ] Verify capability registry reports configured/unverified/degraded/disabled accurately and never claims health without a live probe.
- [ ] Compare static inventory against deployed routes and the live schema using read-only evidence.
- **Evidence:** versioned inventory artifact, reviewed action map, schema snapshot/diff, and CI run URL tied to commit SHA.

## P1 — Security and tenancy

- [ ] Use a dedicated non-production Supabase project and distinct least-privilege users for tenants A/B and viewer role.
- [ ] Execute cross-tenant SELECT/INSERT/UPDATE/DELETE tests; verify unauthorized writes fail and foreign records remain unchanged.
- [ ] Verify same-tenant access and viewer write restrictions.
- [ ] Test RPC execute grants, SECURITY INVOKER/DEFINER boundaries, fixed search paths, storage policies, and audit/approval functions.
- [ ] Confirm exact linked project ref before migration operations; inspect migration ledger and run a dry-run that contains only reviewed SATARK migrations.
- [ ] Apply only the approved repair, then verify migration ledger, support indexes, policy helper references, and function ACLs.
- [ ] Complete a migration parity report and review security-advisor findings individually.
- [ ] Migrate browser session handling to secure HttpOnly cookies end-to-end; do not leave access/refresh tokens in localStorage. Keep the change atomic across sign-in, refresh, logout, and every caller.
- [ ] Test rate limits, request-size limits, CSRF/origin checks, auth expiry/revocation, and fail-closed behavior.
- **Evidence:** non-skipped integration logs, SQL/catalog verification, migration parity report, auth tests, and exact SHA.

## P2 — Wazuh ingestion

- [ ] Provision an authorized Wazuh manager and Windows/Linux agents in an isolated lab.
- [ ] Authenticate using server-side secret storage; never expose manager credentials in browser bundles or logs.
- [ ] Validate TLS, manager identity, least privilege, pagination, timeouts, bounded response sizes, retries/backoff, and rate limits.
- [ ] Persist durable checkpoints; make ingestion idempotent with stable event IDs/deduplication and explicit cursor semantics.
- [ ] Test restart/resume, duplicate batches, gaps, malformed events, provider outage, expired credentials, and clock skew.
- [ ] Verify tenant ownership for every ingested event and retain source timestamps/provenance.
- **Evidence:** redacted real manager responses, endpoint inventory, checkpoint/resume tests, deduplication counts, and end-to-end event records.

## P3 — Detection engine

- [ ] Version and review deterministic detection rules; map applicable rules to Sigma/ATT&CK with source and version provenance.
- [ ] Add positive and negative fixtures for each rule, including boundary cases and benign lookalikes.
- [ ] Run detections against real lab telemetry and verify severity, deduplication, event windows, and correlation logic.
- [ ] Make zero telemetry explicit; never represent missing data as zero alerts or a healthy detector.
- [ ] Test rule updates, replay, late/out-of-order events, duplicate inputs, and false-positive controls.
- [ ] Verify alert persistence, tenant isolation, traceability to source events/rules, and notification delivery only when configured.
- **Evidence:** fixture report, rule coverage matrix, measured precision/recall on a labelled corpus, and real-lab alert IDs.

## P4 — Evidence integrity

- [ ] Canonicalize evidence before hashing and use SHA-256 with documented encoding/version rules.
- [ ] Verify hashes on every read/export and detect altered, truncated, missing, reordered, or substituted evidence.
- [ ] Implement append-only audit events with actor, tenant, timestamp, action, object/version, and outcome.
- [ ] Verify audit-chain continuity and define key rotation, genesis, retention, and tamper-evidence limitations.
- [ ] Test case isolation, evidence upload bounds, MIME/type validation, path traversal, and unauthorized export.
- [ ] Test deterministic export manifests and verify the exported bundle independently.
- **Evidence:** tamper tests, chain verification output, reproducible export, and cross-tenant evidence tests.

## P5 — Local AI

- [ ] Define a provider-independent interface with an offline/local implementation; no hosted AI key required.
- [ ] Pin model identity/version, prompt templates, decoding settings, and resource limits.
- [ ] Ground every claim in supplied evidence IDs; return a typed schema and explicit unknown/insufficient-evidence states.
- [ ] Treat telemetry, documents, and retrieved content as untrusted data; test prompt injection and tool/command injection.
- [ ] Enforce timeouts, cancellation, bounded concurrency, output-size limits, and safe failure when the model is unavailable.
- [ ] Build a held-out, labelled evaluation set including benign cases, attacks, misleading text, and insufficient evidence.
- [ ] Measure groundedness, unsupported-claim rate, classification quality, latency, and resource use; set release thresholds before evaluating.
- **Evidence:** reproducible evaluation command, model/prompt manifest, held-out metrics, and adversarial regression results.

## P6 — Response actions

- [ ] Keep high-impact actions disabled by default until a provider sandbox and verification tests exist.
- [ ] Implement least-privilege provider adapters with typed allowlisted actions and strict target validation.
- [ ] Bind human approval to tenant, case, exact action, exact target, parameters, expiry, and payload hash; reject any post-approval change.
- [ ] Make approval consumption single-use and idempotent; prevent replay and concurrent double execution.
- [ ] Record the provider request ID and independently query provider state after execution; distinguish requested, accepted, completed, failed, and unknown.
- [ ] Test timeouts/ambiguous results without blindly retrying destructive actions; implement safe reconciliation and compensating workflows where supported.
- [ ] Verify audit evidence and notifications for both success and failure.
- **Evidence:** sandbox test run, approval tamper/replay tests, provider request/state IDs, and operator sign-off.

## P7 — Release readiness

- [ ] Run unit, integration, browser, accessibility, security, dependency, secret-scanning, and static-analysis checks.
- [ ] Test backup creation and restore in an isolated environment; record RPO/RTO and verify restored data/integrity.
- [ ] Add health/readiness checks that fail when mandatory dependencies/auth/configuration are unhealthy.
- [ ] Verify logs/metrics/traces contain no secrets and alert on ingestion lag, provider failures, queue growth, auth failures, and audit verification failures.
- [ ] Deploy from the approved exact SHA; verify production deployment SHA/alias and environment configuration.
- [ ] Run production-safe smoke tests for anonymous rejection, authenticated tenant-scoped reads, case lifecycle, reports, and capability status.
- [ ] Confirm rollback procedure and responsible operator.
- **Evidence:** exact-SHA CI, scan reports, restore drill, monitoring checks, deployment metadata, smoke-test report, and rollback evidence.

## P8 — Advanced capabilities

- [ ] Add additional telemetry sources only through a documented threat model, adapter contract, licensing review, and tenant-isolation tests.
- [ ] Add threat-intelligence enrichment with source attribution, freshness/expiry, confidence, and poisoning controls.
- [ ] Measure ATT&CK coverage against the actual enabled telemetry; do not claim coverage from rule labels alone.
- [ ] Benchmark model fine-tuning against the held-out baseline; do not fine-tune unless it measurably improves defined metrics without reducing groundedness.
- [ ] Consider multi-node/queue scaling only after idempotency, checkpointing, locking, ordering, and recovery tests pass.
- **Evidence:** integration-specific test reports, threat model, coverage metrics, and before/after benchmark.

## Release decision

Release is **NO-GO** if any P1 gate fails or is skipped, migration parity is unknown, production SHA is unknown, or any high-impact response action lacks verified approval and provider-state evidence. P2–P8 features must be labelled unavailable/unverified until their evidence exists.

| Gate | Status at document creation |
|---|---|
| P0 Inventory | Partial — static generator exists; manual review and live parity still required |
| P1 Security/tenancy | Blocked — live tenant tests and migration parity not yet evidenced |
| P2 Wazuh | Unverified — authorized endpoint round trip not evidenced |
| P3 Detection | Unverified — real-lab positive/negative evaluation not evidenced |
| P4 Evidence | Unverified — independent tamper/export proof not evidenced |
| P5 Local AI | Unverified — held-out evaluation not evidenced |
| P6 Response | Blocked/disabled until provider verification and approval tests |
| P7 Release | Blocked — production deployment and restore drill not evidenced |
| P8 Advanced | Not started for release purposes — gated on correctness of earlier phases |
