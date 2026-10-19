# SATARK P0–P8 completion and verification gate

This document is an execution checklist, not a claim that the checks have passed. Evidence must come from CI logs, database integration tests, and the deployed app.

## Free isolated database

Use the repository's local Supabase CLI stack for routine migration and database integration testing. It runs on the GitHub Actions runner and does not modify a hosted Supabase project. It does require Docker on the runner.

- Run `supabase start` and `supabase db reset` from a clean checkout.
- Never point this workflow at production credentials.
- Keep synthetic test data only.
- Hosted branch creation is optional, may incur charges, and is not required for this workflow.

## Required release gates

### P0 — baseline
- [ ] Identify the exact tested commit and production commit.
- [ ] Run Python, Node, typecheck, build, dependency audit, CodeQL.
- [ ] No unresolved merge conflicts or unreviewed migrations.

### P1 — isolated schema and lifecycle
- [ ] Local Supabase starts from clean state and every migration applies.
- [ ] Add database integration tests for case/evidence/finding/report CRUD, idempotent retries, partial saves, constraints and persistence after restart.
- [ ] Tests must prove they use the local test database and fail if the database URL points to production.

### P2 — durable approval and audit
- [ ] Test requester/approver separation, allowed roles, expiry, immutable payload, one-time decisions and concurrent decisions.
- [ ] Authorization and consumption must be atomic with respect to the action executor; an authorization boolean alone is not proof that an action may safely execute.
- [ ] Verify audit hashes, previous-hash links, ordering, rollback, tampering, deletion and concurrency.
- [ ] Keep response execution simulated until a separately reviewed executor exists.

### P3 — cross-tenant isolation
- [ ] Seed two tenants and distinct authenticated users in the isolated stack.
- [ ] Exercise reads/writes/RPCs for cases, evidence, findings, reports, approvals and audit events using each tenant's JWT.
- [ ] Assert foreign-tenant access is denied at the database/API layer.
- [ ] CI must fail if the integration suite is skipped or credentials are absent in a job advertised as an integration test.

### P4 — persisted investigation
- [ ] Create case, import evidence, verify digest, mutate evidence, assert tamper detection and quarantine.
- [ ] Run triage, findings, timeline, gaps and report export.
- [ ] Restart/reload and verify persisted records and retry conflict behavior.

### P5 — optional AI
- [ ] Run an integration job against a reachable Ollama model when available.
- [ ] Test timeout, invalid output, fabricated evidence IDs, oversized input and provider outage.
- [ ] Keep deterministic output authoritative and the no-model path fully functional.
- [ ] Do not claim the optional AI runtime passed when only mocks ran.

### P6 — deployment
- [ ] Confirm the intended Supabase project and schema owner before configuring deployment.
- [ ] Configure Supabase URL and publishable key only after project confirmation.
- [ ] Configure shared rate limiting with real credentials, or explicitly document and enforce a suitable production alternative.
- [ ] Confirm deployed commit SHA matches the tested release candidate.

### P7 — deployed browser workflow
- [ ] Use Playwright/browser checks against the release candidate.
- [ ] Demonstrate case creation, evidence integrity, tampering/quarantine, findings, timeline, simulated approval, persisted reload, audit verification and report export.
- [ ] Run a real negative cross-tenant test using dedicated accounts.
- [ ] Do not use production personal or sensitive evidence.

### P8 — security review
- [ ] Review RLS, SECURITY DEFINER functions, grants and search_path.
- [ ] Check request bounds, caching, security headers, rate limiting, logs and secrets.
- [ ] Document remaining prototype limitations and keep live response execution disabled until separately tested.

## Environment safety

The connected Supabase project named `nihdhoom` has a mixed migration history, and the production Vercel environment previously showed empty Supabase and Upstash environment entries. Do not apply migrations to that hosted database or fill production variables until the intended SATARK database is confirmed.

## Evidence required before declaring completion

Attach CI run URLs, the local migration/test logs, test case counts, the actual tenant integration results, Ollama runtime test results (or mark the optional job unavailable), the deployed commit SHA, and a Playwright/browser run report. A workflow definition or successful build alone is not proof of the feature working end to end.
