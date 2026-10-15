# SATARK release acceptance checklist

This checklist distinguishes code validation from production readiness. A green build alone is not release approval.

## Before merge
- [ ] CI, Web CI (including browser smoke routes), SATARK AI CI and CodeQL pass on the exact PR head.
- [ ] Review the full diff, dependency audit, outbound-fetch policy and all new public endpoints.
- [ ] Verify repository branch protection requires the intended checks and prohibits bypass except through a documented emergency procedure.
- [ ] Confirm the SATARK Supabase project identity before applying any migration. Never apply SATARK migrations to the JYC website database or another unrelated project.
- [ ] Apply reviewed migrations through the normal migration workflow and verify the migration ledger matches the checked-in files.

## Vercel environment
- [ ] NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY are set for browser sign-in.
- [ ] SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY are set for server APIs and point to the same intended SATARK project.
- [ ] UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are configured for production and preview; verify atomic shared limiting with concurrent requests.
- [ ] Optional threat-intelligence integrations remain disabled until credentials, terms and data-sharing implications are approved.
- [ ] No service-role key or other privileged database secret is exposed to the browser bundle.

## Tenant and role acceptance
Use dedicated non-production accounts only. Never use real user credentials as CI fixtures.
- [ ] Seed synthetic fixture cases in two distinct tenants, plus tenant B evidence, finding, report and private object. Set the matching SATARK_TEST_* fixture IDs and relative storage path.
- [ ] Two distinct users are members of distinct tenants; each can read its own cases, evidence, findings, reports and private objects.
- [ ] Cross-tenant reads return no records; writes and storage access are denied.
- [ ] A viewer test user can read its seeded case but cannot create or update cases, upload evidence, create findings or save reports.
- [ ] Owner/responder/analyst roles behave according to the reviewed policy matrix.
- [ ] Audit chain verification passes for the fixture tenant; audit events cannot be changed by normal clients.
- [ ] Evidence objects remain private and downloads are authorized by the same tenant and case relationship.

## Feature and browser acceptance
- [ ] Check homepage, investigate, local URL review, image review, QR, PDF/video local triage, FIRSTLIGHT, cases, reports, learning and login on desktop and mobile.
- [ ] Verify keyboard-only use, accessible names, focus visibility, reduced motion, 44px touch targets and no axe violations.
- [ ] Verify PDF/JSON/TXT exports and confirm all exports state their limitations and do not silently include submitted source text.
- [ ] Verify case/evidence/report save, reload, status update, duplicate handling, integrity checks and error/retry behavior.
- [ ] Verify evidence retention, user-requested deletion, orphaned object cleanup, backup restore and rollback procedures before handling real incidents.

## Production release gate
- [ ] Deployment is built from the approved commit and the production alias points to that exact SHA.
- [ ] Run production smoke against the public origin: headers/CSP/HSTS, route health, /api/version, fail-closed rate limiting and safe synthetic analysis.
- [ ] Confirm shared Redis connectivity and multi-instance behavior; environment-variable presence alone does not prove connectivity.
- [ ] Confirm database migration state, tenant-isolation tests and private storage policies.
- [ ] Confirm alerting, logs, backup/restore ownership, rollback owner and incident runbook.
- [ ] Record final acceptance evidence and release decision.

## Non-code gates
A developer cannot manufacture secret values, test identities, billing quota or owner-level branch-protection permissions. Keep release blocked until the authorized owner supplies/configures these items and the acceptance tests pass.

## Live release status — 2026-10-16 IST

This status record is intentionally separate from the checklist above. It records observed blockers and does not grant release approval.

- Repository: `kaustubhdua/Satark`, PR [#125](https://github.com/kaustubhdua/Satark/pull/125).
- Observed PR head: `66c2ec2bd1b1af9aad88169c0a569a34d1c274a6`; observed `main`: `8a8882ff62a7a4189f1a21267e853fb93e85c6e8`.
- GitHub Actions at the PR head: SATARK AI CI run 35, CodeQL run 828, CI run 2211, and Web CI run 952 all report success.
- Vercel's PR-head status is failing with `build-rate-limit` / `api-deployments-free-per-day`. The latest observed READY preview is commit `40463ee8cb8a1d082406b5cef4a89190398a92c8`, which is behind the observed PR head. Do not repeatedly retry builds while the quota restriction remains.
- The production alias `satark-qzym.vercel.app` was observed on commit `265dae7f97d7a6c1fde342db93e76dd0ccd6eedf`, not the observed current main commit. Exact-SHA production acceptance is therefore outstanding.
- Production environment inspection found the Upstash URL/token variable names absent. The analysis endpoint correctly fails closed when shared rate limiting is not configured; this leaves the primary analysis action unavailable in production.
- The PR's current release notes also identify empty threat-intelligence provider credentials, missing dedicated synthetic tenant fixtures, owner-level branch-protection verification, and incomplete acceptance for cross-browser QR decoding, full PDF text extraction, semantic/audio video analysis, retention/deletion, and authenticated case/evidence/report journeys.
- The configured Supabase project must be confirmed as the dedicated SATARK project before any migration or test data is written. Do not seed or mutate the existing Nirdhoom project without owner confirmation.
- **Decision: NOT RELEASE-APPROVED.** Do not merge/promote based on green GitHub CI alone. The owner must resolve quota and environment prerequisites, then run the exact-commit deployment, shared-limiter, tenant-isolation, and production smoke gates above.

