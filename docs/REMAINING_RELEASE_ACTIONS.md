# SATARK — remaining release actions

**Snapshot:** 2026-11-08  
**Decision:** no-go for production use with sensitive or multi-tenant incident evidence.

This file records the external actions that cannot be completed safely from repository-only access. It is intentionally explicit: a green build is not a substitute for tenant-isolation or deployment acceptance.

## Verified repository checks

- Next.js production browser and accessibility smoke: passed on `ed4df88`.
- Next.js web validation: passed on `ed4df88`.
- Python/core validation: passed on `ed4df88`.
- CodeQL: passed on `ed4df88`.
- Supabase tenant-isolation integration: **blocked**; the job correctly fails closed when its dedicated test environment is absent.

## 1. Configure the isolated Supabase test project

In GitHub repository Actions secrets, configure these exact names using a dedicated non-production Supabase project and least-privilege test users:

| Secret | Purpose |
| --- | --- |
| `SATARK_TEST_SUPABASE_URL` | Dedicated test project URL |
| `SATARK_TEST_SUPABASE_PUBLISHABLE_KEY` | Public/publishable key for test project |
| `SATARK_TEST_USER_A_EMAIL` | Tenant A owner test account |
| `SATARK_TEST_USER_A_PASSWORD` | Tenant A owner test password |
| `SATARK_TEST_TENANT_A_ID` | Tenant A fixture UUID |
| `SATARK_TEST_USER_B_EMAIL` | Tenant B owner test account |
| `SATARK_TEST_USER_B_PASSWORD` | Tenant B owner test password |
| `SATARK_TEST_TENANT_B_ID` | Tenant B fixture UUID |
| `SATARK_TEST_VIEWER_EMAIL` | Read-only viewer test account |
| `SATARK_TEST_VIEWER_PASSWORD` | Read-only viewer test password |
| `SATARK_TEST_VIEWER_TENANT_ID` | Viewer tenant fixture UUID |

Use separate accounts with no production data. Do not use a service-role key in this integration job. Confirm the test fixtures have the intended owner/viewer memberships, then run the `CI` workflow on the release commit. The tenant job must demonstrate cross-tenant read/write denial and viewer write denial. Do not convert missing credentials into a skipped/successful required check.

## 2. Web dependency security patch — implemented on this branch

The 2026-11-08 CI install reported one critical-severity npm advisory. This branch now updates `web/package.json` and regenerates the lockfile using npm's resolver:

- Next.js: `15.5.27` → `15.5.28` (maintenance security release).
- Sharp: pinned through the declared dependency range to `^0.35.5`, resolving to `0.35.5` to address the SVG image-optimization vulnerability.
- `npm audit --audit-level=critical`: passed.
- `npm run test:ci`: passed (typecheck, unit tests and production build).
- `npm run test:browser`: passed at desktop and mobile viewports, including the local-analysis smoke.

The patch has not yet been merged into `main`; run the full branch CI and review the resulting PR before merging. Continue to review all non-critical advisories and transitive dependencies. Do not use `npm audit fix --force` or suppress findings.

Reference: [Next.js security update, 2026-10-14](https://nextjs.org/blog/nextjs-security-update-october-14-2026).

## 3. Production deployment acceptance

Do not use real incident evidence until all of the following have been verified against the exact deployed SHA:

- Tenant isolation, owner authorization, viewer permissions, session expiry and token refresh.
- Durable case/evidence persistence, retention and deletion behavior.
- Shared/global rate limits, request-size limits, concurrency limits and provider cost controls.
- Secret storage and rotation; no provider credentials in browser bundles or logs.
- Backup/restore, monitoring, incident response, rollback and an independently reviewed threat model.
- Production route, mobile, accessibility and error-state smoke tests.

## Safe operating boundary

Until the above gates pass, use synthetic or public non-sensitive inputs only. FIRSTLIGHT response actions remain simulated; session audit chains are not independently anchored chain-of-custody evidence. SATARK is a triage aid, not a certified forensic product or malware verdict engine.
