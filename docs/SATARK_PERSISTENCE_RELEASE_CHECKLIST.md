# SATARK persistence release checklist

## What the current persistence slice provides
- Supabase Auth sign-in/sign-up and refresh-token handling in the Next.js workspace UI.
- A trusted tenant-creation RPC that derives the owner from the authenticated identity.
- Tenant-scoped case reads/creates through the Next.js API and existing RLS policies.
- Private satark-evidence Storage bucket, bounded uploads, server-calculated SHA-256, and a verification endpoint that re-fetches stored bytes.
- Persistent normalized FIRSTLIGHT evidence records and deterministic findings.
- Immutable report snapshots with a server-calculated snapshot digest.
- Database-generated audit events for case, evidence, finding, and report creation, plus an audit-chain verification RPC.
- SATARK-only foreign-key indexes for the database-advisor findings.

## Required Vercel environment
The SATARK Vercel project must have the following configured in production, preview, and development:
- SUPABASE_URL
- SUPABASE_PUBLISHABLE_KEY (server API)
- NEXT_PUBLIC_SUPABASE_URL (browser Auth)
- NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY (browser Auth; publishable key only)

Never configure a service-role key in browser code or expose it through a NEXT_PUBLIC_ variable. These routes deliberately use the caller's JWT so RLS remains the authorization boundary. After environment changes, create a fresh deployment.

## Database migrations
Apply migrations in filename order. The migration history must include the case-storage foundation, SATARK foreign-key indexes, trusted tenant provisioning, private evidence storage, server audit hash chain, findings/reports, audit-chain verification, finding/report creator indexes, and audit insert hardening. The migrations are intentionally limited to SATARK-prefixed tables and one private Storage bucket/policy set.

## Manual release verification
1. Use two separate test users, each a member of a different tenant, and verify cross-tenant reads return no rows and writes are denied.
2. Verify a viewer cannot create or update cases/evidence/findings/reports; verify analyst/responder/owner permissions match the role matrix.
3. Sign in, create a workspace, create a case, upload a harmless synthetic file, and verify the server digest matches after a fresh download.
4. Tamper with an isolated test object only in a disposable test environment and verify the endpoint reports an integrity mismatch; never tamper with real evidence.
5. Save FIRSTLIGHT evidence/findings/report, sign out, sign back in, and load the case from a new browser context.
6. Verify the audit chain, then run the verification again after a controlled unauthorized mutation attempt and confirm the database rejects the mutation.
7. Exercise duplicate saves, expired sessions, unavailable Auth/Storage, oversized uploads, malformed metadata, and interrupted network requests.
8. Verify the production deployment's commit, unauthenticated /api/cases 401 response, sign-in page, and private API responses. Do not bypass deployment protection.
9. Configure Upstash REST credentials separately before claiming distributed rate limiting is enabled. Verify normal requests, 429 after the configured threshold, and controlled 503 behavior when the configured backend is unavailable.
10. Keep Microsoft live response disabled until target-bound authorization, approval, idempotency, audit, and authorized test-tenant checks pass.

## Opt-in RLS integration test
web/tests/tenant-isolation.integration.test.mjs is skipped unless test credentials are explicitly supplied in the test environment:
- SUPABASE_URL
- SUPABASE_PUBLISHABLE_KEY
- SATARK_TEST_USER_A_EMAIL, SATARK_TEST_USER_A_PASSWORD, SATARK_TEST_TENANT_A_ID
- SATARK_TEST_USER_B_EMAIL, SATARK_TEST_USER_B_PASSWORD, SATARK_TEST_TENANT_B_ID
- Optional viewer test: SATARK_TEST_VIEWER_EMAIL, SATARK_TEST_VIEWER_PASSWORD, SATARK_TEST_VIEWER_TENANT_ID

Use two dedicated non-admin test accounts in separate test tenants. Do not use production user credentials or real investigation data. Run from web/ with node --test tests/tenant-isolation.integration.test.mjs.

## Current limitations and honest claims
- A SHA-256 match means retrieved bytes match the digest recorded at upload; it does not prove source authenticity or the acquisition process.
- Browser-generated event hashes are supplemental metadata. Uploaded file hashes are calculated by the server.
- Report snapshots are immutable; later changes require a new report.
- The opt-in cross-tenant test is not a substitute for a role matrix test with real test identities.
- External production API verification may be blocked by deployment access policy; a deployment reaching READY is not the same as a verified application request.
- Shared Redis rate limiting is not enabled until valid Upstash credentials are configured and behavior is tested.
- Existing unrelated Supabase Telegram/function advisor findings are not changed by these migrations. Review them with the owning application before modifying anything.
