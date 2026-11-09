# SATARK — remaining release actions

**Snapshot:** 2026-11-09  
**Decision:** no-go for production use with sensitive or multi-tenant incident evidence.

This file records the external actions that cannot be completed safely from repository-only access. It is intentionally explicit: a green build is not a substitute for tenant-isolation or deployment acceptance.

## Superseded persistence instructions

The original main-branch release checklist below was written for a Supabase-backed deployment. The migration branch replaces that runtime with SATARK-owned FastAPI, SQLAlchemy, PostgreSQL/SQLite, private evidence storage, and cookie-backed sessions. **Do not configure or add Supabase secrets.** The old Supabase test-project instructions have been retired.

The replacement acceptance suite is:
- `tests/test_satark_backend.py`: self-hosted signup/login, cookie sessions, tenant isolation, notes, findings, reports, and CSRF checks.
- `tests/test_satark_postgres.py`: PostgreSQL integration for evidence upload/verification, idempotent jobs, worker persistence, and evidence-linked findings.
- `tests/test_firstlight_investigation_worker.py` and `tests/test_firstlight_wazuh_worker.py`: durable queue and Wazuh ingestion behavior.
- Web CI and browser/accessibility smoke: same-origin API proxy, security headers, mobile/browser behavior.

The migration branch is not a production release until these checks pass on its latest commit and a private FastAPI deployment is configured and smoke-tested. Existing Supabase data is not deleted or automatically imported by this branch; preserve the old project until a separately validated export/import and backup plan is complete.

## 2. Web dependency security status

The branch's `web/package.json` and `web/package-lock.json` now pin Next.js **15.5.29**. This is the patched 15.5 maintenance release for the November 3, 2026 advisories affecting versions through 15.5.28, and it is above the October 14 critical-fix floor of 15.5.28.

Verified from the checked-in manifests:
- `next` is pinned to `15.5.29` in the package manifest.
- The lockfile resolves `node_modules/next` to `15.5.29` and its matching `@next/*` packages.
- The November advisories affecting the 15.5 line list 15.5.29 as patched. The remaining November advisories shown on the upstream security page affect 16.x-only Cache Components features.

This manifest check does **not** replace a fresh dependency audit. Before release, run `npm ci`, `npm audit`, `npm run test:ci`, and `npm run test:browser` on the exact release commit, review all transitive advisories, and retain the output. Do not use `npm audit fix --force` or suppress critical findings to obtain a green check.

References: [Next.js security advisories](https://github.com/vercel/next.js/security/advisories), [November 3 advisory — response injection](https://github.com/vercel/next.js/security/advisories/GHSA-pc58-hwjq-p385), [November 3 advisory — SVG rejection bypass](https://github.com/vercel/next.js/security/advisories/GHSA-7qx7-33qx-rqx2), [November 3 advisory — HttpOnly cookie exposure](https://github.com/vercel/next.js/security/advisories/GHSA-f3mh-rxg3-f5g2).

## Additional repository hardening completed

- Evidence objects and tenant/case directories are written with restrictive filesystem permissions (files 0600, private directories 0700), exclusive no-follow creation, atomic replacement, and directory fsync.
- Unrecognized uploaded content types are stored and downloaded as `application/octet-stream`; downloads include `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and a sandbox content security policy.
- Optional email verification is implemented with single-use 30-minute token digests, resend cooldowns, SMTP preflight, a browser verification page, and a migration that grandfather-verifies accounts that predate the feature. Enable only after SMTP and the trusted public base URL are configured.\n- Optional TOTP MFA is implemented with encrypted secrets, time-window verification, hashed single-use recovery codes, authenticated enrollment/disable flows, session revocation on disable, and a browser account-security panel. Configure a persistent `SATARK_MFA_ENCRYPTION_KEY` before enrollment.

## Remaining code and operational limitations

- Invitations for users who have not registered, organization-wide mandatory MFA policy, and per-IP/global edge rate limiting remain outstanding. Session-family reuse detection now revokes the full family when a rotated token is replayed. Email verification and per-account TOTP MFA are implemented but opt-in; production must enable email verification and configure a persistent MFA encryption key according to its security policy.
- PostgreSQL row-level security and adversarial concurrency testing are not yet implemented for the self-hosted database.
- Existing Supabase data is not imported or deleted. A validated export/import and reconciliation run remains necessary if legacy data must be preserved.
- Evidence storage remains a private local filesystem volume; an S3-compatible object-store adapter is not implemented.
- Production restore drills, Wazuh Indexer acceptance, audit anchoring, and deployed-host smoke tests remain outstanding.

## 3. Production deployment acceptance

Do not use real incident evidence until all of the following have been verified against the exact deployed SHA:

- Tenant isolation, owner authorization, viewer permissions, session expiry and revocation.
- Durable case/evidence persistence, retention and deletion behavior.
- Shared/global rate limits, request-size limits, concurrency limits and provider cost controls.
- Secret storage and rotation; no provider credentials in browser bundles or logs.
- Backup/restore, monitoring, incident response, rollback and an independently reviewed threat model.
- Production route, mobile, accessibility and error-state smoke tests.

## Safe operating boundary

Until the above gates pass, use synthetic or public non-sensitive inputs only. FIRSTLIGHT response actions remain simulated; session audit chains are not independently anchored chain-of-custody evidence. SATARK is a triage aid, not a certified forensic product or malware verdict engine.
