# SATARK — remaining release actions

**Snapshot:** 2026-11-08  
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

## 2. Resolve the web dependency audit finding

The 2026-11-08 CI install reported one critical-severity npm advisory. The lockfile currently resolves Next.js `15.5.27`; the upstream 2026-10-14 Next.js security update identifies `15.5.28` as the patched 15.5 maintenance release.

Before release:

1. In `web/`, update Next.js to at least `15.5.28` (or a currently supported patched stable release).
2. Regenerate `package-lock.json` with the project's supported Node/npm toolchain; do not hand-edit integrity hashes or package metadata.
3. Run `npm ci`, `npm audit`, `npm run test:ci`, and `npm run test:browser`.
4. Review all advisories, including transitive dependencies. Do not use `npm audit fix --force` or suppress critical findings to obtain a green check.
5. Record the audit output and exact dependency tree on the release commit.

Reference: [Next.js security update, 2026-10-14](https://nextjs.org/blog/nextjs-security-update-october-14-2026).

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
