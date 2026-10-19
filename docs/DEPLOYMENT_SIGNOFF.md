# SATARK deployment verification and release sign-off

Last reviewed: 2026-10-20 UTC

**Status: NOT SIGNED OFF.** A missing result is unknown, not a pass. The current production deployment is not the latest tested source revision, and Vercel has reported a deployment-rate limit.

## Candidate identity

- Canonical repository: `kaustubhdua/Satark`
- Candidate branch: `main`
- Current `main` revision reviewed: `06cdbb4472c3cc0ef31f658f56efe67f62f01e77`
- Current Vercel production deployment: `dpl_FPJuv6ZYEnzCMs2PwGZJKihdi9ay`
- Production alias: [https://satark-rose.vercel.app](https://satark-rose.vercel.app)
- SHA currently deployed: `5a7486ac28fcc5bebe40e0e627ad26084fa0b092`
- Deployment state: `READY`; alias assignment verified through Vercel deployment metadata
- Revision mismatch: deployed SHA `5a7486...` is older than `main` SHA `06cdbb...`
- Vercel status on the current `main` SHA: **FAILURE — “Deployment rate limited — retry in 24 hours.”**
- Supabase project: `nihdhoom`, reference `igqgtlmnwssjaoxkkzbm`
- Branch protection: not verified; the connected GitHub integration could not read the protection endpoint. Do not assume required checks are enforced.

## CI evidence

- On `06cdbb4472c3cc0ef31f658f56efe67f62f01e77`: CodeQL passed; Web CI passed; the broader CI workflow was still running at the last check.
- Earlier main revision `304a837ab34fc610b60d47e68c8789e3d64ffb95`: CI and CodeQL passed, but that does not prove the newer SHA passed.
- PR #144's isolated Supabase migration validation exposed a SQL syntax issue in the policy migration. The migration was corrected and a new validation run is pending.
- PR #149's isolated database tests exposed a pgTAP assertion that used a data-modifying CTE in a scalar expression. It was corrected to use `lives_ok`; the rerun is pending.
- PR #145 and PR #150 are merged.
- PR #144 (durable approvals and private-policy hardening), PR #149 (tenant/storage isolation), PR #151 (this release documentation), PR #152 (video/PDF edge tests), PR #153 (local-analysis evaluation and README corrections), and PR #154 (Supabase authentication CSP fix) remain open and must be reviewed against their exact heads.

## Database and environment findings

- Vercel environment-variable entries exist for `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `UPSTASH_REDIS_REST_URL`, and `UPSTASH_REDIS_REST_TOKEN`. Their encrypted values were not printed or inspected.
- The production-safe health snapshot now compares browser/server Supabase project references without returning URLs or keys. That code is not yet confirmed deployed.
- The hosted database has RLS enabled on SATARK tenant, membership, case, evidence, finding, report and audit tables. The private membership helper is available to authenticated policy evaluation and denied to `anon`.
- Hosted evidence-storage policies still refer to `satark_has_membership` even though the public wrapper's EXECUTE grant is revoked. Evidence upload/download may fail until the storage policies are rebound to `satark_private.has_membership`; PR #144 and PR #149 contain the fix.
- The hosted database also showed direct EXECUTE grants on `public.satark_reject_audit_mutation()`. The repository ACL-hardening migration must pass isolated validation before being applied to the hosted database.
- The hosted Supabase migration history includes manually applied migrations that are not represented by identical repository migration files. Do not push migrations blindly; reconcile history and verify the final schema before applying production changes.

## Release gate checklist

| Gate | Status | Required evidence |
|---|---|---|
| Exact source SHA | PARTIAL | Record the release SHA only after all required checks pass on that exact commit |
| PR #144 | BLOCKED | Corrected isolated migration test, CI, Web CI and CodeQL must pass; then review and merge |
| PR #149 | BLOCKED | Cross-tenant and storage pgTAP tests plus all required checks must pass; then review and merge |
| Remaining open PRs | BLOCKED | Review test/documentation/CSP changes and merge only after required checks pass |
| Clean database reset | BLOCKED | `supabase db reset` and `supabase test db` must pass on the final release SHA |
| RLS/approval/audit security | PARTIAL | Verify tenant isolation, ownership/role enforcement, approval expiry/replay, and audit tamper detection in isolated tests |
| FIRSTLIGHT lifecycle | PARTIAL | Verify persistent create/save/reopen, evidence hashes, tamper handling, findings, timeline, gaps, reports, export and simulated approval/rejection |
| Scanner coverage | PARTIAL | Positive and negative text, URL, image/QR, PDF and video cases must pass; newly added video/PDF tests await CI |
| AI evaluation | PARTIAL | Run the synthetic local-analysis evaluation and record its corpus-specific metrics; do not represent them as real-world accuracy |
| Browser auth/CSP | BLOCKED | Merge and test PR #154; ensure CSP permits only the configured Supabase origin |
| Vercel deployment | BLOCKED | Wait for the rate limit to clear and confirm the production alias serves the exact release SHA |
| Production smoke | BLOCKED | Verify `/api/version`, `/api/health`, auth, persistence, headers, rate limiting, browser workflow and downloads on the deployed SHA |
| Branch protection | UNVERIFIED | Repository admin must configure and verify required status checks for `main` |
| Operations and recovery | NOT VERIFIED | Test logging/redaction, monitoring, rate/cost controls, rollback, backup and recovery procedures |

## Prototype boundary

SATARK is a security-awareness and incident-triage prototype, not a certified forensic product or antivirus. FIRSTLIGHT response actions remain simulated. Hashes support integrity comparison but do not independently prove original source or chain of custody. Use synthetic or non-sensitive data until the final release gates and a separate security/operational review are complete.

**Sign-off decision: NO-GO** until the exact release SHA passes required CI and isolated database tests, Vercel deploys that SHA, production smoke passes, and the security/authorization findings above are resolved.
