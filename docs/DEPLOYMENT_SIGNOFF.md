# SATARK deployment verification and release sign-off

Last reviewed: 2026-10-20 UTC

**Status: NOT SIGNED OFF.** A missing result is unknown, not a pass. The latest Vercel project metadata lists a READY production-target deployment created at `2026-10-20T04:05:35Z`, but the connected deployment-detail/list endpoints did not return its source SHA. The production alias therefore cannot yet be tied to the current `main` revision. An earlier rate-limit failure was reported at `03:56Z`; do not assume it remains active or cleared without exact-SHA verification.

## Candidate identity

- Canonical repository: `kaustubhdua/Satark`
- Candidate branch: `main`
- Current `main` revision reviewed: `83874ec9744f38eeda815772e1227516bcb50bda`
- Latest Vercel project metadata deployment: `dpl_5ounvL24fTLUDLMV7pAYGs2Avg4V`
- Production alias: [https://satark-rose.vercel.app](https://satark-rose.vercel.app)
- SHA currently deployed: **UNKNOWN** — deployment details could not be retrieved through the connected Vercel integration.
- Deployment state: project metadata reports `READY` for a production-target deployment; exact source SHA and alias-to-deployment mapping are not independently verified.
- Revision mismatch: cannot be determined until the deployment's source SHA is retrieved and compared with `main`.
- Vercel status on the current `main` SHA: **UNVERIFIED**. An earlier deployment-rate-limit error exists, but later project metadata shows a READY production-target deployment without a readable source SHA.
- Supabase project: `nihdhoom`, reference `igqgtlmnwssjaoxkkzbm`
- Branch protection: not verified; the connected GitHub integration could not read the protection endpoint. Do not assume required checks are enforced.

## CI evidence

- PR #144 (durable approvals/private-policy hardening) merged as `15a7631ebd39c3e03704792277a6310e74b58cfb`; isolated migration validation, CI, Web CI and CodeQL passed on its exact head.
- PR #149 (tenant/storage isolation regression coverage) merged as `0136b1b9d92af6c89dd32f64322a61521d8cd942`; isolated migration validation, CI, tenant-isolation/browser checks and CodeQL passed on its exact head.
- PR #152 (video/PDF edge-case coverage) merged as `c420a3079e8fe1e6e07e618c31ded70a4ef9351a`; CI and CodeQL passed.
- PR #153 (local-analysis evaluation and README corrections) merged as `21abd4c7466cb7490ae1acb372d04008f72e40d5`; CI, Web CI and CodeQL passed.
- PR #154 (Supabase authentication CSP fix) merged as `6f27ec8f570f11632e935e8e33a736c604a1e178`; CI, Web CI and CodeQL passed.
- PR #158 (simulation-only approval pgTAP fixtures) merged as `83874ec9744f38eeda815772e1227516bcb50bda`; CI, isolated migration validation and CodeQL passed on its exact head before merge.
- PR #155 (FIRSTLIGHT/Wazuh ingestion and persistent workflows) remains open; its latest API, web, CI, CodeQL and isolated migration runs must all pass on one exact head. Live Wazuh endpoint/credential round-trip is not proven.

## Database and environment findings

- Vercel environment-variable entries exist for `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `UPSTASH_REDIS_REST_URL`, and `UPSTASH_REDIS_REST_TOKEN`. Their encrypted values were not printed or inspected.
- The production-safe health snapshot now compares browser/server Supabase project references without returning URLs or keys. That code is not yet confirmed deployed.
- The hosted database has RLS enabled on SATARK tenant, membership, case, evidence, finding, report and audit tables. The private membership helper is available to authenticated policy evaluation and denied to `anon`.
- Repository migrations now rebind storage policies to `satark_private.has_membership` and harden the public wrapper grants; isolated validation passed on the merged PR heads. The hosted schema has **not** been re-verified or migrated, so production evidence upload/download remains unproven.
- The repository ACL-hardening migration passed isolated validation. The hosted grant state has not been re-queried, and no hosted migration was applied.
- The hosted Supabase migration history includes manually applied migrations that are not represented by identical repository migration files. Do not push migrations blindly; reconcile history and verify the final schema before applying production changes.

## Release gate checklist

| Gate | Status | Required evidence |
|---|---|---|
| Exact source SHA | PARTIAL | Record the release SHA only after all required checks pass on that exact commit |
| PR #144 | MERGED | Isolated migration validation, CI, Web CI and CodeQL passed; hosted migration still requires controlled application and verification |
| PR #149 | MERGED | Tenant/storage regression checks and required workflows passed; hosted behavior remains unverified |
| PR #155 | IN PROGRESS | FIRSTLIGHT API, Web CI, CI, CodeQL and isolated migration validation must pass on one exact head; live Wazuh round-trip remains a separate gate |
| Clean database reset | BLOCKED | `supabase db reset` and `supabase test db` must pass on the final release SHA |
| RLS/approval/audit security | PARTIAL | Verify tenant isolation, ownership/role enforcement, approval expiry/replay, and audit tamper detection in isolated tests |
| FIRSTLIGHT lifecycle | PARTIAL | Verify persistent create/save/reopen, evidence hashes, tamper handling, findings, timeline, gaps, reports, export and simulated approval/rejection |
| Scanner coverage | PARTIAL | Positive and negative text, URL, image/QR, PDF and video cases must pass; newly added video/PDF tests await CI |
| AI evaluation | PARTIAL | Run the synthetic local-analysis evaluation and record its corpus-specific metrics; do not represent them as real-world accuracy |
| Browser auth/CSP | REPOSITORY FIX MERGED | PR #154 passed CI/Web CI/CodeQL; production sign-in/session refresh is not verified on the deployed SHA |
| Vercel deployment | BLOCKED | Wait for the rate limit to clear and confirm the production alias serves the exact release SHA |
| Production smoke | BLOCKED | Verify `/api/version`, `/api/health`, auth, persistence, headers, rate limiting, browser workflow and downloads on the deployed SHA |
| Branch protection | UNVERIFIED | Repository admin must configure and verify required status checks for `main` |
| Operations and recovery | NOT VERIFIED | Test logging/redaction, monitoring, rate/cost controls, rollback, backup and recovery procedures |

## Prototype boundary

SATARK is a security-awareness and incident-triage prototype, not a certified forensic product or antivirus. FIRSTLIGHT response actions remain simulated. Hashes support integrity comparison but do not independently prove original source or chain of custody. Use synthetic or non-sensitive data until the final release gates and a separate security/operational review are complete.

**Sign-off decision: NO-GO** until the exact release SHA passes required CI and isolated database tests, Vercel deploys that SHA, production smoke passes, and the security/authorization findings above are resolved.
