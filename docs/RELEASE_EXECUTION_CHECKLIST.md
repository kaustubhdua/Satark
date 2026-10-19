# SATARK release execution checklist

Last verified: 2026-10-20 UTC

## Current release state

**Release is blocked.** Do not label the current `main` revision production-ready until all checks below have passed on one exact SHA and the deployment has been verified against that SHA.

- Current `main` revision at this review: `06cdbb4472c3cc0ef31f658f56efe67f62f01e77`.
- This is a tracking revision, **not yet a release candidate**: CI, Web CI, and CodeQL runs for this SHA were queued when checked.
- PR #145 (isolated Supabase migration validation and release gates) is merged.
- PR #150 (safe browser/server Supabase project-mapping diagnostics) is merged.
- PR #144 (durable approvals, audit decisions, private membership helper and policy hardening) remains open pending isolated migration and test results.
- PR #149 (cross-tenant writes and evidence-storage regression coverage) remains open pending CI and isolated migration results.
- The latest successful main-branch CodeQL/CI runs at `304a837ab34fc610b60d47e68c8789e3d64ffb95` do not prove the newer `06cdbb4...` revision passed.
- Vercel reported `Deployment rate limited — retry in 24 hours` for the newer revision. The deployment has not been verified against `06cdbb4...`.
- Current Vercel production deployment is READY at `dpl_FPJuv6ZYEnzCMs2PwGZJKihdi9ay`, alias `https://satark-rose.vercel.app`, but it serves SHA `5a7486ac28fcc5bebe40e0e627ad26084fa0b092`, not current `main` SHA `06cdbb4472c3cc0ef31f658f56efe67f62f01e77`.
- A deployment for `06cdbb...` was not present in the production deployment list; Vercel's GitHub status reported `Deployment rate limited — retry in 24 hours`. Live HTTP smoke could not be completed through the connected fetch path, so the new `/api/health` Supabase mapping assertion remains unverified in production.
- GitHub branch protection could not be read by the connected integration; do not assume required checks are enforced. Configure and verify required checks using an account with repository administration access.

## Project and environment findings

- The intended SATARK Supabase project is the `nihdhoom` project, reference `igqgtlmnwssjaoxkkzbm`.
- The Vercel project has environment-variable entries for `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `UPSTASH_REDIS_REST_URL`, and `UPSTASH_REDIS_REST_TOKEN`. Their values are encrypted and were not inspected or printed.
- Both Upstash variable names exist for the production target, but the presence of names alone does not prove that their values are valid or that Redis is reachable.
- The public-safe `/api/health` snapshot and production smoke workflow now check that browser/server Supabase configuration points to `igqgtlmnwssjaoxkkzbm`, without returning URLs or keys.
- `FIRSTLIGHT_API_URL` and `FIRSTLIGHT_API_TOKEN` are optional; the remote service remains unavailable when unset. Ollama is optional for deterministic analysis.
- The hosted Supabase project has RLS enabled on SATARK case, evidence, finding, report, membership, tenant and audit tables. The private membership helper is executable by authenticated policy evaluation and not by `anon`; the public membership wrapper is not executable by authenticated users. However, the live storage policies still deparse to `satark_has_membership` rather than `satark_private.has_membership`, so evidence upload/download may fail after the wrapper grant was revoked. PR #149 and PR #144 contain the corresponding policy correction; validate them against a clean local stack before applying any hosted migration.
- A production query also found that `public.satark_reject_audit_mutation()` still had direct EXECUTE grants at the time of review. The repository ACL-hardening migration must pass isolated validation before it is applied to the hosted database.

## Required release gates

### 1. Source and CI
- [ ] Resolve PR #144; do not merge until CI, Web CI, CodeQL and isolated Supabase migration validation pass on its exact head.
- [ ] Resolve PR #149; do not merge until all checks, including tenant/storage pgTAP tests, pass on its exact head.
- [ ] Confirm all required changes are on `main`, with no required functionality only on an unmerged branch.
- [ ] Record the exact release SHA.
- [ ] Review CodeQL alerts/annotations and dependency audit findings, not just workflow success.
- [ ] Configure and verify required branch protection/status checks with repository-admin access.

### 2. Database and authorization
- [ ] Run `supabase db reset` and `supabase test db` from a clean checkout on the final release SHA.
- [ ] Confirm no duplicate migration versions and no dependency on manually applied migrations absent from the repository.
- [ ] Test tenant isolation for reads, inserts, updates, deletes, storage objects and RPCs.
- [ ] Test approval expiry, requester/approver separation, exact payload binding, replay prevention, concurrent decisions and audit-chain tamper detection.
- [ ] Apply production migrations only after isolated tests pass and the intended project is confirmed; verify resulting grants and policies afterward.
- [ ] Test failures and timeouts so rejected database writes cannot be reported as successful.

### 3. FIRSTLIGHT and scanners
- [ ] Exercise create/save/reload/reopen case lifecycle with persistent data.
- [ ] Test evidence MIME/signature validation, size limits, source and record hashes, tamper detection, findings, timeline, evidence gaps and report exports.
- [ ] Test approval/rejection and ensure decisions create durable audit records. Keep actual response execution disabled until separately reviewed.
- [ ] Run positive and negative tests for text, URL, image/QR, PDF and video scanners, including private IPs, redirects, malformed files, oversized inputs, timeouts and unavailable dependencies.
- [ ] Run Ollama success/failure tests when a reachable self-hosted model is available; keep deterministic fallback usable and document unmeasured detection quality.

### 4. Production deployment
- [ ] Wait for the Vercel deployment-rate limit to clear.
- [ ] Confirm the Vercel deployment is from the intended repository, branch and exact release SHA.
- [ ] Confirm the production alias serves that deployment.
- [ ] Run `/api/health`, `/api/version`, route/security-header checks, unauthenticated API checks and a synthetic analysis request.
- [ ] Verify shared rate limiting is configured and reachable; analysis must fail closed if it is not.
- [ ] Test authenticated persistence against the intended database, desktop/mobile UI flows, downloads, loading/error/retry states and accessibility.
- [ ] Verify request-size, concurrency, timeout and abuse/cost controls, monitoring, log redaction, rollback and backup/recovery procedures.

### 5. Documentation and sign-off
- [ ] Update the README and environment-variable contract to match the final shipped behavior.
- [ ] Record supported file formats and size limits, optional services, retention/deletion behavior and known limitations.
- [ ] Prepare a repeatable synthetic-data demo and capture evidence of the final browser/database workflow.
- [ ] Update `docs/DEPLOYMENT_SIGNOFF.md` only after each applicable gate has evidence.

## Safety boundary

SATARK is a security-awareness and incident-triage prototype, not a certified forensic product or antivirus. FIRSTLIGHT response actions remain simulated; a passing build does not prove the deployed revision is correct, model detections are calibrated, or chain-of-custody evidence is independently anchored. Use synthetic or non-sensitive data until a separate security and operational review approves broader use.
