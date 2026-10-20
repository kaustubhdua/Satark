# SATARK release execution checklist

Last verified: 2026-10-20 UTC

## Current release state

**Release is blocked.** Do not label the current `main` revision production-ready until all checks below have passed on one exact SHA and the deployment has been verified against that SHA.

- Current `main` revision at this review: `83874ec9744f38eeda815772e1227516bcb50bda`.
- This is a tracking revision, **not yet a release candidate**. PR #158's checks passed on its exact head before merge; a full post-merge check set and deployment source-SHA verification remain required.
- PR #145 (isolated Supabase migration validation and release gates) is merged.
- PR #150 (safe browser/server Supabase project-mapping diagnostics) is merged.
- PR #144 (durable approvals and private membership helper/policy hardening) is merged; its isolated migration validation, CI, Web CI and CodeQL passed.
- PR #149 (cross-tenant writes and evidence-storage regression coverage) is merged; its isolated migration validation, CI, tenant-isolation/browser checks and CodeQL passed.
- PR #152 (video/PDF edge tests), PR #153 (synthetic local-analysis evaluation and README corrections), PR #154 (Supabase auth CSP fix), and PR #158 (simulation-only approval fixtures) are merged. These are repository/CI results, not production deployment proof.
- PR #155 adds FIRSTLIGHT/Wazuh ingestion and persistent workflows; its exact-head checks are still running. A live Wazuh endpoint/credential round-trip has not been proven.
- The latest Vercel project metadata reports a READY production-target deployment `dpl_5ounvL24fTLUDLMV7pAYGs2Avg4V` created at `2026-10-20T04:05:35Z`, alias candidates include `https://satark-rose.vercel.app`; its exact source SHA could not be retrieved through the connected deployment-detail/list endpoints.
- An earlier Vercel deployment-rate-limit failure was reported at `03:56Z`, but the later READY deployment means the current rate-limit state is unknown. Do not claim it is either active or cleared without a fresh deploy/status check.
- Live HTTP smoke through the connected fetch path was inaccessible; the new `/api/health` Supabase mapping assertion, browser authentication and production persistence remain unverified.
- GitHub branch protection could not be read by the connected integration; do not assume required checks are enforced. Configure and verify required checks using an account with repository administration access.

## Project and environment findings

- The intended SATARK Supabase project is the `nihdhoom` project, reference `igqgtlmnwssjaoxkkzbm`.
- The Vercel project has environment-variable entries for `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `UPSTASH_REDIS_REST_URL`, and `UPSTASH_REDIS_REST_TOKEN`. Their values are encrypted and were not inspected or printed.
- Both Upstash variable names exist for the production target, but the presence of names alone does not prove that their values are valid or that Redis is reachable.
- The public-safe `/api/health` snapshot and production smoke workflow now check that browser/server Supabase configuration points to `igqgtlmnwssjaoxkkzbm`, without returning URLs or keys.
- `FIRSTLIGHT_API_URL` and `FIRSTLIGHT_API_TOKEN` are optional; the remote service remains unavailable when unset. Ollama is optional for deterministic analysis.
- Repository migrations now rebind storage policies to `satark_private.has_membership`, and the merged isolated migration tests passed. The hosted schema has not been re-queried after the merge or migrated; evidence upload/download remains unverified in production.
- A prior production query found direct EXECUTE grants on `public.satark_reject_audit_mutation()`. Repository ACL-hardening tests passed, but the hosted grant state has not been re-queried and no hosted migration was applied.

## Required release gates

### 1. Source and CI
- [x] Merge PR #144 after CI, Web CI, CodeQL and isolated Supabase migration validation passed; still verify the hosted schema before rollout.
- [x] Merge PR #149 after tenant/storage pgTAP and required checks passed; still verify the hosted schema before rollout.
- [ ] Confirm PR #155 and any follow-up fixes are merged, with no required functionality only on an unmerged branch.
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
- [x] Merge the CSP fix (PR #154); [ ] verify browser sign-in/session refresh on the exact deployed SHA.
- [ ] Verify request-size, concurrency, timeout and abuse/cost controls, monitoring, log redaction, rollback and backup/recovery procedures.

### 5. Documentation and sign-off
- [ ] Update the README and environment-variable contract to match the final shipped behavior.
- [ ] Record supported file formats and size limits, optional services, retention/deletion behavior and known limitations.
- [ ] Prepare a repeatable synthetic-data demo and capture evidence of the final browser/database workflow.
- [ ] Update `docs/DEPLOYMENT_SIGNOFF.md` only after each applicable gate has evidence.

## Safety boundary

SATARK is a security-awareness and incident-triage prototype, not a certified forensic product or antivirus. FIRSTLIGHT response actions remain simulated; a passing build does not prove the deployed revision is correct, model detections are calibrated, or chain-of-custody evidence is independently anchored. Use synthetic or non-sensitive data until a separate security and operational review approves broader use.
