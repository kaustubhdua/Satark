# SATARK + FIRSTLIGHT — Release evidence snapshot

**Snapshot date:** 2026-10-20 UTC  
**Repository:** [kaustubhdua/Satark](https://github.com/kaustubhdua/Satark)  
**Baseline main SHA:** `b526183023a1bb09b5057c594937e7f2af24a1f7)  
**Decision:** **NO-GO for production use** until the external release gates below are verified.

This is an evidence snapshot, not a claim that all features are production-ready. Results are tied to the stated commit and observations. Do not reuse this record as evidence for a later commit or deployment without rerunning the checks.

## 1. Exact-commit repository checks

At the baseline SHA above, GitHub Actions reported:

- [General CI — success](https://github.com/kaustubhdua/Satark/actions/runs/39380821245)
- [CodeQL — success](https://github.com/kaustubhdua/Satark/actions/runs/39380821303)

The general CI workflow includes Python unit and FIRSTLIGHT API/engine tests, Streamlit browser smoke, Next.js typecheck/test/build validation, and the Supabase tenant-isolation integration job. A successful workflow does not prove that the live tenant-isolation test ran; that job can skip its live-account test when dedicated least-privilege test credentials are absent.

The baseline CI and CodeQL results are green, but production readiness is not established by CI alone.

## 2. User-facing route inventory

The Next.js app router includes these page routes:

| Route | Purpose | Key verification |
|---|---|---|
| `/` | Home/workspace | Navigation, responsive layout, first action |
| `/investigate` | Text/message triage | Input validation, local analysis, rate limit, fallback |
| `/url` | Local URL structure inspection | Must not fetch or transmit the destination or expose query values |
| `/image-review` | Local image metadata/integrity | Type/size/dimensions, SHA-256, no external upload |
| `/qr` | Local QR decoding | Supported formats, non-web payload safety, optional URL-text analysis |
| `/pdf-review` | Local PDF/text extraction | File/page/size limits, extraction errors, source fingerprint |
| `/media-review` | Browser-local video frame sampling | Duration/size/dimension bounds, sampling, resource cleanup |
| `/tools` | Feature directory | Copy and links match actual capabilities |
| `/firstlight` | FIRSTLIGHT incident workflow | Authentication, evidence, findings, timeline, simulation labels |
| `/cases` | Persistent case workspace | Membership, case ownership, notes and persistence |
| `/reports` | Review notes/report export | Correct TXT/JSON output, limitations, persistence status |
| `/learn` | Scam-awareness learning | Quiz, explanations, reset and demo-only disclosure |
| `/login` | Sign-in | Session validation and recovery path |
| `/reset-password` | Password recovery | Invalid/expired link behavior and removal of token fragment |

API route handlers include `/api/analyze`, `/api/audit/verify`, `/api/auth/session`, `/api/cases`, `/api/cases/notes`, `/api/evidence`, `/api/evidence/records`, `/api/evidence/[id]/verify`, `/api/findings`, `/api/firstlight/approvals`, `/api/firstlight/evidence/source`, `/api/firstlight/investigate`, `/api/firstlight/jobs`, `/api/firstlight/wazuh/alerts`, `/api/health`, `/api/reports`, `/api/reports/[id]`, and `/api/version`.

The legacy Streamlit app also exposes text, URL, image, QR, PDF, video, reports, history, and learning workflows. Its deployed runtime must be tested separately from the Next.js deployment; one app's successful smoke test does not prove the other is healthy.

## 3. Existing automated test coverage

Repository tests cover deterministic analysis, URL security and URL inspection, file input processing, image/PDF/video review, reports, learning, FIRSTLIGHT engine/API/agents, Wazuh ingestion and workers, response-action contracts, persistent workflows, rate limiting, API validation, tenant-isolation contracts, browser navigation, accessibility, and responsive overflow.

The production browser smoke covers desktop, mobile and narrow-mobile viewports and exercises several key interactions. Any feature not explicitly exercised by an automated test still needs a reproducible manual verification record. Passing axe-core checks is not a substitute for manual keyboard and screen-reader testing.

## 4. Current external release blockers

### Supabase — confirmed by read-only inspection

Project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) is a shared project also used by other applications. Do not reset it, seed fake production tenants, or make broad schema changes.

The current migration history query showed the expected storage-policy migrations `20261020042449` and `20261020044018`, but not all versions required by the documented history repair. The repository migrations `20261020050000_satark_foreign_key_support_indexes.sql` and `20261020051000_satark_rebind_membership_policies.sql` are not recorded as applied.

Read-only verification found:

- The five expected support indexes are absent.
- Six policies on approvals, case notes, and investigation jobs still reference `public.satark_has_membership`.
- `EXECUTE` is denied for that public wrapper to both `authenticated` and `anon`, while `satark_private.has_membership` is executable by `authenticated`.

This can make relevant operations fail closed. Follow [the guarded migration-history repair procedure](SUPABASE_MIGRATION_HISTORY_REPAIR.md) exactly. First verify the linked project, repair only the documented migration history from a trusted CLI, then run `supabase db push --dry-run --linked`. Apply changes only if the dry-run lists exactly the two expected pending SATARK migrations. Verify indexes, policies, function grants, migration history and tenant-isolation tests afterward. Do not run a broad `supabase db push` if the result differs.

### Vercel — deployment identity not proven

The Vercel project `satark` reports a READY production deployment and aliases `satark-rose.vercel.app` and `satark-jyc-website.vercel.app`. However, the Vercel deployment-list API returned HTTP 403 for the connected account, so the deployed source SHA could not be independently established from the deployment listing. The previously recorded production deployment predates the current baseline SHA.

The project has SSO protection enabled for non-custom domains. A recent deployment attempt was reported as blocked by the daily deployment quota, and unauthenticated smoke tests have failed on content markers that may be served by the protection/login page or a stale deployment. Do not disable SSO globally or bypass quotas. The authorized project owner must resolve quota/access through normal account controls, configure the documented scoped smoke-bypass secret or provide an approved public custom domain, deploy the approved SHA, and verify the actual deployment SHA and route responses.

### FIRSTLIGHT API / Wazuh / private worker — not provisioned or live-validated

The recorded Vercel environment inventory has Supabase, Upstash, and optional Ollama settings, but no `FIRSTLIGHT_API_URL`, `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, Wazuh Indexer credentials, or private worker-host configuration. No authorized Wazuh lab endpoint and test tenant/member/actor were available for an end-to-end run.

An authorized operator must provision the API and private worker in the intended environment, use strong secrets, configure an isolated test tenant and Wazuh lab, then verify ingestion → normalization → evidence storage → investigation → report, including retries, checkpoint safety, duplicate prevention, membership revocation, restart/recovery and backup restore.

Keep Defender isolation, Entra session revocation, and all real response actions disabled until an authorized end-to-end lab test verifies target binding, least privilege, human approval, audit records, idempotency and rollback.

## 5. Feature status language

Use these labels consistently in the README and demo:

- **Verified:** reproduced on the exact stated commit/environment with recorded test evidence.
- **Implemented, not live-verified:** source and tests exist, but real provider/deployment behavior has not been demonstrated.
- **Partial / optional:** capability is bounded, depends on configuration, or intentionally does not perform a broader advertised task.
- **Blocked:** required configuration, access, or safe operational prerequisites are missing.
- **Simulation:** no real external response action is performed.

A SHA-256 match proves byte consistency against the selected reference; it does not prove evidence authenticity or truth. A deterministic score is not a calibrated probability. No match or a failed provider request is not proof that content is safe. Session-local audit data is not a durable, independently anchored chain of custody.

## 6. Release acceptance checklist

- [ ] Reconcile Supabase migration history with the documented guarded procedure.
- [ ] Confirm dry-run shows exactly the two expected SATARK migrations, then apply and verify them.
- [ ] Verify all five support indexes, six corrected policies, RLS and function grants.
- [ ] Run authorized tenant-isolation tests with dedicated least-privilege test accounts (not a skipped integration test).
- [ ] Deploy the approved current main SHA and independently verify the deployment source SHA.
- [ ] Resolve protected-domain smoke testing without disabling SSO globally.
- [ ] Provision and validate the private FIRSTLIGHT API/worker and authorized Wazuh lab.
- [ ] Complete an end-to-end ingestion-to-report run and recovery/backup restore test.
- [ ] Re-run CI, Web CI, CodeQL, migration validation and browser/accessibility smoke on the release candidate.
- [ ] Complete manual keyboard, screen-reader and supported-browser review.
- [ ] Verify all advertised features against the feature matrix and document every optional or unsupported capability.
- [ ] Assemble final screenshots, synthetic demo data, test links, commit SHA, deployment identity, limitations and release decision.

**Release decision remains NO-GO for production use until all applicable blockers above have evidence of completion.** A supervised academic demo using synthetic/non-sensitive data can be considered separately once the deployed revision is verified and the demo's limits are disclosed.
