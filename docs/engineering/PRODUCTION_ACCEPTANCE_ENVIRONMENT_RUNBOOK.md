# SATARK production acceptance: environment runbook

Status: **BLOCKED until the environment owner completes the checks below.**
Last verified against repository workflow evidence: 2026-10-22.
Baseline: `fba9b3590be977182a1e35b207f745654980966f`.

This runbook is an execution checklist, not proof that a secret, provider, deployment, or security test is configured. Never put secret values in this file, issue comments, logs, or test artifacts.


## Live recheck — 2026-10-26

**Release decision: NO-GO.** This section supersedes the baseline date for current release blockers; historical evidence below is retained.

- **Audit baseline `main` SHA:** `fba9b3590be977182a1e35b207f745654980966f` (the revision used for this initial production recheck; subsequent commits must be verified separately).
- **Vercel production deployment:** Vercel API reports alias `satark-rose.vercel.app` is attached to deployment `satark-ass053dpx-jyc-website.vercel.app`, state `READY`, target `production`, source branch `main`, commit `fba9b3590be977182a1e35b207f745654980966f`. This confirms which commit is deployed; it does **not** establish runtime readiness.
- **Latest scheduled production smoke:** [run 40177404513](https://github.com/kaustubhdua/Satark/actions/runs/40177404513) failed on 2026-10-25. Public routes and baseline security headers passed, as did unauthenticated API rejection checks. Release checks still report production Supabase browser/server configuration missing or mismatched, shared rate limiting not configured/verified, and the FIRSTLIGHT proxy readiness gate unresolved. A successful HTTP page response is not a release pass.
- **Latest CI on `main`:** [run 39688785640](https://github.com/kaustubhdua/Satark/actions/runs/39688785640) failed because the authenticated Supabase tenant-isolation job could not find its dedicated least-privilege test credentials. Python regression tests, Next.js validation and browser/accessibility smoke passed; the actual tenant-isolation integration did not run. [CodeQL run 39688785694](https://github.com/kaustubhdua/Satark/actions/runs/39688785694) passed.
- **Supabase project identity:** the connected Supabase API identifies project `igqgtlmnwssjaoxkkzbm` as `nihdhoom` in `ap-south-1`; the production smoke expects this project ref. This is a shared project containing multiple applications. Do not change production auth/storage/database routing until the environment owner confirms the intended tenant/auth migration and existing user implications.
- **Vercel configuration write limitation:** the connected Vercel project listing finds project `satark`, but project-scoped variable update/inspection calls return `404 project not found` for the selected scope. No production variable was changed by this review. Resolve project/team ownership in Vercel, then configure values using the table below.
- **Real-world acceptance remains absent:** no verified Wazuh host/agent event has been observed end to end in this review; no authorized persistent worker/endpoint evidence acceptance, isolated authenticated tenant test, backup/object restore, or provider-observed live response has been demonstrated. Keep live response disabled.

### Exact next actions (do not bypass)

1. Resolve the Vercel project/team scope with an owner who can edit the `satark` project. Confirm intended Supabase auth project before changing environment values. Set matching browser/server Supabase URL and publishable key, then run `/api/health` and the production smoke.
2. Configure valid Upstash REST URL/token for Production. Verify actual connectivity and atomic expiry behavior; `/api/health` is only a configuration snapshot. Do not downgrade production to process-local rate limiting.
3. Provision three dedicated ordinary test users and separate SATARK-only tenant fixtures in the approved disposable integration environment. Add the secret names listed in section 4, then require the real tenant-isolation job to pass rather than skip.
4. Configure a genuine authorized Wazuh lab and a private persistent worker; pass `scripts/accept_firstlight_wazuh_live.py` and `scripts/accept_firstlight_worker_live.py` against real source data and preserve sanitized evidence of the run.
5. Test evidence object restoration separately from Postgres restoration, then run an authorized harmless response through durable approval → execution → provider-side verification. Until that passes, advertise response as simulation-only.
6. Re-run all required checks on one frozen SHA, deploy that exact SHA, rerun production smoke, and record the result before release.

## 1. Confirm production ownership before changing configuration

The production smoke workflow targets `https://satark-rose.vercel.app`. At the baseline above, the production smoke failed because browser/server Supabase configuration was missing or mismatched; the workflow expected SATARK project ref `igqgtlmnwssjaoxkkzbm`. Reconcile that expectation with the environment owner's approved architecture and `docs/engineering/SAATHI_SATARK_ENVIRONMENT_RECONCILIATION_2026-10-22.md` before changing production variables.

The connected Vercel deployment context did not show a Git project linked to `kaustubhdua/Satark`. A project named `satark` appears in the Vercel project list, but its details could not be verified with the connected project-inspection action. Confirm the actual project that owns the production alias and its Git integration. Do not create a duplicate project or repoint the alias until ownership is established.

## 2. Production web environment variables

Set values through the authorized hosting provider's encrypted environment-variable UI. Use separate values/scopes for Production, Preview, and Development.

| Variable | Required purpose | Validation |
| --- | --- | --- |
| `SUPABASE_URL` | Server-side Supabase project URL | HTTPS URL; project ref matches approved production project |
| `SUPABASE_PUBLISHABLE_KEY` | Server-side publishable key used by current client code | Present; never log its value |
| `NEXT_PUBLIC_SUPABASE_URL` | Browser Supabase project URL | Same approved project as `SUPABASE_URL` |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Browser publishable key | Matches the approved project's public client configuration |
| `UPSTASH_REDIS_REST_URL` | Shared production rate-limit endpoint | HTTPS URL; connectivity verified with a safe request |
| `UPSTASH_REDIS_REST_TOKEN` | Shared rate-limit credential | Present and least-privileged; rotate if exposed |
| `FIRSTLIGHT_API_URL` | Server-side FIRSTLIGHT backend origin | HTTPS production endpoint; no credentials, query, or fragment in URL |
| `FIRSTLIGHT_API_TOKEN` | Server-to-server investigation proxy token | At least 32 characters; server-only |
| `FIRSTLIGHT_WAZUH_SYNC_TOKEN` | Server-to-server Wazuh sync token | At least 32 characters; server-only |

The health endpoint is configuration-only: it does not prove database, Redis, or FIRSTLIGHT connectivity. Run the production smoke workflow after configuration and confirm the smoke reports real success. Never put private credentials in any `NEXT_PUBLIC_*` variable.

Optional local model configuration (`SATARK_OLLAMA_BASE_URL`, `SATARK_OLLAMA_MODEL`) is not a production requirement for deterministic local analysis. Any third-party threat-intelligence credentials must remain opt-in, server-only and explicitly documented.

## 3. Shared rate limiting is a release blocker

On Vercel, `/api/analyze` intentionally fails closed when shared Upstash rate limiting is missing or misconfigured. Do not change it to silently use an in-process limiter in production. After configuring both Upstash values:

1. Confirm `/api/health` reports `rateLimit.mode=shared-upstash` and `sharedAcrossInstances=true`.
2. Verify live Redis connectivity and correct expiry/atomic behavior; the health snapshot alone does not verify connectivity.
3. Exercise allowed requests, limit exhaustion (429), `Retry-After`, and recovery after the window.
4. Verify analysis returns a valid deterministic result after the limiter is available.
5. Verify no tokens or submitted user content appear in logs.

## 4. Dedicated Supabase integration-test environment

Do not run cross-tenant write/delete tests against shared production data. Create/select a disposable non-production project and create three dedicated identities: Tenant A owner, Tenant B owner, and restricted viewer. Use only IDs belonging to that disposable environment.

Configure these **exact GitHub Actions secret names** through repository Settings → Secrets and variables → Actions. These names match the environment mapping in `.github/workflows/ci.yml`:

- `SATARK_TEST_SUPABASE_URL`
- `SATARK_TEST_SUPABASE_PUBLISHABLE_KEY`
- `SATARK_TEST_USER_A_EMAIL`
- `SATARK_TEST_USER_A_PASSWORD`
- `SATARK_TEST_TENANT_A_ID`
- `SATARK_TEST_USER_B_EMAIL`
- `SATARK_TEST_USER_B_PASSWORD`
- `SATARK_TEST_TENANT_B_ID`
- `SATARK_TEST_VIEWER_EMAIL`
- `SATARK_TEST_VIEWER_PASSWORD`
- `SATARK_TEST_VIEWER_TENANT_ID`

The workflow maps the first two secrets into runtime environment variables named `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`; do not create duplicate Actions secrets under those runtime names unless another workflow explicitly requires them.

Use unique strong credentials, do not reuse personal accounts, and never paste values into chat or commit them. Run the `CI` workflow on the exact candidate SHA. The job `Supabase tenant-isolation integration` and step `Run real Supabase tenant and role isolation tests` must both conclude success; a skipped step is not a pass.

Required cases include cross-tenant read/write denial, viewer write denial, revoked membership, direct API access, forged/expired credentials, approval authorization, and concurrent/replayed operations. Tear down only the disposable test identities/data after preserving sanitized evidence.

## 5. Provider-backed acceptance gates

- **Wazuh:** use an authorized lab and read-only credentials. Ingest genuine benign alerts and prove source/index/document identifiers, timestamps, durable persistence, digests, checkpointing, idempotent replay, pagination, restart recovery, and malformed/unauthorized response handling.
- **Endpoint telemetry:** test the supported Linux sensor on real disposable hosts; verify log rotation/truncation, permission errors, malformed/large inputs, file baseline changes, and restart recovery. Do not claim Windows support unless tested on a real authorized Windows host.
- **Response:** keep live actions disabled until authenticated approval is connected to the durable approval lifecycle. Verify exact target/action/payload binding, expiry, actor/tenant authorization, one-time consumption, replay/concurrency rejection, and provider-observed effect in a controlled lab.
- **Evidence:** export persisted evidence, independently recompute digests, and show altered/truncated/missing records are detected.
- **Detection/AI:** run held-out positive and negative controls; record false positives/negatives and latency. Clearly distinguish deterministic findings, AI assistance, fixtures and simulations.

## 6. Exact-SHA release procedure

1. Freeze the candidate SHA and confirm it is the intended commit on `main`.
2. Require successful CI, Web CI and CodeQL for that exact SHA; investigate any failure instead of bypassing the gate.
3. Run tenant integration with no skipped real-test step.
4. Confirm reviewed migration/schema/policy differences and verified backup/restore; no blind migration push/reset.
5. Deploy the exact SHA through the authorized Vercel project.
6. Run production smoke. Verify public routes, baseline headers, protected API 401s, health configuration, shared limiter and a harmless analysis request.
7. Verify live deployment metadata/commit and inspect runtime logs for errors and secret leakage.
8. Attach sanitized run URLs, SHA, project ref, test counts, and actual provider acceptance evidence to the release record.
9. Only mark a gate complete when its evidence exists. Never infer live provider acceptance from mocks, fixtures, CI-only tests, a green build, or a configuration snapshot.

## 7. Current known blockers at the baseline

- Production smoke failed: production Supabase browser/server configuration was missing or mismatched.
- Production analysis is correctly unavailable if shared rate limiting is absent; configure and verify the shared limiter.
- Tenant-isolation integration failed because dedicated test-account secrets were not provisioned.
- Wazuh live ingestion, provider-observed response, full evidence acceptance and exact-SHA production release must be proven with authorized environments.
- The repository's release-gate workflow requires explicit evidence for migrations, tenant isolation, Windows/Linux telemetry, detection controls, evidence integrity, AI evaluation and a real responder. These must not be attested until actually performed.

This runbook does not authorize changing shared Saathi/Nirdhoom database objects or enabling live response. Environment-owner approval and isolated acceptance are required.
