# SATARK production acceptance: environment runbook

Status: **BLOCKED until the environment owner completes the checks below.**
Last verified against repository workflow evidence: 2026-10-22.
Baseline: `fba9b3590be977182a1e35b207f745654980966f`.

This runbook is an execution checklist, not proof that a secret, provider, deployment, or security test is configured. Never put secret values in this file, issue comments, logs, or test artifacts.

## 1. Confirm production ownership before changing configuration

The production smoke workflow targets `https://satark-rose.vercel.app`. At the baseline above, the production smoke failed because browser/server Supabase configuration was missing or mismatched; the workflow expected SATARK project ref `igqgtlmnwssjaoxkkzbm`. This expected ref must be reconciled with the environment owner's approved architecture and the read-only report in `docs/engineering/SAATHI_SATARK_ENVIRONMENT_RECONCILIATION_2026-10-22.md` before setting production variables.

The connected Vercel deployment context previously showed no project linked to `kaustubhdua/Satark`. Confirm the actual project that owns the production alias and its Git integration. Do not create a second project or repoint the alias until ownership is established.

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

Configure these GitHub Actions secrets through repository Settings → Secrets and variables → Actions:

- `SUPABASE_URL`
- `SUPABASE_PUBLISHABLE_KEY`
- `SATARK_TEST_USER_A_EMAIL`
- `SATARK_TEST_USER_A_PASSWORD`
- `SATARK_TEST_TENANT_A_ID`
- `SATARK_TEST_USER_B_EMAIL`
- `SATARK_TEST_USER_B_PASSWORD`
- `SATARK_TEST_TENANT_B_ID`
- `SATARK_TEST_VIEWER_EMAIL`
- `SATARK_TEST_VIEWER_PASSWORD`
- `SATARK_TEST_VIEWER_TENANT_ID`

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
