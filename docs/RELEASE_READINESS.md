# Release readiness and deployment runbook

> Scope: this runbook covers the current SATARK platform: offline Android File Guard, the Next.js operations interface, the self-hosted FIRSTLIGHT API/workers, PostgreSQL persistence, Wazuh-only endpoint telemetry and guarded response. Android File Guard remains independently usable offline; see [LOCAL_OFFLINE_ACCEPTANCE.md](LOCAL_OFFLINE_ACCEPTANCE.md).

This document separates a working hackathon demonstration from a service that is safe for public or sensitive use. Passing CI is necessary, but it is not proof of production readiness.

## Current release posture

- **Hackathon demonstration with synthetic/non-sensitive inputs:** suitable only after the exact deployed revision passes the checks below.
- **Small supervised pilot with non-sensitive content:** conditional on provider, deployment, abuse-control and recovery checks.
- **Public anonymous service using a shared provider key:** **not ready by default**. A shared per-process sliding-window limiter is defense in depth, not a distributed/global quota: multiple workers, replicas or restarts can bypass its aggregate ceiling. A public service still needs gateway/provider-side global quotas, rate limiting, concurrency limits and cost controls.
- **Confidential, regulated or multi-tenant incident evidence:** **not ready** without authenticated access, authorization/tenant isolation, retention and deletion controls, approved provider data handling, durable case storage, and an independently reviewed operational design.
- **Production / high availability:** requires a separate threat model, security review, monitoring, incident response, backup/restore and rollback exercises.

## Current architecture and deployment snapshot — 2026-11-12

- Microsoft Defender and Entra are not runtime providers. Wazuh 4.14.x is the supported endpoint telemetry and guarded response integration; the Microsoft-free source/configuration boundary is enforced in FIRSTLIGHT API CI.
- PR #241 (Wazuh-only integration, PostgreSQL production stack, Restic backup runner and arcade website redesign) is merged into `main` at `fcfbb2e60827c38586d183c62a4feb383f65323e`.
- The Vercel frontend has a READY production deployment for main commit `ac5169c27851c8e2e9bf1918e0d90f8d78e3f02f` (PR #244); the exact-commit build completed successfully and the deployment is READY. Neither deployment is the complete production platform: the Vercel project still lacks `SATARK_API_INTERNAL_URL`, FIRSTLIGHT backend tokens and a configured shared Redis limiter. Production API routes return 503 when the self-hosted backend is absent, and analysis correctly fails closed without shared rate limiting.
- Main commit `ac5169c27851c8e2e9bf1918e0d90f8d78e3f02f` includes the FIRSTLIGHT response-navigation correction: the primary response tab now points to the saved-case Wazuh workflow, training decisions are explicitly labelled, and the live-response status can be refreshed. The Android emulator foreground smoke and production API smoke remain release blockers. PR #242 contains the Android diagnostic/parser repair; its new unit test caught and fixed a false positive where a background app task was mistaken for the foreground while Android's permission controller owned the top-resumed surface. PR #243 updates the exact-SHA release gate and cross-platform CI triggers; its latest checks are still running.
- No SATARK Render service or Render PostgreSQL instance is currently provisioned in the connected workspace. The production Compose stack, Wazuh bootstrap helper and Restic backup runner are source-controlled, but there is no accepted production host, private Wazuh Manager/Indexer/agent fleet, SMTP configuration, independent Restic repository or recovery host recorded here.
- A production release remains blocked until the exact deployed SHA passes all required checks and an authorized live Wazuh ingestion/response drill, real external backup/isolated restore, persistent self-hosted deployment, tenant-isolation smoke, and physical Android device QA are evidenced. Do not substitute mocks, local Compose validation or a Vercel frontend deployment for these gates.

This snapshot is evidence of the repository and connected deployment state checked on the date above. Refresh it after every release-candidate change.

## Before every deployment

1. Record the Git commit SHA, repository, branch, Streamlit entry point and hosting target. Confirm the host deploys the intended repository and branch—not a similarly named fork or stale app.
2. Run the exact-commit CI and CodeQL workflows. Check dependency consistency, Python compilation, unit tests, desktop/mobile browser smoke tests, report download, and the offline sample. Review every new high/critical code-scanning alert on the changed code; do not suppress an alert without a documented, reviewed rationale.
3. Set `GROQ_API_KEY` only in the host's secret manager. Never put real keys in `.streamlit/secrets.toml` committed to Git, source files, screenshots, issue reports or browser code. Rotate any key that may have been exposed.
4. Keep hosted exception details hidden. The repository's Streamlit defaults set `client.showErrorDetails = "none"` and cap a single upload at 50 MB; PDF and image processing have stricter per-format limits. Confirm the host respects these settings and any platform-level request limits.
5. Test without a provider key. The offline sample and deterministic FIRSTLIGHT demo must remain usable, and failed live-provider requests must not be presented as a safe verdict.
6. With a dedicated test key, exercise a successful text scan, vision scan, provider timeout, invalid/revoked key, unavailable model, malformed provider response, and rate-limit response. Verify user-facing errors do not expose secrets, request headers or raw provider payloads.
7. Exercise malformed, encrypted and oversized PDFs; malformed and oversized images; decompression-bomb-like image dimensions; empty and oversized videos; invalid URLs; private/reserved IPs; mixed DNS answers; and redirects to blocked destinations. Confirm rejection is graceful and bounded.
8. Verify the hosting layer enforces request body size, execution timeout, concurrency and outbound network policy. Application URL checks are defense in depth, not a replacement for egress controls.
9. Review the configured AI provider's current data-processing and retention terms before allowing any real user data. Until approved, use synthetic or public non-sensitive content only.
10. Verify the deployed UI, not only local CI: home, FIRSTLIGHT, every scanner mode, session history, PDF export, mobile layout, refresh/restart behavior, logs and resource use.
11. Confirm the privacy notice, acceptable-use language, contact/security-reporting route, data retention/deletion behavior, incident response owner and rollback procedure are current.
12. Record the result, unresolved risks, owner and go/no-go decision. Do not mark a deployment verified unless you actually tested the deployed URL and revision.
13. Keep the FIRSTLIGHT backend self-hosted and independent: use SATARK-owned SQLAlchemy/Alembic persistence, the PostgreSQL production stack and private evidence storage. Do not reintroduce Supabase, Microsoft Defender/Entra, a hosted auth service or remote object-storage dependency into the runtime. Android File Guard remains offline.

## Security and privacy boundaries

- SATARK is a triage aid; scores are not calibrated probabilities, and results do not prove that content is safe or malicious.
- FIRSTLIGHT supports two fixed Wazuh 4.14.x actions (validated-IP firewall drop and validated local-account disable) behind an explicit feature flag that defaults off. Execution requires the authenticated case approval workflow, distinct requester/approver/executor identities, exact target confirmation, an at-most-once response ledger and independent verification. CI uses mocked Wazuh APIs; live provider execution and reversal remain unverified until an authorized disposable-agent drill. The response ledger is backed up, but this is not a certified or independently anchored chain of custody.
- FIRSTLIGHT now has authenticated server-managed sessions, workspace/case authorization, tenant-scoped persistence and PostgreSQL role/RLS integration tests. These are code/CI capabilities, not proof of a configured production database. The self-hosted web process uses process-local rate limiting by default; do not scale it horizontally without a shared limiter or enforce equivalent global limits at the edge.
- Browser access/refresh bearer tokens are not stored in localStorage: the current web client uses same-origin HttpOnly cookie sessions and keeps only non-secret session metadata in memory. `localStorage` stores the active workspace identifier, not an authentication credential. Continue to treat XSS as a security risk and retain CSP, output encoding and dependency review.
- URL fetching uses validated public DNS results, pinned connections and redirect revalidation, but public URL retrieval still requires outbound network restrictions at the hosting layer.
- Upload limits bound input size, but do not guarantee a fixed memory/CPU budget under concurrent workloads.
- Content submitted for AI analysis may leave the host and be processed by the configured provider. Do not submit credentials, OTPs, private keys or sensitive incident data unless the provider and legal basis have been reviewed.
- Do not add analytics, logging or error reporting that captures raw submitted content, provider keys or full sensitive URLs by default.

## Go/no-go record template

- Deployed repository / branch / commit:
- Hosting target / app URL:
- CI run:
- CodeQL run:
- Live provider test:
- File and URL abuse tests:
- Secret and privacy review:
- Resource and concurrency checks:
- Known limitations:
- Rollback path tested:
- Decision / reviewer / date:

A missing answer is an unresolved item, not an implicit pass.

## External release research — checked 2026-10-11

This section records official-source findings relevant to the outstanding deployment gates. It does not replace target-environment testing.

### Streamlit Community Cloud deployment ownership

- The deployment configuration explicitly selects a GitHub repository, branch, and entrypoint; the app's URL alone does not prove which revision is running.
- Streamlit documents that app logs are available only to users with write access to the associated repository, and that only repository administrators can deploy/delete apps. The person who owns/administers the deployment repository must therefore perform the final sync and inspect the build/logs if this project connection is read-only.
- Official references: [Deploy an app](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy), [Trust and security](https://docs.streamlit.io/deploy/streamlit-community-cloud/get-started/trust-and-security), [Connect GitHub](https://docs.streamlit.io/deploy/streamlit-community-cloud/get-started/connect-your-github-account).

### Groq data-handling nuance

- Groq states that inference customer inputs/outputs are not retained by default, but usage metadata is retained. It may temporarily retain inputs/outputs for reliability troubleshooting or abuse investigation for up to 30 days unless the organization enables Zero Data Retention or a longer legal requirement applies.
- Features that depend on storage, such as batch processing and fine-tuning, have separate retention behavior. The project should review the exact endpoints/features used and the account's Data Controls settings before allowing sensitive evidence.
- This is provider documentation, not a project-specific contractual/legal determination. Use synthetic or public non-sensitive content until the owner approves the applicable terms and settings.
- Official reference: [Groq — Your Data in GroqCloud](https://console.groq.com/docs/your-data).

### URL retrieval / SSRF

- The current `url_security.py` implements several useful controls: HTTP(S)-only parsing, rejection of URL credentials, resolution checks against non-global/reserved addresses, IP-pinned connections, TLS hostname verification, redirect revalidation, HTTPS-to-HTTP downgrade rejection, accepted content-type restrictions, response byte limits, and timeouts.
- Existing tests cover mixed public/private DNS answers, private redirect destinations, DNS failures, IPv4-mapped IPv6, non-unicast addresses, and redirect limits. These are meaningful unit-level protections but do not prove the hosted network boundary is safe.
- OWASP recommends disabling automatic redirect following or revalidating each redirect, and recommends allowlists where feasible. SATARK manually follows redirects and revalidates them; hosting-level egress restrictions remain a separate defense-in-depth requirement.
- Official reference: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

### Remaining closure criteria

1. Deployment owner updates the actual configured deployment repository/branch to the approved candidate, then records the resulting deployed SHA from the host/build evidence.
2. Run CI and CodeQL against the exact final candidate SHA; the previously documented green results apply to the earlier PR head, not automatically to later commits.
3. Complete live, provider-free smoke tests and exports first; then use an authorized dedicated test key to exercise provider success, timeout, invalid key, unavailable model and rate-limit paths.
4. Run controlled upload/URL abuse cases and verify bounded failure behavior; do not test against internal or third-party systems without authorization.
5. Verify host-level body/time/concurrency/egress controls and inspect logs for accidental key or submitted-content exposure.
6. Make a human go/no-go decision and assign an owner for rollback, incident handling and privacy questions.

**Current decision remains NO-GO for a verified release** until the deployed revision is identified and the applicable live gates pass.