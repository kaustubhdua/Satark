# Release readiness and deployment runbook

This document separates a working hackathon demonstration from a service that is safe for public or sensitive use. Passing CI is necessary, but it is not proof of production readiness.

## Current release posture

- **Hackathon demonstration with synthetic/non-sensitive inputs:** suitable only after the exact deployed revision passes the checks below.
- **Small supervised pilot with non-sensitive content:** conditional on provider, deployment, abuse-control and recovery checks.
- **Public anonymous analysis service:** **not ready by default**. A shared per-process sliding-window limiter is defense in depth, not a distributed/global quota: multiple workers, replicas or restarts can bypass its aggregate ceiling. A public service still needs gateway-level global quotas, rate limiting, concurrency limits and cost controls.
- **Confidential, regulated or multi-tenant incident evidence:** **not ready** without authenticated access, authorization/tenant isolation, retention and deletion controls, approved provider data handling, durable case storage, and an independently reviewed operational design.
- **Production / high availability:** requires a separate threat model, security review, monitoring, incident response, backup/restore and rollback exercises.

## Before every deployment

1. Record the Git commit SHA, repository, branch, Streamlit entry point and hosting target. Confirm the host deploys the intended repository and branch—not a similarly named fork or stale app.
2. Run the exact-commit CI and CodeQL workflows. Check dependency consistency, Python compilation, unit tests, desktop/mobile browser smoke tests, report download, and the offline sample. Review every new high/critical code-scanning alert on the changed code; do not suppress an alert without a documented, reviewed rationale.
3. The current Python/Streamlit analysis client uses self-hosted Ollama and does not require a third-party API key. Configure `OLLAMA_BASE_URL` only for an operator-controlled localhost/private-network Ollama service; never expose an Ollama endpoint publicly. Do not add API keys to `.streamlit/secrets.toml` committed to Git, source files, screenshots, issue reports or browser code. If a legacy provider integration is intentionally reintroduced, keep its credential in the host's secret manager and review its data-processing terms first.
4. Keep hosted exception details hidden. The repository's Streamlit defaults set `client.showErrorDetails = "none"` and cap a single upload at 50 MB; PDF and image processing have stricter per-format limits. Confirm the host respects these settings and any platform-level request limits.
5. Test without third-party API credentials. The offline sample and deterministic FIRSTLIGHT demo must remain usable, local-model failures must degrade safely, and failed optional external lookups must never be presented as proof that content is safe.
6. With a dedicated non-production Ollama instance and pinned test models, exercise a successful text scan and supported vision scan, connection timeout, unavailable model, malformed model output, oversized response, and rate-limit response. Verify deterministic fallback and user-facing errors do not expose secrets, request headers or raw provider payloads. Do not treat local inference as a calibrated or exhaustive detection verdict.
7. Exercise malformed, encrypted and oversized PDFs; malformed and oversized images; decompression-bomb-like image dimensions; empty and oversized videos; invalid URLs; private/reserved IPs; mixed DNS answers; and redirects to blocked destinations. Confirm rejection is graceful and bounded.
8. Verify the hosting layer enforces request body size, execution timeout, concurrency and outbound network policy. Application URL checks are defense in depth, not a replacement for egress controls.
9. Review the configured AI provider's current data-processing and retention terms before allowing any real user data. Until approved, use synthetic or public non-sensitive content only.
10. Verify the deployed UI, not only local CI: home, FIRSTLIGHT, every scanner mode, session history, PDF export, mobile layout, refresh/restart behavior, logs and resource use.
11. Confirm the privacy notice, acceptable-use language, contact/security-reporting route, data retention/deletion behavior, incident response owner and rollback procedure are current.
12. Record the result, unresolved risks, owner and go/no-go decision. Do not mark a deployment verified unless you actually tested the deployed URL and revision.

## Security and privacy boundaries

- SATARK is a triage aid; scores are not calibrated probabilities, and results do not prove that content is safe or malicious.
- FIRSTLIGHT response actions are simulated. Its in-session audit chain is not durable, independently anchored evidence storage or certified chain of custody.
- Session state is not authenticated case storage and is not tenant isolation. The analysis limiter is process-local; it is not a durable or distributed abuse-control boundary.
- URL fetching uses validated public DNS results, pinned connections and redirect revalidation, but public URL retrieval still requires outbound network restrictions at the hosting layer.
- Upload limits bound input size, but do not guarantee a fixed memory/CPU budget under concurrent workloads.
- Content submitted for AI analysis may leave the host and be processed by the configured provider. Do not submit credentials, OTPs, private keys or sensitive incident data unless the provider and legal basis have been reviewed.
- Do not add analytics, logging or error reporting that captures raw submitted content, provider keys or full sensitive URLs by default.

## Go/no-go record template

- Deployed repository / branch / commit:
- Hosting target / app URL:
- CI run:
- CodeQL run:
- Local-model and optional external-lookup tests:
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

### Legacy Groq data-handling note (not the current default)

The current `ai_provider.py` client uses self-hosted Ollama and does not call Groq. The following historical provider note applies only if a separately reviewed legacy Groq integration is deliberately reintroduced; it is not a description of the current default data path.

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
3. Complete live, credential-free smoke tests and exports first. Then test local Ollama success, timeout, unavailable model and malformed output with a dedicated non-production instance; separately test any explicitly enabled external threat-intelligence integration with authorized test credentials.
4. Run controlled upload/URL abuse cases and verify bounded failure behavior; do not test against internal or third-party systems without authorization.
5. Verify host-level body/time/concurrency/egress controls and inspect logs for accidental key or submitted-content exposure.
6. Make a human go/no-go decision and assign an owner for rollback, incident handling and privacy questions.

**Current decision remains NO-GO for a verified release** until the deployed revision is identified and the applicable live gates pass.