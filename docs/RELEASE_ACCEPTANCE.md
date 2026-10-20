# SATARK Sentinel release acceptance record

## Candidate

- Repository: `kaustubhdua/Satark`
- Candidate branch: `main`
- Code baseline at this review: `1acf9e1392f3d0110f01cf1a2eed7a4a70946894` (PR #180, Wazuh worker membership revalidation). Current `main` is `ac602e537c4571e7c56a828c4b3038905140a883`, a docs-only release-evidence refresh on top of that code. Re-check the SHA after any later merge before release.
- Source pull request: https://github.com/kaustubhdua/Satark/pull/180
- Decision: **NO-GO for production until the outstanding checks below are evidenced.**

This record distinguishes automated CI evidence from checks that still require a live deployment and authorized provider credentials. A passing CI run is not a production acceptance.

## Automated checks recorded

- PR #174 head `0c607a1004f5a2b9811146b1e195be5a3a78cdd9`: general CI, CodeQL, isolated Supabase migration validation, web validation, and production browser/accessibility smoke passed. The pgTAP suite covers authenticated reads/writes for the six policies being rebound.
- PR #173 head `130670e01087d8663427a85c5bbb37eb4b78f4e4`: FIRSTLIGHT API CI, CodeQL, web validation, and production browser/accessibility smoke passed for empty-window checkpoint advancement.
- The workflow named `Supabase tenant-isolation integration` reported a successful job, but its live least-privilege-account test step was skipped because dedicated test credentials were unavailable. Do not treat that skipped step as evidence of live tenant-isolation success.
- PR #177's 50-assertion pgTAP security suite and PR #178's policy-contract tests passed isolated migration validation. PR #180's FIRSTLIGHT API CI passed for the worker membership-revalidation change.
- The FIRSTLIGHT API CI passed on code baseline `1acf9e1392f3d0110f01cf1a2eed7a4a70946894`. PR #182's docs-only CI and CodeQL passed; a main-branch CI run was cancelled during successive docs-only merges, so use the exact current main SHA and require a fresh successful check before release. Vercel's latest READY production deployment is at SHA `1b6a2dee26498ef6eef5f28ba58062264ff98d07` (main after PR #177), older than the worker fix and production-smoke contract. Production smoke run `39375823346` failed because the live `/` response lacked the expected homepage marker.

These results establish that the listed workflows passed on their exact PR heads. They do not establish that live provider credentials work or that the full production workflow has been accepted.

## Real functionality versus simulated/demo behavior

### Real functionality (subject to environment and runtime configuration)

- The Next.js `/api/analyze` route calls Groq when `GROQ_API_KEY` is configured.
- URLhaus lookups are opt-in and require `SATARK_ENABLE_THREAT_INTEL=true` and `URLHAUS_AUTH_KEY`.
- AbuseIPDB lookups are opt-in and require `SATARK_ENABLE_ABUSEIPDB=true` and `ABUSEIPDB_API_KEY`.
- External reputation lookups have explicit disabled/unavailable states. A no-match result is not proof that content is safe.
- The API route limits request body and input size and has a best-effort in-memory per-instance rate limit. It is not a distributed rate limiter.
- The legacy Streamlit application provides tools that are not all ported to the Next.js UI. Links to the Streamlit app must be understood as a separate runtime.

### Simulated, synthetic, or bounded claims

- FIRSTLIGHT is a synthetic training/demo incident, not a live incident feed.
- FIRSTLIGHT response actions are simulated; do not represent them as real containment or remediation.
- Hashes/audit records generated in the demo are session-level integrity aids and are not independently anchored chain-of-custody evidence.
- A Groq-generated risk score is AI-assisted triage, not a verified verdict or proof that a URL was visited.
- URLhaus no-results and low AbuseIPDB scores do not establish safety.
- Any external response provider or scanner not actually enabled and tested in the deployed environment must be described as unavailable/not configured, not operational.

## Release gate checklist

### P0 — CI and candidate integrity

- [x] Python CI passed on recorded candidate.
- [x] Web CI passed on recorded candidate.
- [x] CodeQL passed on recorded candidate.
- [x] Streamlit workspace-selection browser smoke passed in the recorded CI run.
- [ ] Re-run all required checks after any candidate changes.
- [ ] Resolve any failing Vercel deployment check before merge/release.

### P1 — Provider and API acceptance (must be run against the deployed candidate)

Use only authorized, non-sensitive test inputs. Never paste private, signed, customer, or credential-bearing URLs into a third-party reputation provider.

- [ ] Optional local Ollama: run one benign synthetic event with model assistance enabled; validate schema rejection, timeout, unavailable-model behavior, and safe fallback. Confirm deterministic findings still work with model agents disabled; do not add a hosted AI API-key dependency.
- [ ] URLhaus: explicitly opted-in known test URL or safe provider-documented test fixture; verify no-match and provider unavailable behavior. Confirm the disclosure is visible before sharing.
- [ ] AbuseIPDB: explicitly opted-in public test IP approved for this purpose; verify no-match, provider unavailable, and malformed response behavior.
- [ ] Offline/unconfigured: confirm the UI/API reports unavailable clearly and does not imply successful verification.
- [ ] Invalid JSON, missing input, empty input, invalid URL, and oversized body/input return safe client errors.
- [ ] Repeated requests confirm 429 behavior and recovery after the window. Note that instance-local rate limiting can vary across serverless instances.
- [ ] Confirm no secrets or submitted content are written to application logs.

### P1 — User journey and responsive acceptance

- [ ] Home: navigation, hero CTAs, loading/error states.
- [ ] FIRSTLIGHT: scenario load, workspace switching, findings, audit trail, response simulation disclosures.
- [ ] Investigation: text/URL input, explicit external-sharing controls, loading, result and failure states.
- [ ] Response Center and Audit Trail: empty, populated, refresh, and export states.
- [ ] Supporting scanners, history, uploads, and exports available from the linked Streamlit app.
- [ ] Desktop viewport and mobile viewport; no horizontal overflow or clipped controls.
- [ ] Keyboard-only navigation, visible focus, semantic labels, contrast, reduced motion, and screen-reader names.
- [ ] Capture screenshots and logs against the exact deployed candidate.

### P0 — Deployment and production verification

- [ ] Deploy the exact approved candidate SHA.
- [ ] Verify the Vercel deployment metadata reports the same SHA.
- [ ] Verify the production alias points to that deployment.
- [ ] Smoke-test production routes and API error handling.
- [ ] Complete the P1 provider and user-journey checks against production or an approved environment with identical configuration.
- [ ] Record rollback deployment and recovery steps.
- [ ] Merge only after required checks and deployment gates pass.

## Deployment blocker observed

On 2026-10-20, Vercel reported `api-deployments-free-per-day` (more than 100 deployments in 24 hours). The direct Vercel deployment API also returned HTTP 403. The latest READY production deployment is `dpl_4HRahKGhrAGeEKQdqB2AhRcH4GUJ` at source SHA `1b6a2dee26498ef6eef5f28ba58062264ff98d07`, aliased as `satark-rose.vercel.app` and `satark-jyc-website.vercel.app`; it predates the worker fix and smoke-contract changes. Production smoke run `39375823346` also failed because the live homepage did not contain the expected marker. The project also has SSO protection enabled for all non-custom domains and no configured public custom domain; the smoke failure may be a protection/login response. Do not disable SSO globally. The owner must provide an approved public custom domain or a scoped Vercel protection-bypass secret for CI. Do not repeatedly retry while quota is exhausted or bypass deployment permissions. The project owner must clear the quota through the authorized account path, then deploy the exact current main SHA obtained from `git rev-parse origin/main` and verify it through `/api/version` and the Vercel deployment metadata.

These are environment/account blockers, not passing tests.

## Go/no-go

**NO-GO** until the exact candidate is deployed, its SHA is confirmed, and the outstanding live integration, UI, and production acceptance checks have evidence attached. Do not change this decision based solely on CI passing.
