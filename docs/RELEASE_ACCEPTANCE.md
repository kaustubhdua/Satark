# SATARK Sentinel release acceptance record

## Candidate

- Repository: `kaustubhdua/Satark`
- Candidate branch at the time of this record: `main`
- Candidate commit at the time of this record: `pending-merge`
- Source pull request: https://github.com/kaustubhdua/Satark/pull/45
- Decision: **NO-GO for production until the outstanding checks below are evidenced.**

This record distinguishes automated CI evidence from checks that still require a live deployment and authorized provider credentials. It must be updated with a new commit SHA if the candidate changes.

## Automated checks recorded

For candidate `5abb923aefb749ccf04be87ddc047e91a1390d46`:

- Python CI: passed — https://github.com/kaustubhdua/Satark/actions/runs/38154230216
- Web CI: passed — https://github.com/kaustubhdua/Satark/actions/runs/38154230215
- CodeQL: passed — https://github.com/kaustubhdua/Satark/actions/runs/38154230200
- Python browser-smoke artifact: `satark-browser-smoke`, artifact ID `11707622682`.

These results establish that the listed workflows passed on that commit. They do not establish live provider credentials work or that all journeys have been manually accepted in production.

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

- [ ] Groq: one benign synthetic message; validate schema, timeout, 401/403, 429, and 5xx behavior.
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

The Vercel deployment API returned `402 payment_required` with resource `api-deployments-free-per-day` and `retryAfter=86400`. The latest confirmed ready preview was commit `a794e6e9eca1b445ad93c07e90e278ff6f732a82`, not this candidate. Production was still on `0c90f1aef80c2ec405192deef027707ba0313979` at the time of verification.

The browser automation provider reported a negative remaining credit balance (`-992`), so interactive live-browser acceptance could not be completed through that service. These are environment/account blockers, not passing tests.

## Go/no-go

**NO-GO** until the exact candidate is deployed, its SHA is confirmed, and the outstanding live integration, UI, and production acceptance checks have evidence attached. Do not change this decision based solely on CI passing.
