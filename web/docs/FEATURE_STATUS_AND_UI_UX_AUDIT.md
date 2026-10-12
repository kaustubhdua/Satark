# SATARK release hardening follow-up

Audit date: 2026-10-11. This section separates code/CI evidence from real deployment and provider verification.

## P0 / P1 / P2 execution status

- P0 release gate: PR #41 was merged after Web CI, root CI, and CodeQL all reported success for its final PR head. This verifies the CI checks on that head; it does not prove the merged deployment is live or that external API credentials work.
- P0 live provider verification: not completed in this environment. No provider credentials were read or exposed. Run authorized staging tests for Groq, URLhaus and AbuseIPDB; keep URLhaus/AbuseIPDB feature flags disabled until their tests pass.
- P1 API boundary: request body/input bounds and per-instance throttling exist. A per-instance map is not a distributed abuse control. Add a Vercel/platform-level rate limit or shared store before high-traffic public exposure. Baseline security response headers are being added in the follow-up branch; verify actual headers against a deployed build.
- P1 response latency: independent URLhaus and AbuseIPDB calls now run concurrently, each with a five-second timeout, instead of serially. This reduces worst-case additive waiting but does not guarantee provider availability.
- P1 accessibility: CI browser smoke checks are not a full WCAG audit. Keyboard, screen-reader, contrast, zoom, reduced-motion and mobile visual review still need a human pass; add axe-based automated coverage.
- P2 reports: report export now supports plain-text notes and a versioned JSON envelope. It still exports only what the user typed; it does not automatically bundle analysis findings, evidence, external lookups or a verified chain of custody.
- P2 history: no durable authenticated investigation history is established in this app. Current state is session/page memory unless a feature explicitly says otherwise.
- P2 integrations: the FIRSTLIGHT training workflow remains synthetic; Microsoft live-response adapters in PR #40 are not implied to be enabled or production-verified by merging PR #41. Streamlit-linked media tools remain separate handoffs and must be tested in their own deployment.


## Deployment verification runbook (required before public launch)

### 1. Configure the Vercel edge rate limit (required before public launch)

The in-process map in `web/src/app/api/analyze/route.ts` is only a best-effort fallback. It resets on cold starts and is not shared across instances. The automated test verifies that this fallback rejects the ninth request per minute in one process; it does **not** prove a distributed production limit.

In the Vercel dashboard, open project **satark-qzym** → **Firewall** → **Configure** → **New Rule**, then create and publish this custom rule:

| Setting | Value |
|---|---|
| Name | SATARK Analyze API Rate Limit |
| Conditions (all must match) | Request Path equals `/api/analyze`; Method equals `POST` |
| Action | Rate Limit |
| Strategy | Fixed Window |
| Time window | 60 seconds |
| Request limit | 8 |
| Counting key | IP |
| Exceeded action | Deny / HTTP 429 |

After publishing, send nine requests from one controlled test client within a minute and verify that the edge returns 429 for excess requests and the rule appears in Firewall traffic analytics. Vercel's edge counter is per-region, so it is a shared edge control but not a mathematically exact global counter across all regions. Keep the in-process guard as defense in depth.

Confirm the platform overwrites `x-real-ip`; do not trust caller-controlled forwarding headers. If the rule cannot be published and verified, do not expose the endpoint broadly. Never put provider keys in `NEXT_PUBLIC_*` variables.

### 2. Verify environment without exposing secrets

In the intended Vercel project and each intended environment (Preview/Production), verify the presence of server-only `GROQ_API_KEY`. Keep `SATARK_ENABLE_THREAT_INTEL` and `SATARK_ENABLE_ABUSEIPDB` false/unset until each provider has passed the controlled tests below. Configure `URLHAUS_AUTH_KEY` and `ABUSEIPDB_API_KEY` only as server-side secrets. Never use `NEXT_PUBLIC_` for provider keys, paste keys into issues/logs, or include full signed/private URLs in provider tests.

### 3. Authorized, non-sensitive staging checks

Record timestamp, deployment URL, environment, HTTP status, and a redacted outcome—not request bodies or secrets.

| Check | Procedure | Pass condition |
|---|---|---|
| Groq success | Submit a fabricated harmless message with no real personal data | HTTP 200; bounded schema; limitations present; no key in client bundle/logs |
| Groq missing key | Use an isolated preview environment with the key omitted | HTTP 503; no stack trace or secret disclosure |
| Groq failure | Use a controlled provider outage/quota scenario if safely available | Clear 502/429; no unhandled exception; timeout returns promptly |
| URLhaus consent | Submit a harmless test URL with consent off, then on only in an approved test environment | Off makes no outbound URLhaus call; on reports match/no-match/unavailable truthfully; no-match is not shown as safe |
| AbuseIPDB consent | Submit a public, non-sensitive test IP with consent off, then on only in an approved test environment | Off makes no outbound call; on queries only a validated IP literal and shows inconclusive states honestly |
| Body bounds | Send malformed JSON, empty input, oversized body, and oversized input | 400/413 with generic messages; no provider call |
| Rate limit | Send more than 8 requests from one controlled client within a minute and repeat across instances | 429 at the configured edge limit; limit remains effective across cold starts/instances |
| Headers | Inspect homepage and API responses in the deployed environment | Expected security headers present; API responses remain no-store |
| Browser | Exercise primary flow on desktop and narrow mobile; keyboard-only and reduced-motion | No broken primary path, focus traps, horizontal overflow, or motion-dependent information |

Do not mark any provider **Live** until its successful controlled test is recorded. Never use private/signed URLs for reputation lookups: URLhaus receives the full extracted URL after consent.

### 4. Accessibility and UI acceptance

Automated browser smoke tests are not a WCAG conformance claim. Run an axe-based scan on the home, investigate, reports, and learning routes, then manually verify keyboard order/visible focus, screen-reader labels and announcements, 200% zoom/reflow, text and non-text contrast, reduced motion, and mobile tap targets. Log each failure and retest after fixes.

### 5. Legacy handoff and rollback

Open each image/deepfake, QR, PDF/document, and video/media handoff from the deployed Next.js app and verify the destination is reachable, accepts supported safe sample inputs, explains upload/privacy limits, and fails accessibly. Confirm health monitoring, provider error alerts, deployment rollback procedure, and the last known-good build before public launch.

## Feature truth labels

Use these definitions in the UI and release notes:
- **Live**: a real external provider or deployed service was called successfully in a controlled test, with timestamped evidence.
- **Implemented, not live-verified**: code exists but valid deployment credentials or a successful end-to-end call have not been demonstrated.
- **Synthetic/simulated**: data or actions are generated locally for training; no real account, endpoint or provider is changed.
- **Local-only**: browser memory or downloads; no server persistence.
- **Handoff**: navigation to a separate app; it is not native functionality in this Next.js app.
- **Unavailable/disabled**: configuration or provider state prevents the feature from running.


## Browser security headers — current baseline

The Next.js response policy now includes HSTS and a baseline Content-Security-Policy with `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, and same-origin resource defaults. Automated browser checks assert these headers across desktop/mobile routes. The static-rendering-compatible policy permits `'unsafe-inline'` for scripts to preserve Next.js hydration; it is defense-in-depth, **not** a strict nonce/hash CSP and does not replace XSS prevention. A future hardening pass should evaluate nonce-based CSP against the app's static-rendering and performance requirements before tightening script policy. Confirm HSTS on the intended production hostname and HTTPS deployment before public launch.

# SATARK feature status and UI/UX review

Audit date: 2026-10-11
Scope: Next.js app source on `improve/analysis-safety-and-ux-followup`, current workflow evidence, and the five inspiration repositories reviewed below. This is a source-and-CI audit, not a claim that every external integration was exercised against production credentials.

## Feature status

| Feature | Status | Evidence / limitation | Work needed |
|---|---|---|---|
| Home page, shared navigation, responsive CSS | Implemented; automated desktop/mobile smoke checks pass | Browser smoke checks validate routes and basic interactions, not full visual QA across every browser/device | Do visual review at common widths, keyboard-only review, contrast audit, and verify every link destination |
| Text/message triage | Implemented, provider-dependent | `POST /api/analyze` calls Groq using server-side `GROQ_API_KEY`; response schema is validated and bounded | Test real key in a controlled staging deployment, handle provider quota/timeouts, add provider contract tests |
| URL triage | Implemented as text analysis only | URL is not fetched by the analyzer; simple regex indicators are not a reputation verdict | Clearly distinguish heuristics from verified intel; add SSRF-safe reputation lookups only behind consent/flags |
| Deterministic signals | Implemented, intentionally basic | Detects urgency/pressure, credential/code requests, payment/prize language, and URL presence | Add a versioned, tested ruleset; tests for false positives/negatives and Unicode/obfuscation |
| URLhaus reputation lookup | Implemented on this branch, opt-in + server flag | Requires `URLHAUS_AUTH_KEY` and `SATARK_ENABLE_THREAT_INTEL=true`; timeout and inconclusive states handled. Sends the extracted full URL, including path/query, only after explicit user consent | Keep feature flag off until key/API contract is tested in staging; never submit private/signed URLs; add provider mock/contract tests and verify response schema against current API |
| AbuseIPDB reputation lookup | Implemented on this branch, opt-in + separate server flag | Requires `ABUSEIPDB_API_KEY` and `SATARK_ENABLE_ABUSEIPDB=true`; accepts only a validated IPv4/IPv6 literal, has a 5-second timeout, and returns inconclusive states without claiming safety | Keep disabled until tested in staging with an authorized key; validate the current API contract and add provider mock tests; consent explicitly warns that the IP is shared |
| Rate limiting | Partial / best effort | In-memory map is per instance; forwarded IP handling must be reviewed alongside release PR #39 | Use trusted platform IP extraction and a distributed store/platform limit before public high-traffic exposure |
| FIRSTLIGHT training case | Implemented as a synthetic client-side lab | Synthetic events, timeline/findings, import of JSON/CSV, local SHA-256 digests, simulated tamper, simulated response actions | Do not describe client hashes as chain of custody or forensic sealing; test imports, duplicate IDs, malformed/large inputs and export paths; real Microsoft actions in PR #40 remain separate and guarded |
| FIRSTLIGHT CSV parsing | Automated regression tests pass | Tests cover parser edge cases; does not establish integration with a live SIEM/identity provider | Add schema/version docs and authorized sanitized fixtures |
| Microsoft live-response adapters | Pending review in PR #40 | Not part of PR #41 and not considered enabled/verified by this audit | Review permissions, dry-run behavior, audit trail, tenant config and rollback before enabling |
| Reports page | Basic feature works in browser | Exports only notes entered on the page as a text file; no durable report store and no auto-population from investigation | Either label as local notes export (current behavior) or implement explicit session-to-report flow and tested structured PDF/JSON export |
| Learning hub / quiz | Implemented as local educational interactions | No user accounts or server-side progress tracking observed in page implementation | Test all answers/reset/progress, keyboard navigation and persistence expectations; add persistence only if desired |
| Image/deepfake analysis | Legacy Streamlit handoff | Home page links to existing Streamlit app; it is not native Next.js functionality | Verify Streamlit availability and provider credentials; define supported file types/size, privacy disclosure, and safe failure UI |
| QR-code analysis | Legacy Streamlit handoff | Link to existing full app; not native Next.js functionality | End-to-end test camera/file input, malformed QR, decoded URL safety and mobile permissions |
| PDF/document analysis | Legacy Streamlit handoff | Link to existing full app; not native Next.js functionality | Test text extraction, scanned PDFs/OCR, size limits, parser errors and hostile-file handling |
| Video/media analysis | Legacy Streamlit handoff | Link to existing full app; actual availability depends on that app's installed packages/config | Test codec, file size, duration, upload limits and provider quota |
| History | Legacy handoff / not durable in Next.js | Reports page explicitly says analysis results are not automatically saved and page state is ephemeral | Implement authenticated, consent-based storage with retention/deletion controls or keep the product promise limited to session-only use |
| Authentication / saved cases / team collaboration | Not observed in the current Next.js workspace | No complete auth + persistence flow established by this audit | Decide if required; otherwise explicitly call this a local/session prototype and avoid implying shared workspaces |
| Deployment and provider configuration | Not verified end-to-end | CI build success is not proof of live Vercel/Streamlit configuration or valid secrets | Verify environment variables in the target project, redeploy preview, check health/API with authorized non-sensitive inputs, inspect runtime logs without exposing secrets |

## UI/UX and animation inspiration

### 1. JODC Fromroots — https://github.com/8BitsLife/jodc-fromroots
Observed in `src/App.tsx` and `package.json`: React, Framer Motion, MotionConfig honoring reduced-motion preference, lazy-loaded secondary pages with Suspense, preloader, and separately composed page sections.
Adopt: lazy-load secondary SATARK workflows; use shared motion tokens and a reduced-motion-aware animation wrapper; preserve a fast path to the investigator. Do not copy its cursor effect or preloader by default—security workflows should prioritize clarity and accessibility.

### 2. Drone Wars — https://github.com/Mercy036/drone-wars
Observed in `app/page.tsx` and `package.json`: modular page sections, dedicated background component, Framer Motion, and a deferred-section component imported but not used in the shown home composition.
Adopt: modular sections and reusable background/hero patterns. Fix our own long-page density with task-focused routes and progressive disclosure. Do not cargo-cult its event-focused layout or unused deferral component.

### 3. CICR Connect — https://github.com/amancodes8/CICRCombined
Observed in README and rollback-safe deployment docs: health/readiness checks, migration checks, explicit pre-deploy gates, deploy ordering and rollback criteria; README declares ISC.
Adopt: a release gate checklist, service health/readiness, rollback procedure and clear disabled/configured/error states for each integration. It is an operations reference, not the visual design reference.

### 4. OSDHack26 — https://github.com/osdc/osdhack26
The previously reviewed repository was described as a retro CRT/arcade-style hackathon site with separated CSS and a viewport-height fix. A README fetch returned 404 in this audit, so current source and license could not be re-verified.
Adopt only the general idea of a restrained incident-console motif—small status indicators and purposeful micro-interactions—not noisy CRT effects across the whole product. Verify license and exact source before copying code.

### 5. InnovationJIIT — https://github.com/Omtripathi007/Innovationjiit.in
Observed in README: mobile-first, semantic markup, Intersection Observer scroll reveals, focus handling, reduced-motion support, CSS variables, and a restrained reusable component approach. README states ownership by Innovation Club; no explicit permissive license was verified.
Adopt: editorial hierarchy, accessible reveals, consistent spacing/type tokens, keyboard focus and performance practices. Do not copy photos, videos, fonts or code until rights/license are verified.

### Design implementation direction

- Keep the dark navy base and lime accent as a restrained security-console identity; introduce a secondary cyan only for neutral/informational states and reserve red/amber for severity.
- Make the primary path obvious: **Investigate → Evidence → Findings → Recommended action → Export**. Move less-used tools into dedicated routes or a collapsible “More tools” area rather than showing every feature as equal priority.
- Make real status explicit: live integration, synthetic sample, unavailable, disabled, and legacy-app handoff must never share the same “ready” styling.
- Use animation only to explain state changes: scan progress, section entrance, result expansion, timeline correlation. Honor `prefers-reduced-motion`, avoid cursor-following effects, avoid long preloaders, and never animate risk scores in a way that suggests scientific precision.
- Lazy-load secondary pages and heavy visualization modules, not the first-use investigator or required result content.
- Add real browser assertions for keyboard flow, form submission, error/loading/success states, reduced motion, narrow mobile widths, external-link behavior and downloads. Existing smoke checks are a baseline, not comprehensive UX certification.

## License and reuse boundary

Do not copy complete UI components or media until a repository's actual license file is checked. A README mentioning a license is not sufficient evidence if the license file is missing or inconsistent. Reimplement design patterns independently where the license is unclear. Preserve attribution and license notices for any code actually reused.

## Release gate

Do not mark SATARK production-ready until: all intended PRs are reviewed and reconciled; complete CI/security checks pass on the final merged commit; staging provider calls pass with authorized non-sensitive inputs; desktop/mobile browser regression and accessibility checks pass; the legacy Streamlit handoffs are verified; and rollback/monitoring are documented.