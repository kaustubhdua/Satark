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