# SATARK Sentinel — product completion roadmap

**Status date:** 2026-10-14  
**Goal:** a polished, evidence-led, human-controlled security investigation workspace, with FIRSTLIGHT as the primary workflow and SATARK's triage tools as supporting capabilities.

This is an acceptance plan, not a claim that listed work is complete. A feature is "real" only when the UI action is connected to a server operation, returns or persists a verifiable result as appropriate, handles failure safely, and has an automated test.

## Research and inspiration

These are references for patterns and standards, not instructions to clone a UI:

- [TheHive analyst workflows](https://docs.strangebee.com/): triage alerts, convert them to cases, manage observables, run analyzers, document actions, and export reports. Make SATARK's investigation lifecycle equally explicit and connected.
- [Wazuh dashboard documentation](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/navigating-the-wazuh-dashboard.html): separate security domains, severity context, connected/disconnected states, and drill-down from overview to details.
- [Security Onion dashboards](https://docs.securityonion.net/en/2.4/dashboards.html): deliberate filtering, time ranges, refresh behavior, and inclusion/exclusion of case and detection data.
- [MITRE ATT&CK data and tools](https://attack.mitre.org/resources/working-with-attack/): versioned STIX/TAXII or maintained official data for technique references and defensive coverage; show data version and source date.
- [Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md): local model inference with JSON-schema output. Schema validity is not proof that a model's claims are true.
- [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/): prioritize access control, configuration, supply-chain integrity, authentication, logging, and safe error handling.
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/): threat-model prompt injection, data disclosure, unbounded consumption, retrieval risk, and excessive agency.

## Product principles

1. Evidence before verdicts. Keep observations, deterministic signals, threat-intelligence results, model explanations, analyst conclusions, and response actions distinct.
2. Missing data is not a clean result. Distinguish not requested, disabled, unavailable, no match, and match. Never turn a provider failure into "safe".
3. FIRSTLIGHT leads. The home page should orient users to the next investigation step, not dump every feature onto one screen.
4. Human approval for consequential actions. AI can summarize evidence and propose next steps; it must not authorize containment, account changes, external sharing, or destructive actions.
5. Privacy by default. Keep submitted artifacts out of browser persistence and telemetry unless required; external intelligence sharing must be opt-in and target-specific.
6. No pretend controls. Demo-only actions are labelled, and no button claims an operation that is not connected to a tested implementation.

## Research and implementation references

These are engineering references and inspiration, not claims that SATARK already implements their capabilities.

### Incident workflow and SOC UX
- [Elastic Security cases](https://www.elastic.co/docs/solutions/security/investigate/cases/): cases should collect alerts, evidence, analyst notes, timelines, indicators, and status transitions in one reviewable place. SATARK should adopt the evidence-to-case-to-timeline pattern, not copy proprietary UI.
- [Wazuh dashboard](https://documentation.wazuh.com/current/getting-started/components/wazuh-dashboard.html): show clear security-event summaries, drill-down paths, rule-testing feedback, component health, and useful empty/error states.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): model FIRSTLIGHT around preparation, detection, response, recovery, communication, and improvement rather than a single “scan” button.

### Security verification and AI safety
- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS): use versioned, testable requirements for authentication, authorization, input validation, file handling, logging, and configuration.
- [OWASP GenAI / LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/): explicitly test prompt injection, insecure output handling, sensitive-data disclosure, model denial of service, supply-chain risk, and excessive agency. The model must not authorize or execute response actions.
- [Sigma rules](https://sigmahq.io/): use versioned, provenance-rich, testable detection rules for log/event detection. Do not apply log rules directly to arbitrary pasted text without a defined data model and tests.

### UI system and motion
- [Radix accessibility guidance](https://www.radix-ui.com/primitives/docs/overview/accessibility): use semantic controls, keyboard behavior, focus management, and correct ARIA patterns. Prefer native controls where they suffice.
- [React Bits](https://reactbits.dev/): inspiration for restrained source-owned motion and interaction components. Copy/adapt only the components needed, keep them accessible, respect reduced-motion preferences, and avoid runtime dependency on a hosted animation service.
- Design rule for SATARK: use a persistent navigation shell, one primary task per page, progressive disclosure for advanced evidence, source-linked findings, clear “not checked / unavailable / insufficient evidence” states, and compact cards instead of a wall of widgets.

## P0 — release blockers

P0 means SATARK must not be described as production-ready until applicable gates pass.

### P0.1 Deployment, configuration, and release truth
- [ ] Merge the production-readiness diagnostics change only after its web CI is green.
- [ ] Correct live-demo links and verify the deployed release SHA against the version endpoint.
- [ ] Confirm production deployment is built from the intended main commit; smoke-test core routes and API endpoints.
- [ ] Keep public health output to non-sensitive status; never expose secret values.
- [ ] Record commit SHA, CI links, deployment ID, smoke results, rollback target, and missing provider dependencies in a release checklist.
- [ ] If shared rate limiting is unavailable, fail closed for expensive analysis while keeping basic health and invalid-request diagnostics useful.

**Acceptance:** latest main commit has green Web CI, Python CI, and CodeQL; production SHA is verified; root, /firstlight, /investigate, /reports, /learn, /login, /api/version, and /api/health are smoke-tested. Unavailable integrations are visibly degraded.

### P0.2 Identity, authorization, and tenant isolation
- [ ] Write a route-by-route authorization matrix for cases, evidence, findings, reports, audit verification, uploads, and integrations.
- [ ] Test that user A cannot read, mutate, export, or verify user B's tenant/case data by changing IDs.
- [ ] Test Supabase RLS and server-side authorization with distinct test identities; do not infer isolation solely from RLS being enabled.
- [ ] Confirm service-role credentials are server-only and never bundled to clients.
- [ ] Define session expiry, sign-out, unauthorized/forbidden UX, and recovery states.
- [ ] Add negative tests for missing identity, malformed IDs, cross-tenant references, and privilege escalation.

**Acceptance:** automated isolation tests pass against a non-production environment with at least two tenants; all data routes enforce authorization server-side.

### P0.3 Evidence integrity and durable records
- [ ] Define evidence metadata: original name, content type, size, cryptographic hash, acquisition timestamp, actor, case/tenant, and processing state.
- [ ] Enforce server-side size and content allowlists, inspect file signatures, and reject unsupported or malformed files.
- [ ] Store artifacts privately; use authorization-checked access and test expired/unauthorized access.
- [ ] Verify audit chains on server-side mutations and make tampering/gaps visible.
- [ ] Document exactly what the chain proves; do not call a session hash chain certified chain-of-custody evidence.
- [ ] Ensure reports reference stable evidence IDs and hashes, not browser session state.

**Acceptance:** upload → hash → private storage → record → verify → report export works end-to-end; mutation, replacement, deletion, and cross-tenant tests fail safely.

### P0.4 Real analysis and truthful provider states
- [x] Keep deterministic checks available without third-party provider credentials; the web analysis route now defaults to local-only deterministic rules and optionally calls a configured self-hosted Ollama instance.
- [x] Validate media type, request limits, local-model timeout, bounded model responses, structured output, and deterministic fallback in the Next.js local route.
- [ ] Test the live self-hosted Ollama model on supported hardware and run prompt-injection/quality evaluations.
- [x] Remove third-party AI/reputation HTTP calls and provider API-key requirements from the Next.js analysis route.
- [x] Add an offline operator-managed IOC cache with freshness/provenance states and a local-feed import command. The checked-in cache intentionally remains empty until an operator selects a license-compatible source; analysis never fetches feeds.
- [ ] Verify no-match, unavailable, and not-requested never render as a green "safe" result.

**Acceptance:** the local route succeeds with no API keys and no outbound requests; optional local model failure falls back to deterministic results; local intelligence matches show source/version/freshness and absence of a match is never a safe verdict.

### P0.5 Real UI interactions
- [ ] Inventory every visible button, link, form, toggle, tab, upload control, export, filter, and response action.
- [ ] Give each control an implemented, disabled-with-reason, or labelled-demo state.
- [ ] Remove dead links, inert buttons, fake progress, placeholder charts, and unlabelled simulated actions.
- [ ] Add success, empty, loading, partial failure, retry, and permission-denied states.
- [ ] Test keyboard-only use and focus order for the core journey.

**Acceptance:** every visible action in the core journey has a browser test asserting its actual result, not just that it can be clicked.

## P1 — core product completeness

### P1.1 FIRSTLIGHT investigation lifecycle
- [ ] Create case → define scope → add evidence → run checks → review findings → construct timeline → record decision → generate report.
- [ ] Persist every step and recover state after refresh, sign-in, and network retry.
- [ ] Link each finding to evidence and expose uncertainty and missing evidence.
- [ ] Add owner, severity, status, timestamps, notes, and action history where supported by the schema.
- [ ] Add duplicate detection and idempotency for retryable writes.
- [ ] Separate synthetic training scenarios from live case operations.

**Acceptance:** a synthetic incident can be completed in a fresh browser session; the report can be reopened and reconciled with stored case records.

### P1.2 Upload, analysis, and export
- [ ] Document exact supported formats and limits for text, URLs, images, QR codes, PDFs, and videos; remove unsupported format promises.
- [ ] Add safe parsing and timeouts; never execute uploaded content on the application server.
- [ ] Isolate hostile parsers and malware samples in a separate sandboxed worker if detonation is ever offered.
- [ ] Show per-file progress/errors without losing successful results.
- [ ] Export PDF/JSON/CSV with case ID, timestamps, evidence hashes, sources, method/version, limitations, and audit history.
- [ ] Test large, corrupt, polyglot, encrypted, and unsupported files.

**Acceptance:** each advertised format has a tested parser and meaningful result, or is clearly labelled unavailable; exports are permission-checked and reconcile with persisted records.

### P1.3 Threat intelligence and knowledge
- [ ] Maintain a source registry with provider, license/terms, last successful sync, freshness, confidence, and attribution.
- [ ] Add versioned MITRE ATT&CK references from official STIX/TAXII or maintained official releases; do not describe technique metadata as live IOC reputation.
- [ ] Cache external data and apply timeouts, retries/backoff, rate limits, and stale-data indicators.
- [ ] Add detection-rule metadata (e.g. Sigma-compatible references) and provenance for every match.
- [ ] Benchmark local signals on a curated held-out benign/suspicious corpus before calling any risk score calibrated.

**Acceptance:** intelligence-backed findings include source, timestamp/version, and match evidence; stale/unavailable sources are visible.

### P1.4 Self-hosted AI
- [ ] Select a base model after license, hardware, memory, latency, and offline requirements are assessed.
- [ ] Keep deterministic checks authoritative for observable facts; the model explains and organizes evidence.
- [ ] Add schemas for findings/summaries, evidence references, abstention, and prompt-injection tests.
- [ ] Build a reviewed prompt/completion corpus with provenance, incident/campaign/source-level splits, deduplication, and held-out evaluation.
- [ ] Compare base model and LoRA adapter on groundedness, schema validity, false claims, false positives/negatives, latency, and memory.
- [ ] Pin model revision, tokenizer, library versions, adapter hash, and inference settings.
- [ ] Keep weights out of Git; publish a model card and rollback plan.
- [ ] Integrate only after authentication, tenant authorization, rate limits, cancellation, privacy controls, and abuse tests are ready.

**Acceptance:** reproducible training/evaluation report exists; the tiny synthetic smoke set is not represented as a security benchmark; model failure leaves deterministic triage usable.

### P1.5 Response actions and integrations
- [ ] Separate recommendation, approval, execution, and verification.
- [ ] Bind approvals to tenant, case, target, action, expiry, and actor.
- [ ] Add idempotency, audit entries, least-privilege scopes, dry-run mode, and rollback where supported.
- [ ] Validate Microsoft Defender/Entra adapters in a dedicated test tenant with authorized non-destructive actions before claiming live support.
- [ ] If credentials/test tenant are absent, leave connector disabled and state the dependency.

**Acceptance:** simulated actions are never presented as live; enabled integrations have end-to-end contract tests and documented failure/recovery.

### P1.6 Migrate the legacy Streamlit feature set to local-only operation
- [x] Remove the Groq API-key field and SDK dependency from the legacy UI; default text/image analysis to an operator-controlled Ollama endpoint.
- [x] Add optional local faster-whisper speech-to-text for video, with model-download and hardware requirements; no hosted transcription API.
- [ ] Migrate image, QR, PDF, video, history, classroom, and report workflows into the primary Next.js product or formally retire each unsupported feature.
- [x] Disable external reputation API lookups in the active Streamlit analysis path.
- [ ] Build a local IOC cache and an explicit, auditable feed-update command that runs separately from analysis.
- [ ] Keep the legacy UI behind a clear migration/retirement notice until feature parity and tests are complete.

**Acceptance:** the full declared product runs without third-party API keys, submitted evidence never leaves operator-controlled infrastructure during analysis, and every retained media feature passes fixture-based tests in an offline test environment.

## P2 — excellent UX, accessibility, and performance

### P2.1 Information architecture
- [ ] Make FIRSTLIGHT the main entry: continue investigation/start case, recent cases, concise system health.
- [ ] Separate destinations: Overview, Investigations, Evidence, Findings, Reports, Threat Intel, Learning, Settings.
- [ ] Use progressive disclosure: summary first, technical evidence on demand.
- [ ] Standardize severity, source, timestamps, confidence/uncertainty, and empty states.
- [ ] Add global search/command entry only if it routes to real, permission-checked actions.

### P2.2 Visual design system
- [ ] Define semantic tokens for surfaces, text, borders, accent, status, focus, spacing, radii, elevation, and motion.
- [ ] Establish type scale, responsive grid, consistent content widths, and page hierarchy.
- [ ] Build reusable cards, tables, filters, status badges, evidence rows, timelines, drawers, dialogs, toasts, and skeletons.
- [ ] Use motion sparingly for navigation/loading/state transitions and honor reduced-motion settings.
- [ ] Avoid congested dashboards, excessive gradients/glows, redundant cards, and decorative charts without decision value.
- [ ] Ensure demo data is clearly labelled and never shown as live telemetry.

### P2.3 Accessibility and responsive behavior
- [ ] Target WCAG 2.2 AA; test contrast, focus, keyboard navigation, landmarks/headings, form labels, error announcements, and accessible tables.
- [ ] Test 320px, 375px, 768px, 1024px, 1440px, and wide desktop.
- [ ] Test zoom/reflow, touch targets, screen-reader labels, reduced motion, and color-blind-safe status cues.
- [ ] Never use color as the only severity/state indicator.

**Acceptance:** automated accessibility checks pass and manual keyboard/screen-reader spot checks cover the critical journey. Screenshots alone are not enough.

### P2.4 Performance and reliability
- [ ] Measure Core Web Vitals and bundle sizes on production-like builds.
- [ ] Lazy-load non-critical views and expensive visualizations; split feature routes.
- [ ] Add cancellation/timeouts for long analysis, uploads, exports, and provider calls.
- [ ] Add structured, redacted operational logs, metrics, request IDs, and alerts.
- [ ] Test retries, duplicate submissions, concurrent updates, stale sessions, and provider outages.
- [ ] Establish backup/restore and migration verification.

**Acceptance:** publish performance/error/recovery targets and repeatable tests; compare measurements before/after optimization.

## P3 — validation, governance, and launch

- [ ] Threat-model the web app, file pipeline, provider connectors, model endpoint, and tenant boundary.
- [ ] Run dependency/license scanning, secret scanning, static analysis, DAST, authorization tests, and a focused manual penetration test.
- [ ] Test tenant isolation and backup restore against staging data.
- [ ] Publish vulnerability disclosure, incident response, privacy/retention policy, supported formats, integration matrix, model card, and operator runbook.
- [ ] Create a synthetic-data release demo with scripts and expected results.
- [ ] Tag a release only after P0 gates and agreed P1 acceptance criteria pass.

**Acceptance:** signed-off release checklist, reproducible build, rollback plan, known limitations, and no unresolved critical/high security issues without documented risk acceptance.

## End-to-end acceptance scenarios

1. **New investigation:** create case, upload synthetic evidence, verify hash, analyze, inspect findings/source, build timeline, export report, reopen case, verify record.
2. **Local model unavailable:** stop Ollama or remove model weights; deterministic fallback remains available, and nothing is labelled safe.
3. **Cross-tenant attack:** tenant A uses tenant B's IDs; reads/writes are denied.
4. **Prompt injection:** evidence tells the model to ignore rules or reveal secrets; it remains untrusted data, schema validation holds, and no action executes.
5. **Bad upload:** corrupt/oversized/unsupported file is rejected with no server-side execution.
6. **Interrupted network:** retries do not duplicate cases/evidence/actions; user can recover.
7. **Keyboard/mobile:** complete the core journey at a narrow viewport with accessible focus and errors.
8. **Release truth:** deployment SHA, version endpoint, CI runs, readiness state, and live links match the release.

## Historical status at roadmap creation (before the local-first migration was merged)

- The self-hosted AI prototype is merged, and its dedicated AI CI passed. No model has been trained; the tiny synthetic set is only a smoke test.
- The production-readiness PR branch now defaults the Next.js analysis route to deterministic local checks, with optional self-hosted Ollama summaries and no third-party provider path. A loopback-bound Docker Compose stack and setup guide were added.
- The local analysis route uses a bounded in-process limiter; this is not a shared limiter across Vercel instances. The UI readiness banner calls this out. Do not expose the service publicly without platform-level abuse controls.
- The Next.js and Python/Streamlit analysis paths now use local Ollama and no Groq SDK/API-key field. Optional local faster-whisper handles video audio. This implementation still requires CI confirmation and real model testing on supported hardware.
- Durable case/evidence workflows still require a self-hosted database deployment and end-to-end tenant-isolation verification. The local Compose stack does not yet provide that database.
- Web CI has exposed regression-test failures during migration; merge only after the latest Web CI, Python CI, CodeQL, and browser smoke runs all pass.
- Production is not proven to have complete tenant-isolation testing, a local IOC feed cache, fully implemented response actions, or a visually audited desktop/mobile experience.

## Definition of done

SATARK can be called finished for its declared scope only when every advertised feature is real and tested or clearly labelled unavailable/demo; all P0 acceptance criteria pass; the FIRSTLIGHT workflow is persistent and recoverable; production integrations are exercised with authorized credentials; security, tenant isolation, accessibility, responsive UX, and performance have evidence-based sign-off; release build and live version are verified; and documentation matches what actually works.

"Finished" does not mean every imaginable security capability exists. It means the declared scope is coherent, honest, tested, secure for its intended deployment, usable, and maintainable.


## Follow-up status — 2026-10-14

- PR #100 is merged to `main` at `257c6b4168c53c26436e8f82febafcfcbab69419`. Vercel deployment `dpl_8QefQRRtB3ndVFqLJciCY6MedT2s` reached `READY`, targets production, and is associated with that exact commit. The production build completed successfully. Direct HTTP assertions against the live `/api/version` and `/api/health` responses remain to be confirmed by the GitHub production-smoke workflow; this session's web fetcher could not access the live endpoint.
- The local-only Compose configuration was malformed on `main`; PR #102 repaired its service structure and was merged as `6142a38083bbd5286a47c7de088c0f0f99aacedd`. The YAML was parsed locally and the expected three services, loopback-only app ports, and private Ollama exposure were asserted. A Docker-enabled Compose build/start test remains outstanding.
- PR #103 adds an offline IOC cache and an operator-supplied feed importer. The cache is intentionally empty until a permitted source is chosen; its CI checks must pass before merge. The cache reports `not_configured`, `no_match`, `match`, `stale`, or `unavailable` distinctly.
- Web CI, Python CI, and CodeQL passed on the first tested PR #103 revision. Additional commits were then pushed to improve provenance and exact-domain tests; the latest revision's workflows must finish before merge.
- Local Ollama and faster-whisper still require a real hardware run. No SATARK-specific model has been trained or evaluated on a representative held-out corpus.
- The primary product still needs a visual desktop/mobile audit, an end-to-end persistent case/evidence/report verification using dedicated test tenants, and a documented backup/restore test. Do not equate a successful Vercel build with these acceptance gates.
