# SATARK improvement roadmap

This roadmap prioritizes a reliable, evidence-led investigation over feature count. It is an execution checklist, not a claim that the listed work has been completed.

## Release gate: resolve first

- [ ] Record the canonical repository, deployment repository, branch, hosting target and deployed commit SHA.
- [ ] Compare the canonical and deployment branches; review changes rather than blindly overwriting files.
- [ ] Ensure the deployment repository's GitHub integration has the required write permissions.
- [ ] Run CI and CodeQL on the exact candidate commit.
- [ ] Test the deployed app after release and record the result in `docs/RELEASE_READINESS.md`.

## P0 — core workflow and trust

### FIRSTLIGHT end-to-end workflow
- [ ] Complete a synthetic case from case overview through evidence, findings, timeline, simulated response and report export.
- [ ] Confirm every material finding references known evidence IDs or explicitly states that evidence is missing.
- [ ] Keep imported observations, deterministic inferences, AI interpretations and investigator actions visually distinct.
- [ ] Test evidence verification, evidence-ID substitution, malformed evidence and tamper challenges.
- [ ] Ensure response actions remain simulated and the UI never implies real-world changes occurred.
- [ ] Test report contents for accuracy, readability, sensitive-data exposure and graceful handling of malformed case data.

### Threat-analysis integrity
- [ ] Distinguish observed indicators, interpretations, confidence, and independent corroboration.
- [ ] Never label a score as a probability unless calibration and evaluation support that interpretation.
- [ ] Keep ambiguous cases in an explicit review/insufficient-evidence state.
- [ ] Build a fixed benign, malicious and ambiguous evaluation set.
- [ ] Track false positives, false negatives, unsupported claims, evidence traceability and latency.

### URL and file safety
- [ ] Test URL parsing, public DNS resolution, pinned connections, redirect revalidation, timeouts, response limits and content-type restrictions.
- [ ] Confirm prohibited IP ranges and unsafe redirects are blocked, including mixed DNS answers and rebinding scenarios.
- [ ] Keep hosting/network egress restrictions as defense in depth.
- [ ] Test malformed, encrypted, oversized and resource-intensive files.
- [ ] Confirm all failures are bounded, understandable and do not leak secrets or raw provider responses.

### UI and interaction reliability
- [ ] Give FIRSTLIGHT the primary navigation position; group scanners, records and learning separately.
- [ ] Audit every primary button, navigation transition, form submission and download.
- [ ] Add explicit empty, loading, success, failure and retry states.
- [ ] Test narrow/mobile layouts, keyboard navigation, focus states and reduced-motion preferences.
- [ ] Keep advanced diagnostics and raw data progressively disclosed rather than always visible.

## P1 — quality and maintainability

- [ ] Add unit tests for deterministic normalization, evidence, timeline, import and report functions.
- [ ] Add provider-failure tests for missing/invalid keys, timeouts, rate limits, unavailable models and malformed responses.
- [ ] Measure time-to-interactive and per-workflow latency before optimizing.
- [ ] Cache only suitable reusable data; do not globally cache private case content without an explicit isolation policy.
- [ ] Verify dependencies, Python compilation, test suite, CodeQL and deployment smoke tests in CI.
- [ ] Document the privacy boundary, session-only history, external provider processing and report contents.
- [ ] Keep a go/no-go record and a tested rollback path for each release.

## P2 — only after P0/P1

- [ ] Add authenticated durable case storage only with authorization, tenant isolation, retention, deletion, backup and recovery designs.
- [ ] Add external reputation/corroboration providers only when provenance, rate limits, licensing, privacy and outage behavior are documented.
- [ ] Add team workflows and analytics only when they support a real user decision and use trustworthy underlying data.

## Suggested release acceptance criteria

A release is not ready until the exact deployed revision is known and the following are verified:

1. A synthetic FIRSTLIGHT case can be completed from start to report.
2. Evidence hashes detect controlled modification, with their limitations clearly explained.
3. Findings are evidence-linked or explicitly marked uncorroborated.
4. Simulated response actions cannot be mistaken for real actions.
5. Primary navigation and buttons work in desktop and mobile layouts.
6. URL and file abuse tests fail safely within bounded resource limits.
7. Provider failures never produce a misleading safe verdict.
8. No secret, raw sensitive input or full private URL is leaked through errors/logs by default.
9. CI and CodeQL pass on the exact candidate commit.
10. The deployed app is smoke-tested and the commit SHA is recorded.

## Status vocabulary

Use `PASS`, `FAIL`, `BLOCKED` and `NOT TESTED`. A missing test result is not a pass. Do not mark a deployment verified without testing the deployed revision.
