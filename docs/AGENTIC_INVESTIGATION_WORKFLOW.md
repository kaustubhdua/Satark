# Agentic investigation workflow for SATARK / FIRSTLIGHT

**Status:** historical design note; current production behavior is governed by `docs/PRODUCT_COMPLETION_AUDIT.md`  
**Scope:** adapt useful agent-engineering patterns to SATARK's security-investigation workflow; do not transplant a tutorial framework wholesale.

## What SATARK already has

Inspection of the current `main` code shows that the project already implements several of the patterns people often add an agent framework to obtain:

- `firstlight_engine.py` provides a deterministic investigation workflow (`investigate_case`) with evidence integrity checks, prioritized evidence, a chronological timeline, evidence-linked findings and explicit gaps. It does not manufacture response proposals.
- `append_audit` / `verify_audit_chain` provide a hash-chained audit trail for the current in-memory workflow.
- The old simulated-response helper has been removed from the production engine. Real Wazuh response is a separate guarded workflow, disabled by default and not accepted until it passes authorized lab validation.
- `review_engine.py` separates local deterministic observations from AI interpretation and avoids describing heuristic evidence as proof.
- Unit tests cover evidence tampering, finding references, malformed inputs, audit-chain integrity and the response boundary. Test fixtures are not operational evidence.

**Important distinction:** the named “Evidence Agent”, “Detection Agent”, “Correlation Agent”, and “Verification Agent” currently describe deterministic stages in the workflow. They are not independent LLM agents. That is a sensible baseline for a security investigation product; do not replace it with an autonomous multi-agent framework without a measured reason.

The next useful work is therefore **better contracts, tracing, evaluation, and UI visibility**, not adding more agents for appearance.

## Why the reference is relevant

SATARK is not a general-purpose chatbot. Its useful job is to help a reviewer move from suspicious artifacts and incident events to an evidence-backed, reviewable decision. The agent should therefore be **bounded, traceable, and subordinate to the evidence**.

The reference repository, [GenAI_Agents by Nir Diamant](https://github.com/NirDiamant/GenAI_Agents), is a teaching collection covering agent control flow, tools, memory, orchestration, and evaluation. This document adapts those general engineering ideas to SATARK. It does **not** copy notebooks, source code, prompts, images, or other repository assets. No framework or dependency is required by this design document.

## What is being implemented now

The first code pass closes one concrete correctness gap in FIRSTLIGHT:

- Findings are derived from the actual supplied evidence records instead of being permanently tied to the demo IDs `EV-001` through `EV-005`.
- The current rules look for unfamiliar successful logins, unusual process ancestry, suspicious network signals, archive/staging-like artifacts, and follow-on sessions. Each remains a heuristic and is worded as a lead, not a verdict.
- Correlation uses evidence IDs from the current case only. A record with a failed integrity check cannot support a finding.
- A case that matches no current rule receives an explicit “no rule matched” / analyst-review finding rather than an implied clean bill of health.
- The investigation engine no longer emits simulated response proposals. Response is deliberately separated from investigation and exposed only through the guarded Wazuh workflow.
- Regression tests cover custom evidence IDs, custom event records, finding references, and abstention when no rule matches.

These rules are deliberately small and explainable. They are not a replacement for a proper detection engine or analyst validation.

## Corsair: useful patterns, not a dependency to copy wholesale

[Corsair](https://github.com/corsairdev/corsair) describes itself as an integration platform that exposes integrations through a common REST-oriented interface and provides adapters for agent frameworks. The patterns most relevant to SATARK are:

1. **A consistent integration boundary:** normalize outputs from any future threat-intelligence, identity, endpoint, or ticketing connector into a SATARK-owned schema.
2. **Small provider adapters:** keep vendor-specific auth and API details out of the investigation engine so connectors can be tested independently or disabled.
3. **Event/webhook ingestion:** useful later for receiving security alerts without polling everything. Any webhook must authenticate the sender, validate the payload, deduplicate events, and preserve source/timestamp metadata.
4. **Credential and permission isolation:** use least-privilege credentials, explicit opt-in, bounded scopes, and visible connection state; never expose provider tokens to the model or browser.
5. **Tool capability allowlists:** the model should only see approved read-only tools by default. Consequential response actions stay behind explicit human approval.

**Architecture decision:** do not add Corsair as a runtime dependency yet. SATARK currently spans Python/Streamlit and a separate web workspace; adopting a broad TypeScript integration platform now would add setup and authentication complexity before a single live connector is proven. Implement a thin SATARK-owned adapter contract first, then evaluate Corsair if multiple real integrations are needed and its supported auth/deployment model fits the app. Do not claim any connector is live until credentials, permissions, error paths, and end-to-end tests are validated.

## Recommended workflow

```text
Incident / artifact input
        |
        v
1. Validate + normalize input
        |
        v
2. Preserve evidence identity, hash, timestamp, and source
        |
        v
3. Run existing deterministic checks and investigation engine
        |
        v
4. Optional model-assisted explanation of bounded evidence
        |
        v
5. Validate output; verify evidence IDs; surface gaps/contradictions
        |
        v
6. Human review: approve, reject, or request more evidence
        |
        v
7. Record decision + export a report
```

The model may explain evidence, but it must not invent evidence, silently change deterministic results, or trigger a consequential response action by itself.

## Design rules

### 1. Keep orchestration explicit and small

Continue using a deterministic, named workflow as the control plane. Each stage should have a defined input/output and clear failure state. A failed model call should lead to deterministic-only results or manual review, not an unhandled crash or fabricated conclusion.

Suggested lifecycle for future extension:

- `RECEIVED`
- `VALIDATED`
- `ANALYZED`
- `CORRELATED`
- `AWAITING_REVIEW`
- `APPROVED` or `REJECTED`
- `COMPLETED` or `NEEDS_MANUAL_REVIEW`

Only add explicit persisted lifecycle states if the UI or durable case storage needs them; do not duplicate state that is already correctly managed in the current session.

### 2. Keep tools narrow and allow-listed

Expose existing, tested SATARK functions as tools only when they have a clear contract. A tool definition should include:

- a stable name and short purpose;
- validated input schema and strict size/time limits;
- structured output with evidence references;
- bounded execution and a predictable error result;
- a test that verifies its behavior.

Do not give the model arbitrary shell access, unrestricted URL fetching, repository write access, or credentials. Reuse SATARK's existing input-validation and URL-safety boundaries; do not create a second, weaker path around them.

### 3. Treat evidence and model interpretation as different data

Each finding should distinguish:

- **Observation:** what the parser, log, or deterministic check actually returned;
- **Interpretation:** what the model or rule suggests it may mean;
- **Confidence / uncertainty:** how strong the available support is;
- **Evidence references:** IDs for the artifacts or events supporting the finding;
- **Gap / next check:** what is missing or would corroborate the interpretation.

A model-generated claim without a valid evidence reference should be marked as unverified or excluded from the final finding. Confidence must not be inflated merely because the model sounds certain.

### 4. Keep human approval as a hard boundary

The model can recommend a next step, but the workflow must not execute a real account, identity, endpoint, or tenant response action without explicit human approval tied to the exact target and action. Approval should expire if the target or action changes. Rejection must be a valid terminal decision, not an error.

Keep all synthetic fixtures inside automated tests. The production workspace must not load canned incidents. The guarded Wazuh response adapter is implemented separately and must remain disabled until target-bound authorization, audit logging, independent verification and disposable-lab acceptance are complete.

### 5. Use case-scoped memory, not open-ended memory

Keep workflow state and evidence inside the current investigation/session for now. If persistent case memory is added later, store only explicitly selected, necessary facts with provenance and retention rules. Never silently mix evidence from two different incidents or use a previous model answer as if it were verified evidence.

### 6. Trace each run and decision

The existing hash-chained audit trail is a useful starting point, but it is session-based and is not independently anchored chain-of-custody evidence. Add or surface structured, privacy-safe run metadata where it helps debugging and review:

- case/run ID and workflow version;
- step name, status, duration, and bounded error code;
- tool name and sanitized input/output summaries;
- evidence IDs referenced by each finding;
- model/provider and model identifier when used;
- human decision, action, and timestamp.

Do not log raw secrets, API keys, full uploaded documents, or unnecessary personal data. Do not describe an in-session hash chain as durable or independently tamper-proof.

### 7. Evaluate the workflow, not just model prose

Extend the existing test suite with a small, versioned synthetic evaluation set. Include at least:

- clearly suspicious and benign examples;
- ambiguous / insufficient-evidence cases;
- conflicting indicators;
- malformed or oversized input;
- unavailable model/provider;
- missing or unknown evidence reference;
- human rejection and approval-target mismatch.

Measure deterministic regression results, evidence-reference validity, correct abstention/manual-review behavior, unsafe-action prevention, latency, and failure handling. A passing LLM response alone is not sufficient evidence that the investigation workflow works.

## Incremental implementation plan

### Phase 1 — Close contract and test gaps

- [x] Map the existing FIRSTLIGHT engine and inspect the current integration boundaries.
- [x] Replace demo-ID-specific finding rules with evidence-driven, deterministic heuristics.
- [x] Add tests for custom evidence IDs and no-rule-match abstention.
- [ ] Add schema validation for optional model output, provider failure tests, and approval-target mismatch tests.
- Preserve the deterministic engine as the baseline.

### Phase 2 — Optional bounded model assistance

- Reuse the existing local Ollama integration only where it adds value.
- Run deterministic checks first; use the model for a bounded explanation or question list, not as the source of evidence or the sole risk authority.
- Validate model output against a schema and verify every referenced evidence ID.
- Return a structured manual-review result when output is invalid or the provider is unavailable.

### Phase 3 — Review and trace UI

- Show observations separately from AI interpretation.
- Let a reviewer inspect evidence references, uncertainty, contradictions, and missing evidence.
- Make approve/reject decisions explicit and tied to the current action target.
- Surface a compact per-run trace without exposing secrets or raw sensitive content.

### Phase 4 — Regression evaluation

- Run the synthetic evaluation suite in CI.
- Add or extend browser smoke tests for the principal FIRSTLIGHT flow.
- Document which features are deterministic, model-assisted, simulated, or genuinely connected to an external system.

## Acceptance criteria

- [ ] A complete investigation can finish without a model/provider being available.
- [ ] Model output is schema-validated and cannot create evidence records by itself.
- [ ] Every displayed finding points to existing evidence IDs or is explicitly labelled unverified.
- [ ] Invalid input, tool errors, timeouts, and model failures produce a safe, reviewable result.
- [ ] No real response action can run solely because the model recommended it.
- [ ] Approval is bound to the exact action and target; a changed target requires a new decision.
- [ ] Tests cover successful, ambiguous, malformed, provider-failure, and rejection paths.
- [ ] Documentation accurately labels demo/simulated integrations versus live integrations.

## Scope deliberately excluded for now

- Multi-agent debate or self-improving agents without a measurable need;
- unrestricted web search or arbitrary tool execution;
- automatic remediation or live tenant actions;
- cross-case persistent memory;
- adding LangChain/LangGraph or another orchestration dependency before the existing code paths and deployment constraints are mapped.

These may be evaluated later if a specific SATARK requirement justifies their cost and risk.

## References

- Nir Diamant, [GenAI_Agents](https://github.com/NirDiamant/GenAI_Agents) — general learning reference for agent control flow, tools, memory, orchestration, and evaluation. This SATARK design is an original, project-specific adaptation and does not include copied code or assets.
- [Corsair](https://github.com/corsairdev/corsair) — integration-platform reference for common connector boundaries, provider adapters, and webhook patterns. SATARK borrows these architectural ideas only; it does not copy Corsair source or add it as a dependency.
