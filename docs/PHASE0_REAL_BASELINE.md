# SATARK / FIRSTLIGHT — Phase 0 Real Baseline

**Snapshot:** `main` at `1f939064760c3c2410cc7435bec273c4235b80fb` (2026-10-20 UTC).  
**Purpose:** evidence-oriented inventory and release gating, not a claim of production readiness.  
**Classification rule:** source code and unit tests prove implementation intent only. A capability is not "live" until a real provider, persistent write, authorization boundary, and observable end-to-end test are verified on the target environment.

## Executive baseline

The repository contains a Next.js web application, a Streamlit/Python application, FIRSTLIGHT API/worker modules, a separate AI service, Supabase migrations/tests, and CI workflows. Repository inspection does **not** establish that external providers are configured or healthy.

| Area | Repository evidence | Baseline status | Release consequence |
|---|---|---|---|
| Web UI and API | `web/src/app`, `web/src/app/api` | Partially wired; route-level automated tests exist | Test every route on deployed commit |
| Session security | `web/src/app/api/auth/session/route.ts`; `web/src/lib/satark-auth.ts` | Partially wired; cookie endpoint exists, browser helper historically retains localStorage token flow | Block release until all browser paths use HttpOnly sessions |
| Supabase persistence/RLS | `supabase/migrations`, `supabase/tests` | Implemented in repository; live schema/history is unverified and known mismatched | Freeze shared-project writes; reconcile exact migration list first |
| Evidence/audit | `evidence_engine.py`, evidence API, audit migrations | Partially wired; database and test contracts exist | Verify immutable finalization, export manifest and hash chain against real DB |
| Wazuh ingestion | `firstlight_wazuh.py`, `firstlight_wazuh_worker.py`, ingestion API and checkpoint migration | Partially wired; no verified real manager + Windows/Linux endpoint evidence | Do not represent fixture events as live telemetry |
| Detection/rules | `firstlight_rules.py`, `docs/FIRSTLIGHT_DETECTION_RULES.md` | Partially wired; rule engine exists, corpus/coverage and live alert delivery unverified | Detection coverage remains unverified |
| Investigation jobs | `firstlight_investigation_worker.py`, job migrations/API | Partially wired; persistence code exists, restart/retry proof unverified | Do not claim durable production processing |
| AI | `ai_provider.py`, `ai/service`, `analysis_engine.py` | Partially wired; provider/model runtime and representative benchmark unverified | AI health must be unknown/degraded until real inference succeeds |
| Response | `integrations/response_actions.py`, approval migrations | Simulation-only/unsafe to claim live until each adapter is independently verified | High-impact containment disabled |
| Reports | `reports.py`, report API/UI, report migrations | Partially wired; persisted-input reproducibility unverified | Report must cite persisted evidence/findings and versions |
| Deployment | GitHub workflows, Dockerfiles, Vercel project | Unverified; deployment API previously returned 403 and quota/build rate limit blocked rollout | No production sign-off without exact-commit smoke test |
| Observability/release gate | health/version APIs and workflows | Partially wired; required checks may be skipped without integration secrets | Skipped/stale checks must fail the release gate |

## Inventory (repository paths)

### Web pages / UI routes

- `/` — `web/src/app/page.tsx`
- `/login` — `web/src/app/login/page.tsx`
- `/reset-password` — `web/src/app/reset-password/page.tsx`
- `/cases` — `web/src/app/cases/page.tsx`
- `/firstlight` — `web/src/app/firstlight/page.tsx`
- `/investigate` — `web/src/app/investigate/page.tsx`
- `/reports` — `web/src/app/reports/page.tsx`
- `/tools` — `web/src/app/tools/page.tsx`
- `/learn` — `web/src/app/learn/page.tsx`
- `/url` — `web/src/app/url/page.tsx`
- `/qr` — `web/src/app/qr/page.tsx`
- `/pdf-review` — `web/src/app/pdf-review/page.tsx`
- `/image-review` — `web/src/app/image-review/page.tsx`
- `/media-review` — `web/src/app/media-review/page.tsx`
- Shared/layout/error surfaces: `layout.tsx`, `route-experience.tsx`, `site-header.tsx`, `site-footer.tsx`, `loading.tsx`, `error.tsx`, `not-found.tsx`.

### API route inventory and UI/backend contracts

| API route | Intended operation / UI contract | Persistence / side effect | Tests to treat as contract | Baseline |
|---|---|---|---|---|
| `POST/DELETE /api/auth/session` | Establish/clear server session; browser login/logout | Supabase Auth verification and HttpOnly cookies | `web/tests/session-cookie-contract.test.mjs`; browser login/logout, expiry/refresh/revocation | Partially wired |
| `GET/POST/PATCH /api/cases` | List/create/update case workspace | Supabase cases + audit event | `web/tests/cases-api.test.mjs`, `unauthenticated-api-status.test.mjs`, tenant integration | Partially wired |
| `/api/cases/notes` | Case notes | Supabase notes + audit | `web/tests/case-notes-api.test.mjs`; tenant/role tests | Partially wired |
| `/api/evidence` | Evidence upload/creation | Supabase metadata + object storage + audit | evidence signature, storage schema, body limits, tenant tests | Partially wired |
| `/api/evidence/records` | Evidence records/listing | Supabase evidence metadata | storage schema + tenant tests | Partially wired |
| `/api/evidence/[id]/verify` | Verify evidence integrity | Read stored object and persisted hashes | evidence-signature tests; tamper/tenant tests | Partially wired |
| `/api/audit/verify` | Verify audit chain | Read persisted audit events/checkpoints | audit redirect policy + database RPC tests | Partially wired |
| `/api/analyze` | Analyze submitted content | AI/provider call; persistence depends on workflow | local analysis/evaluation, timeout tests | Provider unverified |
| `/api/findings` | Create/list findings | Supabase findings + audit | persistent workflows, tenant tests | Partially wired |
| `/api/reports` | Generate/list reports | Persist report from findings/evidence | reports and persistent workflow tests | Partially wired |
| `/api/reports/[id]` | Retrieve report | Tenant-scoped read | report API + tenant tests | Partially wired |
| `/api/firstlight/approvals` | Request/decide response approval | Supabase approval + audit | approval/RPC migration contracts; live DB ACL check | Production DB unverified |
| `/api/firstlight/evidence/source` | Retrieve source evidence | Tenant-scoped source snapshot/object read | source evidence + storage policy + tenant tests | Partially wired |
| `/api/firstlight/investigate` | Start/continue investigation | Durable job, evidence/findings/timeline writes | investigation API/worker + restart tests | Partially wired |
| `/api/firstlight/jobs` | Inspect/manage investigation jobs | Supabase job records | jobs API + tenant/role tests | Partially wired |
| `/api/firstlight/wazuh/alerts` | Fetch/ingest Wazuh alerts | Checkpointed event ingestion | Wazuh API/worker tests + real manager integration | Real source unverified |
| `/api/health` | Health/readiness snapshot | Provider checks, no business write | health snapshot tests; dependency outage injection | Partial; verify readiness semantics |
| `/api/version` | Runtime/build identity | No business write | deployed SHA compared to main SHA | Implemented; deployed value unverified |

**Required mapping for every interactive control:** add/maintain an entry in `docs/PHASE0_UI_ACTION_MAP.md` identifying the component, action, endpoint, required role/tenant, persistent write, external side effect, failure behavior, and test. If any value is unknown, mark it unverified; do not infer from button labels.

### Python services, adapters and background work

| Component | Role | State |
|---|---|---|
| `satark.py`, `ui/*` | Streamlit application and navigation/views | Present; route parity and production usage unverified |
| `firstlight_api.py` | FIRSTLIGHT API | Present; deployment/provider wiring unverified |
| `firstlight_ingest.py` | Event normalization/ingestion | Present; real-source durability unverified |
| `firstlight_wazuh.py` | Wazuh API/adapter | Present; real manager credentials/connectivity unverified |
| `firstlight_wazuh_worker.py` | Wazuh collection worker | Present; live scheduling and restart recovery unverified |
| `firstlight_investigation_worker.py` | Durable investigation processing | Present; queue/worker lifecycle in target environment unverified |
| `firstlight_engine.py`, `firstlight_agents.py` | Investigation logic/agent workflow | Present; end-to-end evidence grounding unverified |
| `firstlight_rules.py` | Deterministic detection rules | Present; rule coverage, mapping and live alerts unverified |
| `ai_provider.py`, `analysis_engine.py` | Model-provider abstraction and analysis | Present; real local inference health/benchmark unverified |
| `ai/service/*` | Separate inference service and schemas | Present; deployment and model artifact unverified |
| `evidence_engine.py`, `findings.py`, `reports.py` | Evidence integrity, findings and report generation | Present; persistence/reproducibility tests required |
| `integrations/response_actions.py` | Response integrations | Treat as simulation-only unless real provider state is verified |
| `threat_intel.py`, `radar_background.py` | Enrichment and background monitoring | Present; source configuration/freshness/delivery unverified |
| `rate_limiter.py`, `url_security.py`, `satark_utils.py` | Security/support utilities | Present; production settings and route coverage require review |

### Supabase migration inventory

There are 31 migration files in `supabase/migrations` at this snapshot. They cover core case storage, foreign-key indexes, tenant provisioning, private evidence storage, audit hash chain, findings/reports, audit verification, upload limits, case identity immutability, approval hardening, Wazuh checkpoints, investigation jobs, case notes, assignable members, storage policies, support indexes, membership policy rebinding and private approval RPC implementations.

**Important:** file presence is not proof of application. The shared project `nihdhoom` (`igqgtlmnwssjaoxkkzbm`) is shared by SATARK, Nirdhoom and Saathi. Known pending SATARK migrations are:
- `20261020050000_satark_foreign_key_support_indexes.sql`
- `20261020051000_satark_rebind_membership_policies.sql`
- `20261020052000_satark_private_approval_rpc_implementations.sql`

Known history entries `202610200004` and `20261020042000` require careful repair only under the operator procedure in `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`. No reset, blind push, or broad shared-project mutation is authorized by this baseline.

### Tests and CI

Repository includes Python tests for AI provider, analysis, evidence, findings, FIRSTLIGHT agents/API/engine/ingestion/rules/Wazuh/workers, reports, response actions, threat intelligence, security utilities and UI; web contract tests cover API auth/status, sessions, tenant isolation, storage, evidence signatures, approvals, timeouts, rate limiting, and UI contracts. Workflows include CI, CodeQL, AI CI, FIRSTLIGHT API CI, web CI, local Supabase migration validation and production smoke.

A green workflow is insufficient if integration tests were skipped because secrets were missing. Release evidence must include each required job's result and skipped-step reason.

## Capability registry semantics

The machine-readable registry lives at `docs/capability-registry.json`. Statuses mean:
- `configured`: required configuration is present and validated (not necessarily healthy).
- `healthy`: a real dependency check succeeded recently and records a timestamp.
- `degraded`: capability works with a documented limitation or a dependency is failing.
- `disabled`: deliberately disabled by configuration/policy.
- `unverified`: no current runtime evidence supports a stronger claim.
- `partially_wired`: code exists but the complete production path is not verified.
- `simulated`: behavior is intentionally a fixture/mock and must never be displayed as real.

The repository registry is a static baseline, **not a live health endpoint**. Runtime health must be generated from server-side checks, redact secrets, include `checkedAt` and `reasonCode`, and distinguish `no_data` from `healthy_no_findings`.

## Phase 0 exit criteria

- [x] Snapshot commit and repository path inventory recorded.
- [x] UI/API route inventory recorded with expected persistence/side-effect/test mapping.
- [x] Known migration discrepancy and shared-project freeze recorded.
- [x] Capability registry with conservative statuses added.
- [ ] Every individual UI control audited against source and tests (follow-up map is a working inventory, not complete behavioral proof).
- [ ] Runtime capability endpoint backed by actual dependency checks and timestamps.
- [ ] Dedicated non-production Supabase integration tests pass without skips.
- [ ] Exact main commit deployed and smoke-tested; currently unverified.

## Immediate safe order

1. Preserve this baseline and avoid shared Supabase writes.
2. Review `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md` against the actual linked project and exact dry-run.
3. Finish cookie-only browser auth before expanding workflow surface.
4. Add server-generated capability health with fail-closed semantics.
5. Use dedicated non-production Supabase and real authorized Wazuh lab for end-to-end evidence.
6. Resolve Vercel authorization/quota and deploy only after all release-required tests pass.
