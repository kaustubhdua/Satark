# Phase 0 — real SATARK/FIRSTLIGHT baseline

**Inventory baseline:** `1f939064760c3c2410cc7435bec273c4235b80fb` (main at 2026-10-20 UTC). This is a source inventory, not a claim of production operation. The current branch adds a truthful capability registry and this baseline. Live external systems are not verified by repository inspection.

## Status vocabulary

- **Live (code path exists):** source implementation exists; production functionality still requires runtime proof.
- **Partially wired:** route/adapter exists, but the full data and side-effect path is not proven.
- **Mock/simulated:** test-only or simulation-only; never report as a real provider action.
- **Unconfigured:** required settings/provider are absent or no provider exists.
- **Unverified:** code exists but real runtime, persistence, tenant isolation or end-to-end behavior has not been demonstrated.
- Capability endpoint statuses are `configured`, `healthy`, `degraded`, `disabled`, and `unverified`. This initial registry intentionally never emits `healthy` because it performs no network probes.

## Next.js page inventory

| Route | Source | Initial classification | Required proof |
|---|---|---|---|
| `/` | `web/src/app/page.tsx` | partially wired | Browser tests for all actions |
| `/cases` | `web/src/app/cases/page.tsx` | partially wired | Authenticated CRUD and tenant denial |
| `/firstlight` | `web/src/app/firstlight/page.tsx` | partially wired | Real authenticated investigation lifecycle |
| `/investigate` | `web/src/app/investigate/page.tsx` | unverified | Source-to-persisted-result workflow |
| `/reports` | `web/src/app/reports/page.tsx` | partially wired | Persisted report and export reconciliation |
| `/learn` | `web/src/app/learn/page.tsx` | unverified | Content and control audit |
| `/tools` | `web/src/app/tools/page.tsx` | unverified | Real adapters and unavailable states |
| `/url` | `web/src/app/url/page.tsx` | unverified | Safe URL inspection and dependency failure |
| `/qr` | `web/src/app/qr/page.tsx` | unverified | Client processing and file bounds |
| `/pdf-review` | `web/src/app/pdf-review/page.tsx` | unverified | Parser isolation, size bounds and errors |
| `/image-review` | `web/src/app/image-review/page.tsx` | unverified | File bounds and processing behavior |
| `/media-review` | `web/src/app/media-review/page.tsx` | unverified | File bounds and processing behavior |
| `/login` | `web/src/app/login/page.tsx` | partially wired | HttpOnly cookie migration, refresh and logout |
| `/reset-password` | `web/src/app/reset-password/page.tsx` | unverified | Provider flow, expiry and recovery |
| Error/loading/not-found | files under `web/src/app` | code exists | Browser accessibility and safe failure |

## Next.js API inventory

| Endpoint | Source | Initial classification | Required proof |
|---|---|---|---|
| `GET /api/health` | `web/src/app/api/health/route.ts` | live configuration snapshot | Never treat as readiness |
| `GET /api/capabilities` | `web/src/app/api/capabilities/route.ts` | live configuration snapshot | Status vocabulary and no secret leakage |
| `GET /api/version` | `web/src/app/api/version/route.ts` | live code path | Missing commit fails closed |
| `GET/POST /api/cases` | `web/src/app/api/cases/route.ts` | partially wired | Anonymous 401, CRUD persistence, RLS |
| `POST /api/analyze` | `web/src/app/api/analyze/route.ts` | partially wired | Limiter and no fake AI results |
| `GET/POST /api/evidence` | `web/src/app/api/evidence/route.ts` | partially wired | Bounded upload, private storage, digest |
| `GET /api/evidence/records` | `web/src/app/api/evidence/records/route.ts` | partially wired | Tenant-scoped listing |
| `GET /api/evidence/[id]/verify` | corresponding route | partially wired | Recomputed digest and authorization |
| `GET/POST /api/findings` | `web/src/app/api/findings/route.ts` | partially wired | Case tenant ownership and evidence provenance |
| `GET/POST /api/reports` | `web/src/app/api/reports/route.ts` | partially wired | Stored facts and tenant-safe export |
| `GET /api/reports/[id]` | corresponding route | partially wired | Tenant-scoped read/download |
| `POST /api/cases/notes` | corresponding route | partially wired | Membership and audit |
| `POST /api/audit/verify` | corresponding route | partially wired | Verification against stored audit rows |
| `POST/DELETE /api/auth/session` | corresponding route | partially wired | Cookie flags, refresh, expiry, revocation |
| `GET /api/firstlight/approvals` | corresponding route | partially wired | Exact payload binding, expiry, replay rejection |
| `POST /api/firstlight/evidence/source` | corresponding route | partially wired | Source identity and tenant authorization |
| `POST /api/firstlight/investigate` | corresponding route | partially wired | Durable enqueue and persisted results |
| `GET /api/firstlight/jobs` | corresponding route | partially wired | Ownership, retry and restart recovery |
| `GET /api/firstlight/wazuh/alerts` | corresponding route | partially wired | Upstream auth, pagination, freshness and failures |

## Database and migration inventory

Migrations live in `supabase/migrations/`; pgTAP tests are in `supabase/tests/`. The repository contains migrations for case/storage, foreign-key indexes, tenant provisioning, evidence storage, audit hash chains, findings/reports, immutable case identity, durable approvals, trigger ACL hardening, storage/membership policies, Wazuh checkpoints, investigation jobs, case notes, assignment RPCs and private approval RPC implementations.

Database feature areas referenced by those migrations include tenants, memberships, cases, evidence, findings, reports, audit events, ingestion checkpoints, investigation jobs, case notes, approvals and private helper/RPC functions. The exact live schema must be queried on a confirmed non-production project; filenames do not prove deployed schema parity.

**Migration freeze:** the shared Supabase project `nihdhoom` has a known ledger mismatch. Do not reset it or run an unreviewed push. Follow `docs/SUPABASE_MIGRATION_HISTORY_REPAIR.md`, verify the linked project reference, inspect `supabase migration list --linked`, and require a dry-run containing exactly the reviewed SATARK-only migrations before an authorized operator applies them.

## Workers, providers and security modules

| Component | Source | Initial classification | Proof required |
|---|---|---|---|
| Investigation worker | `firstlight_investigation_worker.py` | unverified | Durable queue, lease/retry and restart recovery |
| Wazuh worker | `firstlight_wazuh_worker.py` | unverified | Real manager, checkpoint, dedupe and recovery |
| Wazuh adapter | `firstlight_wazuh.py` | partially wired | Authenticated API, pagination and source identity |
| Ingestion | `firstlight_ingest.py` | partially wired | Schema validation, timestamps, raw hash and tenant binding |
| Detection rules | `firstlight_rules.py` | unverified against live telemetry | Positive/negative corpus and rule provenance |
| AI interface/service | `ai_provider.py`, `ai/service/` | partially wired | Real inference health, typed output and evaluation |
| Evidence | `evidence_engine.py` and web APIs | partially wired | Immutable finalized evidence and independent export hash |
| Findings/analysis | `findings.py`, `analysis_engine.py` | partially wired | Reproducible persisted outputs and evidence citations |
| Response actions | response implementation and `tests/test_response_actions.py` | simulated until independently proven | Real provider request ID, exact-action approval and read-after-action verification |
| Threat intelligence | `threat_intel.py` and related modules | unverified | Provider setup, source provenance, license and freshness |

## UI action → endpoint → durable effect → test map (initial)

| UI action family | Endpoint | Durable write / side effect | Required test |
|---|---|---|---|
| Sign in/out | `/api/auth/session` and Supabase Auth | HttpOnly cookie lifecycle | Cookie flags, refresh, expiry and revocation |
| Case create/update | `/api/cases` | Case row and audit event | Read-after-write plus cross-tenant denial |
| Evidence upload/verify | `/api/evidence`, `/api/evidence/records`, `/api/evidence/[id]/verify` | Private object, metadata, audit | Hash recomputation and unauthorized download denial |
| Findings | `/api/findings` | Findings rows | Persisted evidence IDs and case ownership |
| Investigation | `/api/firstlight/investigate`, `/api/firstlight/jobs` | Durable job and output | Worker restart and idempotent retry |
| Wazuh collection | `/api/firstlight/wazuh/alerts` | Event rows/checkpoint | Real lab event, pagination and duplicate suppression |
| Approval | `/api/firstlight/approvals` | Approval row and audit | Payload hash, expiry and replay rejection |
| Reports | `/api/reports`, `/api/reports/[id]` | Persisted report/export | Reconcile against stored findings/evidence |
| Audit verification | `/api/audit/verify` | Read-only result | Tamper, deletion and ordering tests |
| Live response | Must remain disabled absent a verified provider executor | External side effect only after approval | Provider ID plus independent state verification |

This is a route/action-family map, not an exhaustive per-button handler trace. That requires inspecting every page component and event handler, then adding a test for each actionable control.

## Capability registry

`GET /api/capabilities` reports safe capability state. It performs no network calls, never exposes secret values, keeps `healthVerified=false`, and never returns `healthy` without probes. Live response is explicitly disabled. This is intentionally conservative.

## External blockers

1. **Supabase:** requires read-only reconciliation, exact dry-run and authorized operator for writes. No hosted database writes were performed as part of this baseline.
2. **Vercel:** previous deployment operations returned 403 / build-rate-limit. Code cannot grant account permissions or increase quota. Exact production SHA remains unverified until authorized access is restored and smoke tests pass.
3. **Real telemetry:** requires an authorized Wazuh manager and enrolled Windows and Linux endpoints. Repository fixtures are not live telemetry.
4. **Credentials:** dedicated non-production test identities, notification provider, model runtime and integration secrets must be set in provider settings. Never send credentials in chat.

## Phase 0 exit gate

- [ ] Inventory cross-checked against every route, migration, table, worker, provider and UI handler.
- [ ] Every actionable control mapped to handler, endpoint, persistent write/side effect and test.
- [ ] Database inventory and ledger verified against a confirmed isolated non-production database.
- [x] Initial capability registry added with conservative states and secret-safe output.
- [ ] Shared Supabase writes remain frozen until reviewed dry-run approval.
- [ ] External integration and deployment blockers cleared with evidence.

Phase 0 is **not complete** until the remaining UI-handler trace, full schema inventory and live project reconciliation have evidence.
