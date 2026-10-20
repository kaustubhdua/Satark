# SATARK UI action map — working contract

Snapshot: `main@1f939064760c3c2410cc7435bec273c4235b80fb`. This map is deliberately conservative: a route/component name is not proof that every control has a complete backend effect. For each visible control, fill in the exact component/handler and test reference before marking it verified.

| UI surface | Action / intent | Backend endpoint | Persistent write | External side effect | Required access / scope | Test contract | Status / gap |
|---|---|---|---|---|---|---|---|
| Login | Sign in | `POST /api/auth/session` after Supabase Auth | Session cookies only; auth provider owns identity | Supabase Auth request | Authenticated identity, same-origin | `session-cookie-contract.test.mjs`; browser login | Partially wired: remove token storage from browser helper |
| Header/account | Sign out | `DELETE /api/auth/session` | Clears session cookies | None | Current session | session-cookie contract + browser logout | Verify all logout paths clear server cookies and client state |
| Cases | List cases | `GET /api/cases` | None | Supabase read | Active user + tenant membership | `cases-api.test.mjs`, unauthenticated status, tenant integration | Partially wired; deployed auth path unverified |
| Cases | Create case | `POST /api/cases` | Case row + audit event | None | Authorized tenant role | cases API + tenant integration | Verify persistent row and audit event together |
| Cases | Update case | `PATCH /api/cases` | Case row + audit event | None | Tenant membership + allowed role | cases API + body contract + tenant integration | Verify immutable identity fields and role changes |
| Case workspace | Add note | `POST /api/cases/notes` | Case note + audit event | None | Case tenant and allowed role | `case-notes-api.test.mjs` + tenant integration | Verify actor, timestamp and case ownership |
| Evidence | Upload evidence | `POST /api/evidence` | Object + evidence metadata + audit event | Object storage write | Case tenant, role, size/type policy | evidence signature, storage schema, body limit tests | Verify object and metadata failure compensation |
| Evidence | List/read evidence | `GET /api/evidence/records` or `GET /api/evidence` | None | Object read if content fetched | Tenant/case membership; raw-source role restrictions | storage schema + tenant integration | Verify every query and signed URL is tenant-bound |
| Evidence | Verify evidence | `POST /api/evidence/[id]/verify` | Verification audit result if designed | Object read/hash | Tenant/case membership | evidence signature + cross-tenant tests | Tamper and missing-object behavior must fail closed |
| Audit | Verify chain | `POST /api/audit/verify` (confirm method in route) | No mutation to historical audit events | DB RPC/read | Authorized tenant/auditor role | audit verify redirect + RPC tests | Confirm route method and role contract from implementation |
| Analyze | Analyze content | `POST /api/analyze` | Not assumed; verify persistence path | Model/provider call | Auth, limits, timeout | local analysis/evaluation + API timeout | Provider health and persistence are unverified |
| Findings | Create/list findings | `POST/GET /api/findings` | Finding rows + audit | None | Tenant and case scope | persistent workflows + tenant integration | Verify source evidence references and provenance |
| FIRSTLIGHT | Start investigation | `POST /api/firstlight/investigate` | Durable job, case-linked findings/timeline/evidence as stages complete | AI inference; possibly Wazuh reads | Tenant membership and allowed role | firstlight investigation API/worker tests | Verify no success response until durable enqueue succeeds |
| FIRSTLIGHT jobs | Inspect job status | `GET /api/firstlight/jobs` | None | None | Tenant + role | jobs API + tenant integration | Verify no cross-tenant job ID enumeration |
| FIRSTLIGHT source evidence | Fetch raw source evidence | `GET /api/firstlight/evidence/source` | None | Storage read | Tenant/case membership; viewer restrictions | storage policy + source evidence tests | Verify raw Wazuh payload role boundary |
| FIRSTLIGHT Wazuh | Collect/list alerts | `GET /api/firstlight/wazuh/alerts` (confirm supported methods) | Normalized event + checkpoint on ingestion path | Wazuh manager API request | Server-side connector credential; source bound to tenant by trusted config | Wazuh API/worker tests + real lab test | Live manager and endpoint collection unverified |
| Approvals | Request/decide approval | `/api/firstlight/approvals` | Approval row + audit event | No response action by approval alone | Tenant/role; exact action + payload hash | approvals tests + live RPC ACL verification | Live DB migrations unverified; never infer response executed |
| Reports | Generate/list report | `POST/GET /api/reports` | Versioned report based on persisted findings/evidence | None unless explicit export | Tenant/case scope | reports + persistent workflow tests | Reproducibility and source versions unverified |
| Reports | Read report | `GET /api/reports/[id]` | None | None | Tenant membership | reports + tenant integration | Cross-tenant read must return non-disclosing denial |
| Health | Inspect dependency health | `GET /api/health` | None | Server-side dependency probes only | Avoid leaking secrets/config values | health snapshot + outage injection | Do not return healthy when required dependencies are unconfigured |
| Version | Inspect build identity | `GET /api/version` | None | None | Public-safe build metadata only | compare response to deployed commit | Deployed SHA currently unverified |
| Response | Execute containment/action | Adapter-specific; no generic endpoint assumed | Provider action audit + result | Real provider call | Separate worker, exact approval binding, least privilege | `tests/test_response_actions.py` plus real lab test | Simulated until independently verified; high-impact actions disabled |

## Rules for adding or verifying an action

1. Record exact source file, event handler and HTTP method/path; do not infer from the page URL.
2. Record authorization rule (user, tenant, role, case ownership) and how revocation is rechecked.
3. Name every durable write and the transaction/compensation behavior if a later step fails.
4. For external effects, record provider, idempotency key, provider request ID, timeout and independent post-action verification.
5. Link a test that asserts the negative path as well as success (anonymous, wrong tenant, wrong role, expired/revoked identity, timeout/provider outage).
6. Status must remain `unverified` until the real target environment is exercised. Test fixtures are valid only as isolated fixtures and must never appear as live telemetry.
7. For any feature with no data, render `no_data`/unknown, not “all clear” or “no threats detected.”
