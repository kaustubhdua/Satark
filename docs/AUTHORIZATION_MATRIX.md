# Authorization matrix (self-hosted API)

Derived from `satark_backend.py`. Every route except those marked **Public** requires a valid bearer session
(`current_user`). Tenant-scoped routes then call `require_membership`, which returns 403 unless the caller has a
membership in the requested tenant with an allowed role. Roles: `owner`, `responder`, `analyst`, `viewer`.
"Member" means any role, including `viewer`. Cross-tenant ID changes are covered by
`tests/test_satark_isolation_and_uploads.py` (also run against PostgreSQL with RLS when `SATARK_TEST_POSTGRES_URL` is set).

`tests/test_authorization_matrix.py` fails if a route is added without being listed here or loses authentication.

| Method | Path | Access |
|---|---|---|
| GET | /api/health | Public (non-sensitive status) |
| GET | /api/health/storage | Public (non-sensitive status) |
| POST | /api/auth/email-verification/request | Public |
| POST | /api/auth/email-verification/complete | Public (single-use token) |
| POST | /api/auth/signup | Public |
| POST | /api/auth/login | Public |
| POST | /api/auth/password-reset/request | Public |
| POST | /api/auth/password-reset/complete | Public (single-use token) |
| GET | /api/auth/session | Authenticated |
| POST | /api/auth/refresh | Authenticated |
| POST | /api/auth/logout | Authenticated |
| GET | /api/auth/mfa/status | Authenticated (own account) |
| POST | /api/auth/mfa/enroll/start | Authenticated (own account) |
| POST | /api/auth/mfa/enroll/confirm | Authenticated (own account) |
| POST | /api/auth/mfa/disable | Authenticated (own account) |
| POST | /api/workspaces | Authenticated (creator becomes owner) |
| GET | /api/workspaces | Authenticated (own memberships only) |
| POST | /api/workspaces/invitations/accept | Authenticated; token must match the signed-in account |
| POST | /api/workspaces/invitations | owner |
| GET | /api/workspaces/invitations | owner |
| DELETE | /api/workspaces/invitations | owner |
| GET | /api/workspaces/members | Member |
| POST | /api/workspaces/members | owner |
| PATCH | /api/workspaces/members | owner |
| DELETE | /api/workspaces/members | owner |
| GET | /api/cases | Member |
| POST | /api/cases | owner, responder, analyst |
| PATCH | /api/cases | owner, responder |
| GET | /api/cases/notes | Member |
| POST | /api/cases/notes | owner, responder, analyst |
| GET | /api/findings | Member |
| POST | /api/findings | owner, responder, analyst |
| GET | /api/reports | Member |
| POST | /api/reports | owner, responder, analyst |
| GET | /api/reports/{report_id} | Member |
| POST | /api/evidence | owner, responder, analyst |
| POST | /api/evidence/records | owner, responder, analyst |
| GET | /api/evidence | Member |
| GET | /api/evidence/records | Member |
| GET | /api/evidence/{evidence_id}/download | Member |
| GET | /api/evidence/{evidence_id}/verify | Member |
| GET | /api/firstlight/evidence/source | Member |
| GET | /api/audit/events | Member |
| GET | /api/audit/verify | Member |
| GET | /api/firstlight/jobs | Member |
| POST | /api/firstlight/jobs | owner, responder, analyst |
| POST | /api/firstlight/investigate | owner, responder, analyst |
| GET | /api/firstlight/wazuh/alerts | Member |

## What this does and does not prove
Role checks are enforced in application code and are unit-tested; the audit hash chain detects edits and gaps in
stored events but is not certified chain-of-custody. Wazuh-backed routes depend on a configured connector and have
not been exercised against a live Wazuh lab.
