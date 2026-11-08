# SATARK self-hosted backend

## Goal

The application backend is owned by SATARK. It does not require Supabase Auth, PostgREST, Supabase Storage, Supabase RPC, a Supabase project URL, or a Supabase key.

## Components

- **FastAPI** serves authenticated application APIs.
- **SQLAlchemy 2.x** maps users, opaque sessions, workspaces, memberships, cases, notes, evidence, findings, reports, approvals, audit events, and durable investigation jobs.
- **Argon2id** hashes passwords; session tokens are random opaque values and only their SHA-256 digests are stored.
- **Alembic** applies versioned schema migrations.
- **Private filesystem storage** stores evidence bytes outside the web root. The API verifies each download against the recorded SHA-256.
- **FIRSTLIGHT worker** claims jobs from the same database, enforces bounded evidence/result sizes, persists findings and reports, and records completion in the audit chain.
- **Next.js** proxies same-origin `/api/*` requests to the private FastAPI service. Database credentials are never exposed to the browser.

## Local setup

Requirements: Docker Compose.

~~~bash
cp .env.example .env
docker compose -f docker-compose.local.yml up --build
~~~

Open `http://localhost:3000`. The local Compose stack uses SQLite and a named `satark_data` volume for the database and evidence objects. Optional Ollama runs locally in the Compose network; SATARK's deterministic analysis and FIRSTLIGHT rules do not need a hosted AI API key.

## Multi-instance deployment

Set `SATARK_DATABASE_URL` to a PostgreSQL connection string using the SQLAlchemy psycopg driver, for example:

~~~text
postgresql+psycopg://satark:REDACTED@db.internal:5432/satark
~~~

Mount a private durable evidence volume at `SATARK_EVIDENCE_DIR` and share it between the API and investigation worker. The filesystem must not be exposed by a public static route. Use a managed secret store for database credentials. Configure TLS to PostgreSQL, least-privilege database roles, backups, restore drills, retention/deletion, and monitoring.

SQLite is intended for local development and single-host use, not horizontally scaled production. PostgreSQL is required for multiple API/worker instances because queue claims and tenant audit writes rely on row-level transaction locks.

## Authentication and authorization

- Passwords are hashed using Argon2id; plaintext passwords are never stored.
- Session tokens are generated with a cryptographically secure random generator, stored as SHA-256 digests, and delivered in HttpOnly, SameSite=Lax cookies.
- Session expiry and revocation are checked on every authenticated request.
- Cookie-authenticated mutations reject cross-origin requests.
- Every tenant-scoped API verifies a membership row and allowed role before accessing a case or workspace.
- Workspace creation grants the creating account the owner role.
- There is no browser-visible service key or database credential.

## Evidence integrity

Uploaded files are bounded to 4 MiB per object and checked against supported content signatures. Each object is stored under a server-generated identifier inside a tenant/case directory. The database stores the SHA-256 digest and metadata. Download and verification endpoints recompute the digest. A matching digest proves the stored bytes match the recorded upload digest; it does not prove original-source authenticity or independently establish chain of custody.

Investigation processing is limited to 500 evidence records, 32 MiB total evidence bytes, 4 MiB per object, and a 1 MiB result snapshot. Deterministic findings reference evidence IDs; tampered bytes are not treated as trusted evidence.

## Current limitations

- Email verification, password-reset delivery, MFA, and account-recovery workflows are not implemented in the self-hosted identity service.
- Workspace member invitation/role administration is not implemented yet; workspace creation currently creates a single owner membership.
- Database-level PostgreSQL RLS policies are not yet part of this migration. Tenant isolation currently depends on the API's membership checks and tenant-scoped SQL queries; do not treat this as independently audited multi-tenant production isolation until DB-level policies and adversarial integration tests are added.
- The hash-linked audit stream is application-managed. It is not externally anchored and is not a certified chain-of-custody service.
- The Wazuh adapter remains optional and needs its own target-environment validation.
- No live endpoint, account, network, or process response action is executed by the FIRSTLIGHT investigation worker.
- The migration branch must pass Python, frontend, browser/accessibility, migration, and security checks before it is merged or deployed.

## Validation

From the repository root:

~~~bash
python -m pip install -r firstlight-api-requirements.txt pytest
SATARK_DATABASE_URL=sqlite:////tmp/satark-test.db alembic upgrade head
SATARK_DATABASE_URL=sqlite:////tmp/satark-test.db python -m pytest -q tests/test_satark_backend.py tests/test_firstlight_investigation_worker.py
~~~

From `web/`:

~~~bash
npm ci
npm run test:ci
npm run test:browser
~~~

