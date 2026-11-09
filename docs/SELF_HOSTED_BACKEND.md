# SATARK self-hosted backend

## Goal

The application backend is owned by SATARK. It does not require Supabase Auth, PostgREST, Supabase Storage, Supabase RPC, a Supabase project URL, or a Supabase key.

## Components

- **FastAPI** serves authenticated application APIs.
- **SQLAlchemy 2.x** maps users, opaque sessions, workspaces, memberships, cases, notes, evidence, findings, reports, approvals, audit events, and durable investigation jobs.
- **Argon2id** hashes passwords; session tokens are random opaque values and only their SHA-256 digests are stored. Near-expiry cookie sessions rotate atomically and previous tokens are revoked.
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

Open `http://localhost:3000`. The default local Compose stack uses SQLite and a named `satark_data` volume for the database and evidence objects. It starts without Ollama; deterministic analysis and FIRSTLIGHT rules work without an AI model. To opt into local model inference, start the optional AI profile with `docker compose -f docker-compose.local.yml --profile ai up --build`. The Ollama model is then available inside the Compose network. No hosted AI API key is required.

## Multi-instance deployment

Set `SATARK_DATABASE_URL` to a PostgreSQL connection string using the SQLAlchemy psycopg driver, for example:

~~~text
postgresql+psycopg://satark:REDACTED@db.internal:5432/satark
~~~

Mount a private durable evidence volume at `SATARK_EVIDENCE_DIR` and share it between the API and investigation worker. The filesystem must not be exposed by a public static route. Use a managed secret store for database credentials. Configure TLS to PostgreSQL, least-privilege database roles, backups, restore drills, retention/deletion, and monitoring.

SQLite is intended for local development and single-host use, not horizontally scaled production. PostgreSQL is required for multiple API/worker instances because queue claims and tenant audit writes rely on row-level transaction locks. The runtime database role must not be PostgreSQL superuser or have `BYPASSRLS`; `FORCE ROW LEVEL SECURITY` does not constrain superusers. Run migrations with a controlled schema-owner role and give the runtime role only the required DML privileges.

## Authentication and authorization

- Passwords are hashed using Argon2id; plaintext passwords are never stored.
- Session tokens are generated with a cryptographically secure random generator, stored as SHA-256 digests, and delivered in HttpOnly, SameSite=Lax cookies.
- Session expiry and revocation are checked on every authenticated request. Near-expiry sessions rotate through a one-time atomic refresh endpoint; old session tokens are revoked. Rotated-token reuse revokes the entire session family, while a new login creates an independent family.
- Failed sign-ins are counted in SATARK's database by a one-way email key; ten failures in a 15-minute window trigger a 15-minute cooldown. Password-reset delivery is capped per account.
- Cookie-authenticated mutations validate both the Origin host and scheme. Empty bearer headers cannot bypass cookie CSRF checks.
- Password recovery uses single-use, 30-minute SHA-256-digested tokens, invalidates prior reset links, and revokes all sessions after a successful reset.
- Email verification is opt-in with `SATARK_REQUIRE_EMAIL_VERIFICATION=true`. When enabled, signup does not issue a session until a single-use, 30-minute verification token is confirmed. Existing accounts are grandfathered by the migration using their original creation timestamp. SMTP delivery and `SATARK_PUBLIC_BASE_URL` must be configured before enabling the setting. The browser supports verification completion and generic resend requests.\n- TOTP MFA encrypts authenticator secrets at rest using `SATARK_MFA_ENCRYPTION_KEY`, requires an authenticator code at sign-in, and issues one-time recovery codes stored with Argon2id hashes. The account security panel supports enrollment and disable; disabling MFA revokes all active sessions. Set `SATARK_REQUIRE_MFA=true` to block workspace access until each account enrolls an authenticator; the setup routes remain available so users can enroll. Generate the key with `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'` and keep it stable in a secret manager. If the key is lost, enrolled factors cannot be decrypted.\n- SMTP delivery uses `SATARK_SMTP_*`; `SATARK_PUBLIC_BASE_URL` must be the trusted public origin. Password-reset and verification requests return generic responses whether an account exists or email is unavailable.
- Every tenant-scoped API verifies a membership row and allowed role before accessing a case or workspace. PostgreSQL also enables and forces row-level security on tenants, cases, notes, evidence, findings, reports, audit events, approvals, ingestion checkpoints, and investigation jobs. The API binds the authenticated user to a transaction-local setting; trusted workers use a separate transaction-local worker flag for queue claims and then set the requesting actor identity before reading tenant content. The membership table remains an internal authorization mapping used by the policy helper and is not directly exposed to browser clients.
- Workspace creation grants the creating account the owner role. Owners can invite existing or unregistered email addresses as responder, analyst, or viewer. Invitation tokens are stored as digests, expire after seven days, are single-use, and are bound to the invited email; SMTP and `SATARK_PUBLIC_BASE_URL` must be configured. Invitations use a token-scoped PostgreSQL RLS policy so an invited user can accept before becoming a member.
- There is no browser-visible service key or database credential.

## Evidence integrity

Uploaded files are bounded to 4 MiB per object and checked against supported content signatures. Each object is stored under a server-generated identifier inside a tenant/case directory. The database stores the SHA-256 digest and metadata. Download and verification endpoints recompute the digest. A matching digest proves the stored bytes match the recorded upload digest; it does not prove original-source authenticity or independently establish chain of custody.

Investigation processing is limited to 500 evidence records, 32 MiB total evidence bytes, 4 MiB per object, and a 1 MiB result snapshot. Deterministic findings reference evidence IDs; tampered bytes are not treated as trusted evidence.

## Backup, verification, and restore

The repository includes `scripts/satark_backup.py` for a versioned archive containing a consistent database export, the private evidence tree, and a SHA-256 manifest. The utility rejects symlinks and unsafe archive paths, restores evidence with 0600/0700 permissions, and rebases stored absolute evidence keys to the restored volume. PostgreSQL dump/restore and evidence rebasing are covered by CI. For PostgreSQL, set `SATARK_BACKUP_DATABASE_URL` to a separate superuser or BYPASSRLS-capable backup/restore connection with the necessary target-database creation privileges; restore into a pre-created empty target database. Never reuse that credential for the runtime API.

Stop SATARK API and worker writers before creating a backup so the database and evidence files represent the same point in time:

~~~bash
docker compose -f docker-compose.local.yml stop web firstlight-wazuh-worker firstlight-investigation-worker streamlit firstlight-api
docker compose -f docker-compose.local.yml run --rm --no-deps firstlight-api \
  python /app/scripts/satark_backup.py create --output /data/backups/satark-$(date -u +%Y%m%dT%H%M%SZ).tar.gz
docker compose -f docker-compose.local.yml run --rm --no-deps firstlight-api \
  python /app/scripts/satark_backup.py verify /data/backups/<backup-file>.tar.gz
~~~

Restore only into an empty target database and empty evidence directory:

~~~bash
docker compose -f docker-compose.local.yml run --rm --no-deps \
  -e SATARK_DATABASE_URL=sqlite:////data/restore/satark.db \
  -e SATARK_EVIDENCE_DIR=/data/restore/evidence firstlight-api \
  python /app/scripts/satark_backup.py restore /data/backups/<backup-file>.tar.gz
~~~

For PostgreSQL, install the matching `pg_dump` and `pg_restore` client tools and set `SATARK_DATABASE_URL` to the empty target database. The restore command does not drop existing database objects. Test restores in an isolated environment before production use.

The archive is **not encrypted**. Encrypt it with an approved KMS, age, or GPG workflow before off-host transfer; restrict file permissions and retention. Do not place backup archives inside the live evidence directory. Backup/restore code is not a substitute for scheduled restore drills, PostgreSQL WAL/PITR, or tested recovery objectives.

## Current limitations

- MFA and email verification are implemented as opt-in account policies. Email verification is not enforced unless `SATARK_REQUIRE_EMAIL_VERIFICATION=true` is set; MFA can be enrolled per account when `SATARK_MFA_ENCRYPTION_KEY` is configured. Organization-wide mandatory MFA can be enforced with `SATARK_REQUIRE_MFA=true`. Login throttling is per normalized email, not a global per-IP or edge rate limit; deploy an edge/WAF limit as an additional control.
- Workspace owners can add existing SATARK accounts, manage member roles/removal, and send/revoke time-limited invitations for unregistered users.
- PostgreSQL RLS is now enabled and forced on the core tenant data tables, with an integration test that uses a non-owner, non-superuser application role. SQLite relies on API membership checks. The membership mapping table is intentionally kept outside RLS because the policy helper reads it; it must remain inaccessible to browser clients. A production threat-model review, role/privilege review, and adversarial concurrency testing are still required.
- The hash-linked audit stream is application-managed and PostgreSQL rejects ordinary UPDATE/DELETE mutations through a trigger. It is not externally anchored and is not a certified chain-of-custody service.
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

