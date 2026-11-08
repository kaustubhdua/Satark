# Supabase-independent backend migration

**Status:** Architecture and migration contract; implementation is not complete.
**Target:** Remove all runtime dependency on Supabase Auth, PostgREST, Storage, database RPCs, and Supabase-specific environment variables.
**Branch:** remove-supabase-runtime-dependency

## Decision

SATARK will own its backend and persistence. The application will not call Supabase at runtime and will not require a Supabase project, API URL, publishable key, service-role key, Auth service, PostgREST endpoint, or Storage bucket.

Use the existing FastAPI service as the single backend boundary. Use PostgreSQL in production and SQLite for local development and automated tests. Use a private filesystem evidence store for local/single-node deployments and an S3-compatible private object-store interface (for example, MinIO) for multi-node deployments. Neither storage implementation may expose evidence publicly.

This is a backend replacement, not a security downgrade. Tenant isolation, roles, session security, immutable audit history, approval controls, evidence integrity, and fail-closed behavior remain mandatory.

## Current dependency inventory

The current Next.js application directly calls Supabase from multiple API route handlers. Authentication is performed in the browser against /auth/v1, and the server session route verifies Supabase access tokens. Case, evidence, note, report, findings, approval, and job flows use PostgREST, Storage, or database RPCs. Background workers use Supabase service-role credentials. SQL migrations encode RLS policies, membership helpers, audit triggers, approval consumption, and Storage policies.

The existing FIRSTLIGHT FastAPI service provides a bounded, token-protected investigation API, but its case investigation request is stateless. It is a foundation, not yet a replacement for the durable SATARK application backend.

## Target architecture

Browser -> same-origin Next.js BFF (HttpOnly session cookie, CSRF/origin checks) -> private FastAPI SATARK API -> Auth/session service; tenant authorization; domain services; SQLAlchemy repository; PostgreSQL production / SQLite local-test; private EvidenceStore; FIRSTLIGHT engine and integrations.

Only FastAPI may access the database or evidence store. The browser must never receive database credentials, service credentials, password hashes, raw refresh tokens, or object-store credentials. Next.js must not make direct calls to Supabase or the database.

## Required domain model

- users: normalized unique email, Argon2id password hash, verified/disabled timestamps.
- sessions: hash of opaque random session token, user, expiry, rotation/revocation metadata, created-at and last-seen timestamps. Store only token hashes.
- tenants and memberships: tenant ownership and explicit owner/responder/analyst/viewer roles.
- cases, case_notes, evidence, findings, reports: tenant-scoped rows with immutable tenant/case identity and foreign keys.
- audit_events: append-only per-tenant hash chain; canonical serialization and verification; no update/delete API.
- approvals: target-bound, expiring, one-time consumption; simulation-only until a separate live-response release gate passes.
- investigation_jobs: durable leases, idempotency, bounded retries, dead-letter/failure state, and audit linkage.
- wazuh_checkpoints: tenant/source-scoped checkpoints with overlap and replay protection.

Every tenant-owned record must be checked against membership and role in the same backend transaction as the requested operation. Never trust a client-supplied tenant ID, user ID, role, or creator field. The backend derives the actor from the validated session. Cross-tenant reads and writes must return no data and be covered by integration tests.

## Authentication and browser session contract

1. Sign-up and sign-in terminate at FastAPI; passwords are hashed with Argon2id.
2. Sessions use cryptographically random opaque tokens. Persist only a keyed/hash representation. Rotate refresh sessions on use; detect reuse and revoke the token family.
3. The Next.js same-origin session endpoint sets Secure (HTTPS), HttpOnly, SameSite=Lax cookies with narrow paths and bounded lifetimes. Enforce Origin/CSRF protections on mutations.
4. Browser API requests go through same-origin Next.js routes. The BFF forwards cookie-derived identity only to the private FastAPI origin over a trusted network. No bearer/session token in localStorage.
5. Password recovery must use a configured mail transport or be explicitly disabled with a safe administrator recovery process. Do not claim email verification if no mail provider exists.
6. Sign-out revokes the server-side session. Expiry and revocation are enforced by FastAPI, not by trusting cookie expiry alone.

## Evidence storage contract

- Preserve the existing 4 MiB upload bound and file-signature validation.
- Generate opaque object IDs; do not use user filenames as storage paths.
- Store evidence outside the web root with restrictive permissions. Enforce tenant/case authorization before reads, writes, downloads, or deletion.
- Persist SHA-256 source digest, canonical record digest, content type, size, creator, and timestamps.
- Write to a temporary object, fsync where supported, then atomically publish and commit metadata. Recover orphaned temporary files and metadata/object mismatches.
- Use private S3-compatible storage for multi-instance deployments; presigned URLs must be short-lived and issued only after authorization. No public bucket.
- Deletion must follow an explicit retention/legal-hold policy and append an audit event. Never silently delete evidence during migration.

## Supabase feature parity checklist

The migration is incomplete until every item is implemented and tested:

- Replace Supabase Auth sign-up/sign-in/refresh/logout/password recovery.
- Replace membership and tenant creation RPCs with transactional service methods.
- Replace PostgREST for cases, notes, evidence, findings, reports, approvals, jobs, checkpoints, audit events, and assignable members.
- Replace Supabase Storage with the private EvidenceStore.
- Reimplement RLS policies, membership helpers, trigger immutability, approval ACLs, and audit-chain rules in backend authorization/transactions and DB constraints/triggers where appropriate.
- Move every worker to the same repository and tenant authorization contract; remove Supabase service-role credentials.
- Remove required Supabase configuration from environment checks, Docker Compose, CI, smoke tests, deployment docs, and operator runbooks.
- Search the complete repository for SUPABASE_, supabase.co, /auth/v1, /rest/v1, /storage/v1, supabase-js, and Supabase SDK imports. Remaining matches may only be historical migration/export documentation or migration tooling, never runtime paths.

## Safe migration sequence

1. Add backend repository interfaces, SQLAlchemy models, migrations, SQLite fixtures, and PostgreSQL integration tests.
2. Implement authentication and session lifecycle; test password hashing, token rotation/reuse, expiry, revocation, CSRF, and session fixation.
3. Implement tenant and membership authorization and prove cross-tenant read/write denial for every resource.
4. Implement cases, notes, findings, reports, approvals, jobs, and append-only audit behavior with transaction and concurrency tests.
5. Implement private evidence storage and crash/recovery tests.
6. Move Next.js routes to the FastAPI BFF contract; remove browser Supabase Auth and localStorage token persistence.
7. Move workers and Wazuh checkpoints to the same repository.
8. Add a one-way export/import utility for existing Supabase data. Validate row counts, tenant ownership, evidence digests, audit-chain continuity, and referential integrity before cutover. Do not delete or mutate the source project.
9. Run the full test matrix against SQLite and PostgreSQL, security tests, browser/accessibility tests, dependency scans, and backup/restore.
10. Remove Supabase packages, env vars, workflows, and runtime references only after all application paths use the replacement backend. Deploy the replacement and verify production smoke before retiring any old backend.

## Acceptance gates

- A clean checkout starts locally with Docker Compose and no Supabase variables or credentials.
- All web features (auth, workspaces, cases, evidence, notes, findings, reports, approvals, and FIRSTLIGHT jobs) work against the replacement API.
- Automated tests prove tenant isolation for owner, responder, analyst, and viewer roles, including IDOR attempts and concurrent mutations.
- Session rotation, revocation, password reset behavior, CSRF, rate limits, and brute-force protections are tested.
- Evidence upload/download integrity, private access, deletion/retention, backup, and restore are tested.
- PostgreSQL production mode and SQLite local/test mode both pass the same repository contract suite.
- Repository-wide static search proves there is no Supabase runtime dependency.
- No production-readiness claim until the exact deployment passes these gates.

## Explicit non-goals

- Do not remove authentication or make workspaces public.
- Do not replace durable storage with browser localStorage or ephemeral process memory.
- Do not weaken tenant checks, evidence integrity, audit immutability, approval consumption, or fail-closed behavior.
- Do not silently migrate or delete data.
- Do not enable live containment/response actions as part of this backend migration.
- This architecture document alone does not complete the migration.