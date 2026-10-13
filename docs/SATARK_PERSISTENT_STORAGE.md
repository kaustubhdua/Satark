# SATARK persistent case storage — implementation notes

This migration is a reviewed starting point for a **dedicated SATARK Supabase project**. It has not been applied to any database and does not make the current Next.js UI persistent by itself. Do not apply it to the unrelated JYC website project.

## Included
- Tenant membership with owner/responder/analyst/viewer roles.
- Tenant-scoped cases and evidence metadata.
- Row-level security policies that derive identity from Supabase Auth and tenant membership.
- Evidence SHA-256 metadata fields and size constraints.
- Append-only audit-event permissions and a database trigger that rejects update/delete.
- Narrow client grants; tenant/membership provisioning remains a trusted server-side operation.

## Required before use
1. Confirm the dedicated SATARK Supabase project and its region, plan, backups and retention policy.
2. Configure Supabase Auth in the Next.js application and enforce authorization in every Route Handler and server action. UI-only checks are not authorization.
3. Implement trusted tenant provisioning, membership changes, and invitation flows with role checks and audit events.
4. Compute audit event hashes server-side over a canonical representation including the previous event hash, and validate the chain during export. The migration stores hashes but does not calculate or verify them.
5. Restrict service-role credentials to server-only code; never expose them to client bundles. Add integration tests for cross-tenant read/write denial and append-only behaviour.
6. Review schema, RLS policies, backups, deletion/retention, data residency and legal/privacy obligations before applying it.
7. Apply through a reviewed migration in a development/staging project first, run Supabase security advisors, then promote via the normal release process.

## Not enabled by this migration
- The current FIRSTLIGHT page still keeps its evidence and audit trail in browser memory.
- No live response endpoint is added. Defender isolation and Entra session revocation must remain disabled until authenticated operator authorization, target-bound confirmation, idempotency, server-side audit, and authorized test-tenant validation are complete.
- No shared rate limiter is provisioned. Configure and verify a distributed limiter or platform WAF separately.

This file is intentionally not connected to an existing database automatically: applying a schema to the wrong project or assuming credentials/authorization would be unsafe.
