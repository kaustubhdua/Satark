# SATARK persistent case storage — implementation notes

SATARK's isolated storage schema has been applied to the existing **Nirdhoom (`nihdhoom`) Supabase project**. This avoids creating another project. The schema uses the `satark_` prefix, adds five new tables and one helper function, and does not alter Nirdhoom's existing application tables or policies. Shared infrastructure still means shared project-level quotas and operational blast radius; monitor usage and back up the project.

## Included
- Tenant membership with owner/responder/analyst/viewer roles.
- Tenant-scoped cases and evidence metadata.
- Row-level security policies that derive identity from Supabase Auth and tenant membership.
- Evidence SHA-256 metadata fields and size constraints.
- Append-only audit-event permissions and a database trigger that rejects update/delete.
- Narrow client grants; tenant/membership provisioning remains a trusted server-side operation.

## Authenticated case API

`web/src/app/api/cases/route.ts` provides:
- `GET /api/cases?tenant_id=<uuid>` to list up to 100 recent cases for a tenant.
- `POST /api/cases` to create a case with title, optional status/severity, and bounded metadata.
- Supabase Auth session validation on each request.
- Requests to PostgREST use the caller's JWT plus a publishable key, never a service-role key; database RLS remains the authorization boundary.
- Request size/field validation, no-store responses, and generic upstream errors to avoid leaking database internals.

Configure these server environment variables in Vercel for the SATARK project:
- `SUPABASE_URL`: the existing Nirdhoom project URL.
- `SUPABASE_PUBLISHABLE_KEY`: the publishable key for that same project.

Do not set a service-role key for this route. The endpoint deliberately fails closed until configuration exists and requires a valid signed-in Supabase user with an existing SATARK tenant membership. No SATARK tenant or membership is auto-created; provisioning must be implemented as a trusted, audited server-side flow before users can create cases. The existing UI does not yet sign users in or consume this API, so do not represent the product as fully persistent until that UI integration and authorization tests are complete.

## Required before production use
1. Configure Supabase Auth and the two Vercel variables for the Nirdhoom project; redeploy and verify `/api/cases` responds 503 when unconfigured and 401 when no valid bearer session is provided.
2. Implement trusted tenant provisioning, membership changes, and invitation flows with role checks and audit events.
3. Wire the authenticated UI to this API; add sign-in/out, session refresh, tenant selection, loading/error/empty states, and case CRUD flows.
4. Compute audit event hashes server-side over a canonical representation including the previous event hash, and validate the chain during export. The migration stores hashes but does not calculate or verify them.
5. Add integration tests with authenticated users for cross-tenant read/write denial, role restrictions, invalid/expired tokens, and append-only behavior.
6. Review schema, RLS policies, backups, deletion/retention, data residency, shared project quotas, and legal/privacy obligations.
7. Run Supabase security advisors and verify Nirdhoom's existing flows after migration.

## Shared analysis rate limiting

The Next.js analysis endpoint supports a shared Upstash Redis REST limiter when both `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` are configured server-side in Vercel. It uses an atomic Redis increment with a 60-second expiry and an 8-request window per hashed client key. If the shared backend is configured but unavailable or misconfigured, the endpoint returns HTTP 503 rather than silently falling back to per-instance limits. If neither value is configured, the endpoint retains a best-effort in-process fallback.

Before enabling broad public traffic, provision an approved Upstash database, add both secrets to the appropriate Vercel environments, run the shared-limiter tests, and verify the production endpoint returns 429 after the limit and 503 during a controlled backend failure. Do not commit secrets or use a client-exposed `NEXT_PUBLIC_` prefix.

## Not enabled by this migration
- FIRSTLIGHT evidence and its audit trail are still browser-only.
- No live response endpoint is added. Defender isolation and Entra session revocation must remain disabled until authenticated operator authorization, target-bound confirmation, idempotency, server-side audit, and authorized test-tenant validation are complete.
- No shared rate limiter is provisioned. Configure and verify a distributed limiter or platform WAF separately.
