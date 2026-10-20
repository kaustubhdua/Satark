# FIRSTLIGHT backup and restore runbook

This is an operational procedure, not a claim that a restore drill has passed. Run it only from an approved private operator host. Never write backups into the same failure domain as the source system, and never restore into the shared production project as a test.

## Scope

FIRSTLIGHT uses two independent persistence planes:

1. Supabase Postgres: cases, memberships, evidence metadata, findings, reports, job state, approvals and audit-chain records.
2. Supabase Storage: raw Wazuh source snapshots and any exported evidence objects in the private `satark-evidence` bucket.

A database backup alone is **not** a complete evidence backup.

## Required controls

- Use a dedicated backup identity with only the permissions required for export; do not expose the service-role key to browser code or commit it.
- Encrypt backup files at rest and in transit; restrict the backup directory to the operator account.
- Record UTC start/end times, project ID, migration versions, object count, byte count and manifest digest.
- Keep at least one copy outside the source project's account/region and apply the documented retention policy.
- Never overwrite an existing backup set. Each run gets a new, immutable directory.
- Do not include secrets in manifests or logs. Restrict access to exported personal/security telemetry.

## Database export

Use the Supabase-supported database backup/PITR export for the project plan, or a database connection with an appropriately scoped role. A typical private-host export is:

```bash
umask 077
export PGHOST='your-database-host'
export PGPORT='5432'
export PGDATABASE='postgres'
export PGUSER='your-backup-role'
read -rsp 'Database password: ' PGPASSWORD; export PGPASSWORD; echo
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$HOME/firstlight-backups/$STAMP"
pg_dump --format=custom --no-owner --no-privileges \
  --file="$HOME/firstlight-backups/$STAMP/postgres.dump"
unset PGPASSWORD
sha256sum "$HOME/firstlight-backups/$STAMP/postgres.dump" \
  > "$HOME/firstlight-backups/$STAMP/database.sha256"
```

Use the connection parameters from the trusted Supabase dashboard; do not guess the host. For production recovery, use the supported backup/PITR capability available on the project's plan and record its recovery point. A logical dump is not a substitute for point-in-time recovery when the recovery objective requires it.

## Storage object export

Enumerate objects in `satark-evidence` using the authenticated Supabase Storage API from a private host. Page through the listing; never assume the first page is complete. For every object, download the exact bytes and record:

- bucket and exact object path;
- byte length and SHA-256 of the downloaded bytes;
- download timestamp in UTC;
- response/verification status;
- manifest format version.

Verify each downloaded object's SHA-256 against the digest encoded in its tenant/case-scoped path when the object is a Wazuh snapshot. Fail the backup if any object cannot be listed or downloaded; do not silently omit failures. Store the manifest beside the encrypted object archive and hash the manifest itself. Never place the service-role key in command-line arguments or logs.

## Restore drill (isolated target only)

1. Provision an isolated Supabase project/database with the same supported PostgreSQL major version and compatible extensions.
2. Apply the repository migrations in order and compare the resulting migration history with the backup's recorded history.
3. Restore the database dump into the isolated target. Keep production traffic and external integrations disconnected.
4. Recreate the private `satark-evidence` bucket with its intended private visibility and object-size limit before importing objects.
5. Restore object bytes without changing paths. Verify every restored byte count and SHA-256 against the manifest.
6. Verify database RLS and FORCE RLS, grants, storage policies, approval constraints, audit-chain verification and the service-role-only worker checkpoint/job tables.
7. Run case/evidence/finding/report/job/approval readback checks with least-privilege test identities; verify cross-tenant and viewer-role access is denied.
8. Recompute the audit chain using the project's verification RPC. A valid hash chain proves internal consistency, not independent source authenticity.
9. Record measured RPO/RTO, any missing objects, every failure and the operator sign-off. Delete the isolated target only after preserving the drill record.

## Release gate

Do not mark backup/recovery complete until the isolated database **and** Storage objects have both been restored and verified. No production restore drill has been run as part of the current FIRSTLIGHT work; a dedicated isolated target and least-privilege identities are required.
