# FIRSTLIGHT backup and restore runbook (self-hosted)

This runbook covers the self-hosted SATARK/FIRSTLIGHT persistence planes. It is a procedure, not evidence that a restore drill has passed.

## Persistence planes

1. **SATARK database:** users, sessions, workspaces, memberships, cases, notes, evidence metadata, findings, reports, audit events, approvals, Wazuh checkpoints and durable investigation jobs. Configured with `SATARK_DATABASE_URL` (PostgreSQL recommended for production; SQLite for local development).
2. **Evidence objects:** private original uploads and Wazuh source snapshots under `SATARK_EVIDENCE_DIR`.
3. **Live-response ledger:** append-only response approvals and action audit chain in `FIRSTLIGHT_RESPONSE_DB`.
4. **Optional model assets:** local Ollama model store, if the operator uses model-assisted advisory analysis. This is not required for deterministic operation.

A database backup alone is not a complete evidence backup. The current satark_backup.py archive includes the database, evidence object archive and optional FIRSTLIGHT response-ledger snapshot, with SHA-256 manifest verification.

## Backup requirements

- Use a private operator host and a dedicated backup identity.
- Encrypt backups at rest and in transit; restrict filesystem permissions.
- Use immutable, timestamped backup directories; never overwrite an earlier backup set.
- Record UTC start/end times, commit SHA, database type/version, schema revision, evidence object count/bytes, and manifest digest.
- Keep at least one encrypted copy outside the source host and storage failure domain.
- Exclude secrets, signing keys, session cookies and credentials from backups/manifests unless a separately approved secrets backup policy exists.

## Backup utility

The production Compose profile runs a one-shot backup container. Its privileged BYPASSRLS credential is isolated from the web/API process.

~~~bash
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
docker compose -f docker-compose.production.yml --profile backup run --rm satark-backup \
  create --output "/backups/satark-$STAMP.tar.gz"
docker compose -f docker-compose.production.yml --profile backup run --rm satark-backup \
  verify "/backups/satark-$STAMP.tar.gz"
~~~

The archive contains a consistent SQL database dump, evidence objects and the FIRSTLIGHT response ledger snapshot when that SQLite file exists. The response ledger is integrity-checked when snapshotted and restored. Quiesce API and worker writes before taking the full archive so all persistence planes represent the same point in time. Encrypt the archive and copy it outside the source host.

For PostgreSQL, the backup role is separate from the runtime role and has BYPASSRLS only for the backup/restore utility. Restored objects are reassigned to the configured runtime role. Do not grant BYPASSRLS to the API runtime identity.

## Restore drill (isolated target only)

1. Provision an isolated host with compatible Python, database and filesystem permissions.
2. Restore the verified archive into an isolated empty database/data volume with the backup utility; verify the SQL database, evidence objects and response ledger are all present.
3. Restore evidence files to the exact `SATARK_EVIDENCE_DIR` layout and verify every manifest hash.
4. Verify the restored response ledger's SQLite integrity and hash-chained audit sequence.
5. Apply/verify the repository schema revision using the project's documented migration process.
6. Run authenticated workspace, case, evidence, finding, report, job and approval readback checks with least-privilege identities.
7. Confirm cross-workspace reads/writes are denied.
8. Verify queued/expired jobs recover safely and response actions left in `executing` are marked `unknown`, never retried.
9. Record RPO/RTO, object counts, digests, failures and operator sign-off.

Never restore into a live production host as a test. Do not declare recovery complete until database, evidence objects and response ledger have all been restored and verified.
