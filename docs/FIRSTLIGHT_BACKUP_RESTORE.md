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

## Automated encrypted off-host backup

The production Compose profile uses a dedicated `satark-backup` image. It contains the PostgreSQL 16 client matching the production PostgreSQL 16 server, the archive utility, and the open-source Restic client. The API runtime never receives the privileged backup database URL or Restic credentials.

1. Configure `SATARK_BACKUP_DATABASE_URL` with the dedicated `satark_backup` identity.
2. Configure an independent remote `RESTIC_REPOSITORY` (for example, a private S3-compatible bucket) and provider credentials in the root `.env`.
3. Create `secrets/restic-password` with a unique repository password, readable only by the backup container's UID/GID 10001. Store a separate recovery copy in an approved password manager or offline vault.
4. Initialize the remote repository once:

   ```bash
   docker compose -f docker-compose.production.yml --profile backup run --rm --entrypoint restic satark-backup init
   ```

5. Start and inspect the scheduler:

   ```bash
   docker compose -f docker-compose.production.yml --profile backup up -d satark-backup
   docker compose -f docker-compose.production.yml logs -f satark-backup
   restic snapshots --tag satark
   ```

The scheduler runs immediately and then at `SATARK_BACKUP_INTERVAL_SECONDS` (default 86400 seconds). Each run creates the SQL/evidence/response-ledger archive, verifies its SHA-256 manifest, uploads it to Restic, checks a configured subset of repository data, applies daily/weekly/monthly retention, and confirms a tagged snapshot is visible. It fails closed if the remote repository or password is unavailable. See [PRODUCTION_BACKUPS.md](PRODUCTION_BACKUPS.md) for the full operator procedure.

The archive contains a database snapshot, evidence objects and the FIRSTLIGHT response-ledger snapshot when configured. Evidence objects are treated as immutable; still schedule a controlled recovery window and verify the recovered database, evidence and response ledger together. The scheduler does not itself prove a successful restore. Keep live response disabled until a separate restore and Wazuh lab acceptance is signed off.

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
