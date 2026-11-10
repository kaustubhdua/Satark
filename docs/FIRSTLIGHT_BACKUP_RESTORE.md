# FIRSTLIGHT backup and restore runbook (self-hosted)

This runbook covers the self-hosted SATARK/FIRSTLIGHT persistence planes. It is a procedure, not evidence that a restore drill has passed.

## Persistence planes

1. **SATARK database:** users, sessions, workspaces, memberships, cases, notes, evidence metadata, findings, reports, audit events, approvals, Wazuh checkpoints and durable investigation jobs. Configured with `SATARK_DATABASE_URL` (PostgreSQL recommended for production; SQLite for local development).
2. **Evidence objects:** private original uploads and Wazuh source snapshots under `SATARK_EVIDENCE_DIR`.
3. **Live-response ledger:** append-only response approvals and action audit chain in `FIRSTLIGHT_RESPONSE_DB`.
4. **Optional model assets:** local Ollama model store, if the operator uses model-assisted advisory analysis. This is not required for deterministic operation.

A database backup alone is not a complete evidence backup.

## Backup requirements

- Use a private operator host and a dedicated backup identity.
- Encrypt backups at rest and in transit; restrict filesystem permissions.
- Use immutable, timestamped backup directories; never overwrite an earlier backup set.
- Record UTC start/end times, commit SHA, database type/version, schema revision, evidence object count/bytes, and manifest digest.
- Keep at least one encrypted copy outside the source host and storage failure domain.
- Exclude secrets, signing keys, session cookies and credentials from backups/manifests unless a separately approved secrets backup policy exists.

## PostgreSQL backup

Use the exact connection parameters configured for `SATARK_DATABASE_URL`. A typical private-host dump is:

```bash
umask 077
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$HOME/firstlight-backups/$STAMP"
pg_dump --format=custom --no-owner --no-privileges \
  --file="$HOME/firstlight-backups/$STAMP/satark.dump"
sha256sum "$HOME/firstlight-backups/$STAMP/satark.dump" \
  > "$HOME/firstlight-backups/$STAMP/satark.dump.sha256"
```

For SQLite, stop writers or use SQLite's online backup API/CLI to create a consistent copy. If using WAL mode, include a consistent checkpoint/backup; copying only the main database file while active can omit committed WAL data.

## Evidence object backup

Enumerate every file under `SATARK_EVIDENCE_DIR`. For each object record its relative path, byte length and SHA-256 in a manifest. Preserve directory structure and permissions. Fail the backup if any object cannot be read or hashed. Encrypt the archive before transferring it off-host.

## Response ledger backup

Back up `FIRSTLIGHT_RESPONSE_DB` consistently. It contains response approval state, provider references and the append-only audit chain. Preserve its integrity and do not reset it during a restore. Verify the response audit chain after restore.

## Restore drill (isolated target only)

1. Provision an isolated host with compatible Python, database and filesystem permissions.
2. Restore the PostgreSQL dump or SQLite database into the isolated target.
3. Restore evidence files to the exact `SATARK_EVIDENCE_DIR` layout and verify every manifest hash.
4. Restore the response ledger and verify its audit chain.
5. Apply/verify the repository schema revision using the project's documented migration process.
6. Run authenticated workspace, case, evidence, finding, report, job and approval readback checks with least-privilege identities.
7. Confirm cross-workspace reads/writes are denied.
8. Verify queued/expired jobs recover safely and response actions left in `executing` are marked `unknown`, never retried.
9. Record RPO/RTO, object counts, digests, failures and operator sign-off.

Never restore into a live production host as a test. Do not declare recovery complete until database, evidence objects and response ledger have all been restored and verified.
