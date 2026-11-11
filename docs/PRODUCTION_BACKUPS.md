# SATARK encrypted off-site backups

The production backup service uses the open-source [Restic](https://restic.net/) repository format. It creates a consistent SATARK archive (PostgreSQL dump, private evidence objects and FIRSTLIGHT response ledger), verifies its internal SHA-256 manifest, uploads it to a separate Restic repository, runs a repository integrity check, applies retention, and confirms that a SATARK snapshot is visible.

## Configure an independent destination

Use a bucket/account that is not on the SATARK application host. For an S3-compatible provider, add these values to the private root `.env` file:

```dotenv
RESTIC_REPOSITORY=s3:https://s3.example.net/your-private-bucket/satark
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=...
```

Create `secrets/restic-password` with a long, unique Restic repository password and protect it:

```sh
mkdir -p secrets
umask 077
openssl rand -base64 48 > secrets/restic-password
sudo chown root:10001 secrets/restic-password
chmod 0440 secrets/restic-password
```

The backup container runs as UID/GID 10001, so the mounted password file must be readable by that group and must not be world-readable. Keep the `secrets` directory itself restricted to administrators.

The password is not recoverable from the repository. Store a separate copy in an approved password manager or offline recovery vault. Do not commit it.

Initialize the remote repository once, after reviewing the exact repository URL and credentials:

```sh
docker compose -f docker-compose.production.yml --profile backup run --rm --entrypoint restic satark-backup init
```

Start the scheduler:

```sh
docker compose -f docker-compose.production.yml --profile backup up -d satark-backup
docker compose -f docker-compose.production.yml logs -f satark-backup
```

The scheduler runs immediately and then every `SATARK_BACKUP_INTERVAL_SECONDS` (default 86400). It keeps 7 daily, 4 weekly and 12 monthly snapshots by default. The integrity check reads a configurable subset (default 5%) of repository data each run.

## Restore drill

Do not restore over the live database or evidence volume. On an isolated recovery host, configure the same Restic repository and password file, then:

1. List and choose a known-good snapshot: `restic snapshots --tag satark`.
2. Restore the snapshot to a temporary directory: `restic restore <snapshot-id> --target /recovery/restore`.
3. Run `python scripts/satark_backup.py verify /recovery/restore/backups/satark-....tar.gz`.
4. Restore into an empty isolated PostgreSQL database and evidence directory using `python scripts/satark_backup.py restore <archive> --database-url <isolated-target-url> --evidence-dir /recovery/evidence --response-ledger /recovery/firstlight-response.sqlite3`.
5. Verify evidence hashes, FIRSTLIGHT response ledger integrity, login/MFA recovery, case access and application readiness before considering failover.

The repository destination, access keys, password vault and recovery host must be independent of the production host. CI's local PostgreSQL round-trip test is not a substitute for a real off-host recovery exercise. The backup service fails closed if Restic is not configured or the remote repository is unavailable.
