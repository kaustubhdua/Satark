# Self-hosted production deployment

SATARK/FIRSTLIGHT production is a self-hosted Docker deployment, not a Vercel-only application. The Android File Guard remains fully offline. The server stack uses PostgreSQL, private evidence storage, a durable response ledger, Next.js, FastAPI, persistent workers and Caddy-managed HTTPS.

## Hosting and cost boundary

The repository contains a production Compose stack, but it does not create a cloud account or a free virtual machine. A public service needs a reachable Linux host, domain/DNS, persistent disk and a backup destination. A free application tier is not sufficient evidence of durable storage or production uptime. The operator must provision a host they control and confirm its cost/quotas before deployment.

## Prerequisites

- Linux host with Docker Engine and Docker Compose plugin.
- A DNS A/AAAA record for the chosen domain pointing to the host.
- Inbound TCP 80/443 for ACME certificate issuance and HTTPS; do not expose PostgreSQL or the Wazuh Manager API publicly.
- Persistent disk with enough space for PostgreSQL, evidence objects, response ledger, logs and backups.
- SMTP account for verification and password recovery.
- Private Wazuh Manager/Indexer network route and least-privilege credentials if Wazuh is enabled.
- vm.max_map_count=262144 on the Wazuh host if deploying the Wazuh Indexer on the same machine.

## Configure

1. Clone the exact approved SATARK release commit onto the host.
2. Copy deploy/production.env.example to the root .env; replace every placeholder with unique values and run chmod 600 .env.
3. The first PostgreSQL initialization runs deploy/postgres-init/01-create-roles.sh. It creates separate satark_runtime and satark_backup roles; only the backup role has BYPASSRLS. URL-encode special characters in both database URLs. Configure SATARK_DATABASE_URL for satark_runtime and SATARK_BACKUP_DATABASE_URL for satark_backup; never use the PostgreSQL bootstrap administrator or runtime API credential for backups. Initialization scripts run only when the PostgreSQL data volume is empty, so rotate credentials through SQL after first initialization rather than expecting environment changes to alter existing roles.
4. Put Wazuh trust anchors under `./secrets/wazuh/` (for example, `wazuh-manager-ca.pem` and `wazuh-indexer-ca.pem`). The API and Wazuh worker mount only this directory; the Restic password is isolated under `./secrets/backup/` and is never mounted into application containers. Restrict both directories to root:10001 with mode 0750 and CA files to root:10001 with mode 0440. The Manager certificate SAN must match `FIRSTLIGHT_WAZUH_MANAGER_API_URL`.
5. Keep SATARK_ENABLE_LIVE_RESPONSE=false until the Wazuh lab response workflow and reversal have been independently tested. Configure only disposable agent IDs in FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS.

Generate independent secrets:

~~~bash
openssl rand -hex 32
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
~~~

## Deploy

~~~bash
docker compose -f docker-compose.production.yml config --quiet
docker compose -f docker-compose.production.yml build
docker compose -f docker-compose.production.yml up -d
docker compose -f docker-compose.production.yml ps
~~~

Caddy obtains and renews HTTPS certificates automatically after DNS and ports 80/443 are correctly configured. Verify the public origin, sign-up/email verification, MFA enrollment, session expiry, case access, evidence upload/verification, report export and health endpoints before inviting users.

Optional Wazuh polling worker:

~~~bash
docker compose -f docker-compose.production.yml --profile wazuh up -d firstlight-wazuh-worker
~~~

Do not enable that worker until the tenant, case, actor, Indexer role and agent allowlist have been checked.

## Backup and isolated restore

Configure the dedicated `satark_backup` database role, an independent Restic repository, and the protected `secrets/backup/restic-password` file before enabling the backup profile. Follow [PRODUCTION_BACKUPS.md](PRODUCTION_BACKUPS.md) to initialize the remote repository and start the scheduler:

```bash
docker compose -f docker-compose.production.yml --profile backup run --rm --entrypoint restic satark-backup init
docker compose -f docker-compose.production.yml --profile backup up -d satark-backup
docker compose -f docker-compose.production.yml logs -f satark-backup
```

The scheduler creates a database/evidence/response-ledger archive, verifies its SHA-256 manifest, uploads it to the independent Restic repository, checks repository data, and applies configured retention. Confirm successful snapshots and alert on a missing or failed scheduled run. A local archive or successful CI `pg_dump`/`pg_restore` test is not proof of off-host backup or recovery.

For a restore drill, provision a separate host and empty database/data volume, restore a selected Restic snapshot to a temporary directory, verify the archive, and restore with `scripts/satark_backup.py` into the isolated target. Verify every evidence hash, the response-ledger audit chain, tenant isolation and application readback. Record RPO/RTO and operator sign-off. Never test restore on the live production database.

## Release discipline

- Pin the exact Git commit and image build inputs; do not deploy a moving branch.
- Run all GitHub Actions checks on the exact SHA before deployment.
- Record the image digests, database migration revision and deployed commit SHA.
- Run post-deploy smoke tests for login/MFA, tenant isolation, file/evidence access, report export, Wazuh alert ingestion and audit verification.
- Confirm backups are encrypted and off-host, and perform a scheduled isolated restore drill.
- Keep live response disabled until a separate approved Wazuh lab acceptance report exists.

A successful docker compose up or a healthy homepage is not by itself proof of production readiness.
