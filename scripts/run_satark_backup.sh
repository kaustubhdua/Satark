#!/bin/sh
set -eu
umask 077

: "${SATARK_BACKUP_DATABASE_URL:?Set the dedicated PostgreSQL backup URL}"
: "${SATARK_EVIDENCE_DIR:=/data/evidence}"
: "${RESTIC_REPOSITORY:?Set an independent off-host Restic repository}"
: "${RESTIC_PASSWORD_FILE:=/run/secrets/restic-password}"
: "${RESTIC_CACHE_DIR:=/tmp/restic-cache}"
: "${SATARK_BACKUP_HOST:=satark-production}"
: "${RESTIC_CHECK_SUBSET:=5%}"

if [ ! -r "$RESTIC_PASSWORD_FILE" ]; then
  echo "Restic password file is missing or unreadable: $RESTIC_PASSWORD_FILE" >&2
  exit 2
fi
if ! command -v restic >/dev/null 2>&1 || ! command -v pg_dump >/dev/null 2>&1; then
  echo "The backup image must include restic and PostgreSQL client tools." >&2
  exit 2
fi

BACKUP_DIR="${SATARK_BACKUP_DIR:-/backups}"
mkdir -p "$BACKUP_DIR" "$RESTIC_CACHE_DIR"
ARCHIVE="$BACKUP_DIR/satark-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"

# The archive is created with the separate BYPASSRLS backup identity and
# includes PostgreSQL, evidence objects and the FIRSTLIGHT response ledger.
python /app/scripts/satark_backup.py create --output "$ARCHIVE"
python /app/scripts/satark_backup.py verify "$ARCHIVE"

# Restic encrypts and uploads the archive to the independently configured
# repository. A local archive is never reported as a successful offsite backup.
restic backup --tag satark --host "$SATARK_BACKUP_HOST" "$ARCHIVE"
restic check --read-data-subset="$RESTIC_CHECK_SUBSET"
restic forget --tag satark \
  --keep-daily "${RESTIC_KEEP_DAILY:-7}" \
  --keep-weekly "${RESTIC_KEEP_WEEKLY:-4}" \
  --keep-monthly "${RESTIC_KEEP_MONTHLY:-12}" \
  --prune
restic snapshots --json --tag satark | python -c 'import json,sys; rows=json.load(sys.stdin); assert rows, "No SATARK Restic snapshots are visible after backup"'

# Retain a short local recovery window only after remote upload and verification.
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'satark-*.tar.gz' -mtime +7 -delete
echo "SATARK encrypted offsite backup and repository verification succeeded: $ARCHIVE"
