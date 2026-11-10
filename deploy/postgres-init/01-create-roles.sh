#!/bin/sh
set -eu

: "${SATARK_RUNTIME_DB_PASSWORD:?SATARK_RUNTIME_DB_PASSWORD is required}"
: "${SATARK_BACKUP_DB_PASSWORD:?SATARK_BACKUP_DB_PASSWORD is required}"

psql --set ON_ERROR_STOP=1 \
  --set runtime_password="$SATARK_RUNTIME_DB_PASSWORD" \
  --set backup_password="$SATARK_BACKUP_DB_PASSWORD" <<'SQL'
CREATE ROLE satark_runtime LOGIN PASSWORD :'runtime_password';
CREATE ROLE satark_backup LOGIN BYPASSRLS PASSWORD :'backup_password';

GRANT CONNECT ON DATABASE satark TO satark_runtime;
GRANT USAGE, CREATE ON SCHEMA public TO satark_runtime;

GRANT CONNECT, CREATE, TEMPORARY ON DATABASE satark TO satark_backup;
GRANT USAGE, CREATE ON SCHEMA public TO satark_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO satark_backup;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO satark_backup;

ALTER DEFAULT PRIVILEGES FOR ROLE satark_runtime IN SCHEMA public
  GRANT SELECT ON TABLES TO satark_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE satark_runtime IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO satark_backup;
SQL
