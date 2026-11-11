#!/usr/bin/env python3
"""Perform a real pg_dump/pg_restore round trip against an isolated temporary database."""
from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.satark_backup import _pg_env


def run(command: list[str], env: dict[str, str]) -> None:
    subprocess.run(command, check=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def connect(url, *, autocommit: bool = False):
    return psycopg.connect(
        host=url.host,
        port=url.port,
        dbname=url.database,
        user=url.username,
        password=url.password,
        autocommit=autocommit,
    )


def main() -> int:
    raw_url = os.environ.get("SATARK_TEST_POSTGRES_URL", "").strip()
    if not raw_url:
        raise SystemExit("SATARK_TEST_POSTGRES_URL is required for the PostgreSQL restore drill.")
    source = make_url(raw_url)
    if source.get_backend_name() != "postgresql":
        raise SystemExit("Restore drill requires PostgreSQL.")
    source_db = source.database
    if not source_db:
        raise SystemExit("PostgreSQL URL must include a database name.")
    restore_db = f"satark_restore_{uuid.uuid4().hex[:12]}"
    admin_url = source.set(database="postgres")
    restore_url = source.set(database=restore_db)
    backup = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"{restore_db}.dump"
    table = "satark_restore_drill"
    marker = uuid.uuid4().hex

    try:
        with connect(source) as connection:
            connection.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (marker text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now())").format(sql.Identifier(table)))
            connection.execute(sql.SQL("INSERT INTO {} (marker) VALUES (%s) ON CONFLICT DO NOTHING").format(sql.Identifier(table)), (marker,))
        dump_command = ["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", str(backup)]
        if source.host:
            dump_command.extend(["--host", source.host])
        if source.port:
            dump_command.extend(["--port", str(source.port)])
        if source.username:
            dump_command.extend(["--username", source.username])
        dump_command.extend(["--dbname", source_db])
        _, auth_env = _pg_env(source)
        run(dump_command, auth_env)
        if not backup.is_file() or backup.stat().st_size == 0:
            raise RuntimeError("pg_dump did not produce a non-empty backup.")
        with connect(admin_url, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restore_db)))
        restore_command = ["pg_restore", "--no-owner", "--no-privileges", "--exit-on-error"]
        if source.host:
            restore_command.extend(["--host", source.host])
        if source.port:
            restore_command.extend(["--port", str(source.port)])
        if source.username:
            restore_command.extend(["--username", source.username])
        restore_command.extend(["--dbname", restore_db, str(backup)])
        _, auth_env = _pg_env(source.set(database=restore_db))
        run(restore_command, auth_env)
        with connect(restore_url) as restored:
            row = restored.execute(sql.SQL("SELECT marker FROM {} WHERE marker = %s").format(sql.Identifier(table)), (marker,)).fetchone()
            if not row or row[0] != marker:
                raise RuntimeError("Restored database did not contain the committed marker row.")
        print(f"PostgreSQL backup/restore drill passed: source={source_db}, isolated_target={restore_db}, bytes={backup.stat().st_size}")
    finally:
        with connect(admin_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(restore_db)))
        backup.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
