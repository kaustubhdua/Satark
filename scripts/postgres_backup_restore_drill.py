#!/usr/bin/env python3
"""Perform a real pg_dump/pg_restore round trip against an isolated temporary database."""
from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

from scripts.satark_backup import _pg_auth_env


def run(command: list[str], env: dict[str, str]) -> None:
    subprocess.run(command, check=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


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
    admin_url = source.set(database="postgres").render_as_string(hide_password=False)
    source_url = source.set(drivername="postgresql").render_as_string(hide_password=False)
    restore_url = source.set(drivername="postgresql", database=restore_db).render_as_string(hide_password=False)
    backup = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"{restore_db}.dump"
    table = "satark_restore_drill"
    marker = uuid.uuid4().hex

    try:
        with psycopg.connect(source_url) as connection:
            connection.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (marker text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now())").format(sql.Identifier(table)))
            connection.execute(sql.SQL("INSERT INTO {} (marker) VALUES (%s) ON CONFLICT DO NOTHING").format(sql.Identifier(table)), (marker,))
        with _pg_auth_env(source) as auth_env:
            run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", str(backup), source_url], auth_env)
        if not backup.is_file() or backup.stat().st_size == 0:
            raise RuntimeError("pg_dump did not produce a non-empty backup.")
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restore_db)))
        with _pg_auth_env(source.set(database=restore_db)) as auth_env:
            run(["pg_restore", "--no-owner", "--no-privileges", "--exit-on-error", "--dbname", restore_url, str(backup)], auth_env)
        with psycopg.connect(restore_url) as restored:
            row = restored.execute(sql.SQL("SELECT marker FROM {} WHERE marker = %s").format(sql.Identifier(table)), (marker,)).fetchone()
            if not row or row[0] != marker:
                raise RuntimeError("Restored database did not contain the committed marker row.")
        print(f"PostgreSQL backup/restore drill passed: source={source_db}, isolated_target={restore_db}, bytes={backup.stat().st_size}")
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(restore_db)))
        backup.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
