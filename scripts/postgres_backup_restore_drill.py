#!/usr/bin/env python3
"""Exercise a complete isolated PostgreSQL + evidence + response-ledger restore."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import uuid
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

from scripts.satark_backup import create_backup, restore_backup, verify_backup


def connect(url, *, autocommit: bool = False):
    return psycopg.connect(
        host=url.host,
        port=url.port,
        dbname=url.database,
        user=url.username,
        password=url.password,
        autocommit=autocommit,
    )


def create_database(admin_url, name: str) -> None:
    with connect(admin_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))


def drop_database(admin_url, name: str) -> None:
    with connect(admin_url, autocommit=True) as admin:
        admin.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
        )


def main() -> int:
    raw_url = os.environ.get("SATARK_TEST_POSTGRES_URL", "").strip()
    if not raw_url:
        raise SystemExit("SATARK_TEST_POSTGRES_URL is required for the PostgreSQL restore drill.")
    base = make_url(raw_url)
    if base.get_backend_name() != "postgresql" or not base.database:
        raise SystemExit("Restore drill requires a PostgreSQL URL with a database name.")

    suffix = uuid.uuid4().hex[:12]
    source_name = f"satark_backup_source_{suffix}"
    restore_name = f"satark_backup_restore_{suffix}"
    admin_url = base.set(database="postgres")
    source_url = base.set(database=source_name)
    restore_url = base.set(database=restore_name)
    work_root = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    work_root.mkdir(parents=True, exist_ok=True)

    evidence_source = work_root / f"{source_name}-evidence"
    evidence_restore = work_root / f"{restore_name}-evidence"
    ledger_source = work_root / f"{source_name}-response.sqlite3"
    ledger_restore = work_root / f"{restore_name}-response.sqlite3"
    archive = work_root / f"{source_name}-complete-backup.tar.gz"
    tenant_id = "tenant-restore-drill"
    case_id = "case-restore-drill"
    object_relative = Path(tenant_id) / case_id / "source-alert.json"
    marker = uuid.uuid4().hex
    object_payload = ('{"source":"wazuh-lab-drill","marker":"' + marker + '"}\\n').encode()
    expected_object_hash = hashlib.sha256(object_payload).hexdigest()

    try:
        create_database(admin_url, source_name)
        create_database(admin_url, restore_name)
        object_path = evidence_source / object_relative
        object_path.parent.mkdir(parents=True, exist_ok=True)
        object_path.write_bytes(object_payload)

        with connect(source_url) as source:
            source.execute(sql.SQL(
                "CREATE TABLE satark_restore_drill (marker text PRIMARY KEY)"
            ))
            source.execute(
                "INSERT INTO satark_restore_drill(marker) VALUES (%s)", (marker,)
            )
            source.execute(sql.SQL(
                "CREATE TABLE satark_evidence (id text PRIMARY KEY, tenant_id text NOT NULL, "
                "case_id text NOT NULL, object_key text NOT NULL)"
            ))
            source.execute(
                "INSERT INTO satark_evidence(id, tenant_id, case_id, object_key) "
                "VALUES (%s, %s, %s, %s)",
                ("evidence-restore-drill", tenant_id, case_id, str(object_path)),
            )

        with sqlite3.connect(ledger_source) as ledger:
            ledger.execute(
                "CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY, event_type TEXT NOT NULL)"
            )
            ledger.execute(
                "INSERT INTO audit_events(sequence, event_type) VALUES (1, 'restore.drill.marker')"
            )
            ledger.commit()

        manifest = create_backup(
            archive,
            source_url.render_as_string(hide_password=False),
            evidence_source,
            response_ledger_path=ledger_source,
        )
        verified = verify_backup(archive)
        if verified["files"] != manifest["files"]:
            raise RuntimeError("Backup manifest changed between creation and verification.")
        if "firstlight-response.sqlite3" not in verified["files"]:
            raise RuntimeError("Backup archive omitted the FIRSTLIGHT response ledger.")

        restored_manifest = restore_backup(
            archive,
            restore_url.render_as_string(hide_password=False),
            evidence_restore,
            ledger_restore,
        )
        if restored_manifest.get("evidence_objects_rebased") != 1:
            raise RuntimeError("Restore did not rebase the evidence object reference.")

        with connect(restore_url) as restored:
            restored_marker = restored.execute(
                "SELECT marker FROM satark_restore_drill"
            ).fetchone()
            if not restored_marker or restored_marker[0] != marker:
                raise RuntimeError("Restored PostgreSQL database is missing its committed marker.")
            restored_object_key = restored.execute(
                "SELECT object_key FROM satark_evidence WHERE id = %s",
                ("evidence-restore-drill",),
            ).fetchone()
        if not restored_object_key:
            raise RuntimeError("Restored PostgreSQL database is missing evidence metadata.")
        restored_object = Path(restored_object_key[0])
        if restored_object != evidence_restore / object_relative or not restored_object.is_file():
            raise RuntimeError("Restored evidence object path was not safely rebased.")
        if hashlib.sha256(restored_object.read_bytes()).hexdigest() != expected_object_hash:
            raise RuntimeError("Restored evidence object SHA-256 does not match the source.")

        with sqlite3.connect(ledger_restore) as ledger:
            integrity = ledger.execute("PRAGMA integrity_check").fetchone()
            event = ledger.execute(
                "SELECT event_type FROM audit_events WHERE sequence = 1"
            ).fetchone()
        if not integrity or integrity[0] != "ok" or not event or event[0] != "restore.drill.marker":
            raise RuntimeError("Restored FIRSTLIGHT response ledger failed integrity/readback.")

        print(
            "Complete isolated restore passed: "
            f"postgresql={restore_name}, evidence_objects=1, "
            f"evidence_sha256={expected_object_hash}, response_ledger=integrity_ok, "
            f"archive_bytes={archive.stat().st_size}"
        )
    finally:
        drop_database(admin_url, restore_name)
        drop_database(admin_url, source_name)
        archive.unlink(missing_ok=True)
        ledger_source.unlink(missing_ok=True)
        ledger_restore.unlink(missing_ok=True)
        import shutil
        shutil.rmtree(evidence_source, ignore_errors=True)
        shutil.rmtree(evidence_restore, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
