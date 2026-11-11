from __future__ import annotations

import io
import sqlite3
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from sqlalchemy.engine import make_url

from scripts.satark_backup import _pg_auth_env, _pg_env, create_backup, restore_backup, verify_backup


class SatarkBackupTests(unittest.TestCase):
    def test_sqlite_database_and_private_evidence_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "source.db"
            evidence = root / "source-evidence"
            evidence.mkdir()
            (evidence / "case-1.json").write_text('{"event":"login"}', encoding="utf-8")
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY, title TEXT)")
                connection.execute("INSERT INTO incidents(title) VALUES (?)", ("Synthetic incident",))
                connection.execute("CREATE TABLE satark_evidence (id TEXT PRIMARY KEY, object_key TEXT)")
                connection.execute(
                    "INSERT INTO satark_evidence(id, object_key) VALUES (?, ?)",
                    ("evidence-1", str(evidence / "case-1.json")),
                )

            archive = root / "satark-backup.tar.gz"
            manifest = create_backup(archive, f"sqlite:///{database}", evidence)
            self.assertEqual(manifest["database_engine"], "sqlite")
            self.assertEqual(verify_backup(archive)["format"], "satark-backup-v1")

            restored_database = root / "restored.db"
            restored_evidence = root / "restored-evidence"
            restored_manifest = restore_backup(archive, f"sqlite:///{restored_database}", restored_evidence)
            self.assertEqual(restored_manifest["evidence_objects_rebased"], 1)
            with sqlite3.connect(restored_database) as connection:
                row = connection.execute("SELECT title FROM incidents WHERE id = 1").fetchone()
            self.assertEqual(row[0], "Synthetic incident")
            with sqlite3.connect(restored_database) as connection:
                restored_object_key = connection.execute(
                    "SELECT object_key FROM satark_evidence WHERE id = 'evidence-1'"
                ).fetchone()[0]
            self.assertEqual(restored_object_key, str(restored_evidence / "case-1.json"))
            self.assertTrue(Path(restored_object_key).is_file())
            self.assertEqual(
                (restored_evidence / "case-1.json").read_text(encoding="utf-8"),
                '{"event":"login"}',
            )
            import stat
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(restored_database.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(restored_evidence.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((restored_evidence / "case-1.json").stat().st_mode), 0o600)


    def test_firstlight_response_ledger_is_included_and_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "source.db"
            evidence = root / "source-evidence"
            evidence.mkdir()
            ledger = root / "response-ledger.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY, title TEXT)")
                connection.execute("INSERT INTO incidents(title) VALUES ('lab incident')")
            with sqlite3.connect(ledger) as connection:
                connection.execute("CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY, event_type TEXT)")
                connection.execute("INSERT INTO audit_events(event_type) VALUES ('approval.requested')")

            archive = root / "complete-backup.tar.gz"
            with mock.patch.dict("os.environ", {"FIRSTLIGHT_RESPONSE_DB": str(ledger)}):
                manifest = create_backup(archive, f"sqlite:///{database}", evidence)
            self.assertIn("firstlight-response.sqlite3", manifest["files"])

            restored_database = root / "restored.db"
            restored_evidence = root / "restored-evidence"
            restored_ledger = root / "restored-response-ledger.sqlite3"
            restore_backup(archive, f"sqlite:///{restored_database}", restored_evidence, restored_ledger)
            with sqlite3.connect(restored_ledger) as connection:
                row = connection.execute("SELECT event_type FROM audit_events WHERE sequence=1").fetchone()
            self.assertEqual(row[0], "approval.requested")

    def test_backup_checksum_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "source.db"
            evidence = root / "evidence"
            evidence.mkdir()
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE test (value TEXT)")
                connection.execute("INSERT INTO test(value) VALUES ('ok')")
            archive = root / "good.tar.gz"
            create_backup(archive, f"sqlite:///{database}", evidence)

            corrupted = root / "corrupted.tar.gz"
            with tarfile.open(archive, "r:gz") as source, tarfile.open(corrupted, "w:gz") as target:
                for member in source.getmembers():
                    raw = source.extractfile(member).read()
                    if member.name == "evidence.tar.gz":
                        raw += b"tampered"
                    info = tarfile.TarInfo(member.name)
                    info.size = len(raw)
                    target.addfile(info, io.BytesIO(raw))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_backup(corrupted)

    def test_postgres_backup_url_does_not_expose_password_to_process_arguments(self):
        url = make_url("postgresql+psycopg://satark:private-secret@db.internal:5432/satark?sslmode=require")
        safe_url, env = _pg_env(url)
        self.assertTrue(safe_url.startswith("postgresql://"))
        self.assertNotIn("private-secret", safe_url)
        self.assertEqual(env["PGPASSWORD"], "private-secret")



    def test_postgres_auth_uses_private_temporary_passfile_and_cleans_it(self):
        import stat

        url = make_url("postgresql+psycopg://satark:p%40ss%3Aword@db.internal:5432/satark")
        with _pg_auth_env(url) as env:
            self.assertNotIn("PGPASSWORD", env)
            passfile = Path(env["PGPASSFILE"])
            self.assertTrue(passfile.is_file())
            self.assertEqual(stat.S_IMODE(passfile.stat().st_mode), 0o600)
            self.assertEqual(
                passfile.read_text(encoding="utf-8"),
                r"db.internal:5432:satark:satark:p@ss\:word" + "\n",
            )
        self.assertFalse(passfile.exists())

    def test_restore_refuses_symlink_targets_and_source_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "source.db"
            evidence = root / "source-evidence"
            evidence.mkdir()
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE test (value TEXT)")
            archive = root / "backup.tar.gz"
            create_backup(archive, f"sqlite:///{database}", evidence)

            real_target = root / "real-evidence"
            real_target.mkdir()
            evidence_link = root / "evidence-link"
            evidence_link.symlink_to(real_target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                restore_backup(archive, f"sqlite:///{root / 'target.db'}", evidence_link)

            database_link = root / "database-link.db"
            database_link.symlink_to(database)
            with self.assertRaisesRegex(FileNotFoundError, "unsafe"):
                create_backup(root / "linked-source-backup.tar.gz", f"sqlite:///{database_link}", evidence)

            evidence_source_link = root / "evidence-source-link"
            evidence_source_link.symlink_to(evidence, target_is_directory=True)
            with sqlite3.connect(root / "another.db") as connection:
                connection.execute("CREATE TABLE test (value TEXT)")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                create_backup(root / "linked-evidence-backup.tar.gz", f"sqlite:///{root / 'another.db'}", evidence_source_link)

    def test_restore_refuses_nonempty_evidence_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "source.db"
            evidence = root / "source-evidence"
            evidence.mkdir()
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE test (value TEXT)")
            archive = root / "backup.tar.gz"
            create_backup(archive, f"sqlite:///{database}", evidence)
            target_database = root / "target.db"
            target_evidence = root / "target-evidence"
            target_evidence.mkdir()
            (target_evidence / "keep.txt").write_text("do not overwrite", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "must be empty"):
                restore_backup(archive, f"sqlite:///{target_database}", target_evidence)
            self.assertFalse(target_database.exists())


if __name__ == "__main__":
    unittest.main()
