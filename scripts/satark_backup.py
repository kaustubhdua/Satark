"""Create, verify, and restore a SATARK database + private-evidence backup.

Quiesce API/worker writes before creating a backup so the database snapshot and
filesystem evidence archive represent the same point in time. Encrypt the
resulting archive with an approved offline/managed key before moving it off-host.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy.engine import make_url


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pg_env(url) -> tuple[str, dict[str, str]]:
    env = os.environ.copy()
    if url.password:
        env["PGPASSWORD"] = url.password
    if url.username:
        env["PGUSER"] = url.username
    if url.host:
        env["PGHOST"] = url.host
    if url.port:
        env["PGPORT"] = str(url.port)
    if url.database:
        env["PGDATABASE"] = url.database
    safe_url = str(url.set(password=None, username=url.username))
    return safe_url, env


def _sqlite_path(url) -> Path:
    if not url.database or url.database == ":memory:":
        raise ValueError("A file-backed SQLite database is required for backups.")
    path = Path(url.database).expanduser().resolve()
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("The configured SQLite database file does not exist or is unsafe.")
    return path


def _copy_database(database_url: str, destination: Path) -> str:
    url = make_url(database_url)
    if url.drivername.startswith("sqlite"):
        source = _sqlite_path(url)
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as src:
            with sqlite3.connect(destination) as dst:
                src.backup(dst)
        return "sqlite"
    if url.drivername.startswith("postgresql"):
        if not shutil.which("pg_dump"):
            raise RuntimeError("pg_dump is required to back up PostgreSQL.")
        safe_url, env = _pg_env(url)
        subprocess.run(
            ["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", str(destination), safe_url],
            env=env, check=True, timeout=3600,
        )
        return "postgresql"
    raise ValueError("Only SQLite and PostgreSQL SATARK databases are supported.")


def _archive_evidence(evidence_dir: Path, destination: Path) -> None:
    root = evidence_dir.expanduser().resolve()
    if not root.exists():
        root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Evidence directory must be a real directory.")
    with tarfile.open(destination, "w:gz") as archive:
        for item in sorted(root.rglob("*")):
            if item.is_symlink():
                raise ValueError(f"Evidence backup refuses symbolic links: {item.relative_to(root)}")
            if item.is_file():
                archive.add(item, arcname=item.relative_to(root).as_posix(), recursive=False)


def create_backup(output: Path, database_url: str, evidence_dir: Path) -> dict[str, Any]:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"Backup already exists: {output}")
    with tempfile.TemporaryDirectory(prefix="satark-backup-") as temporary:
        work = Path(temporary)
        database_file = work / "database"
        database_kind = _copy_database(database_url, database_file)
        database_name = "database.sqlite" if database_kind == "sqlite" else "database.dump"
        database_file.rename(work / database_name)
        evidence_file = work / "evidence.tar.gz"
        _archive_evidence(evidence_dir, evidence_file)
        manifest = {
            "format": "satark-backup-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database_engine": database_kind,
            "files": {
                database_name: sha256_file(work / database_name),
                "evidence.tar.gz": sha256_file(evidence_file),
            },
            "restore_note": "Restore only into an empty target database and evidence directory.",
        }
        manifest_file = work / "manifest.json"
        manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary_output = output.with_name(output.name + ".tmp")
        try:
            with tarfile.open(temporary_output, "w:gz") as archive:
                for name in (database_name, "evidence.tar.gz", "manifest.json"):
                    archive.add(work / name, arcname=name, recursive=False)
            os.replace(temporary_output, output)
        finally:
            if temporary_output.exists():
                temporary_output.unlink()
        return manifest


def _safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def verify_backup(archive_path: Path) -> dict[str, Any]:
    expected_names = {"manifest.json", "evidence.tar.gz"}
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if any(not member.isfile() or not _safe_member_name(member.name) for member in members):
            raise ValueError("Backup contains an unsafe or unsupported archive member.")
        by_name = {member.name: member for member in members}
        if len(by_name) != len(members) or not expected_names.issubset(by_name):
            raise ValueError("Backup is missing required files or contains duplicate paths.")
        if "database.sqlite" in by_name:
            database_name = "database.sqlite"
        elif "database.dump" in by_name:
            database_name = "database.dump"
        else:
            raise ValueError("Backup database file is missing.")
        if set(by_name) != expected_names | {database_name}:
            raise ValueError("Backup contains unexpected files.")
        manifest_raw = archive.extractfile(by_name["manifest.json"])
        if manifest_raw is None:
            raise ValueError("Backup manifest cannot be read.")
        manifest = json.loads(manifest_raw.read().decode("utf-8"))
        if manifest.get("format") != "satark-backup-v1":
            raise ValueError("Unsupported SATARK backup format.")
        if manifest.get("database_engine") not in {"sqlite", "postgresql"}:
            raise ValueError("Unsupported database engine in backup.")
        if (manifest["database_engine"] == "sqlite") != (database_name == "database.sqlite"):
            raise ValueError("Backup database file does not match its manifest.")
        if set(manifest.get("files", {})) != {database_name, "evidence.tar.gz"}:
            raise ValueError("Backup manifest file inventory is invalid.")
        for name in (database_name, "evidence.tar.gz"):
            source = archive.extractfile(by_name[name])
            if source is None:
                raise ValueError(f"Backup file cannot be read: {name}")
            digest = hashlib.sha256(source.read()).hexdigest()
            if not hmac.compare_digest(digest, manifest["files"][name]):
                raise ValueError(f"Backup checksum mismatch: {name}")
        return manifest


def _extract_evidence_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not _safe_member_name(member.name):
                raise ValueError("Evidence archive contains an unsafe or unsupported entry.")
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents:
                raise ValueError("Evidence archive path escapes its destination.")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("Evidence archive entry cannot be read.")
            with target.open("xb") as handle:
                shutil.copyfileobj(source, handle)


def restore_backup(
    archive_path: Path,
    target_database_url: str,
    target_evidence_dir: Path,
) -> dict[str, Any]:
    manifest = verify_backup(archive_path)
    target_evidence_dir = target_evidence_dir.expanduser().resolve()
    if target_evidence_dir.exists() and any(target_evidence_dir.iterdir()):
        raise FileExistsError("Target evidence directory must be empty.")
    target_evidence_dir.parent.mkdir(parents=True, exist_ok=True)
    target_url = make_url(target_database_url)
    if manifest["database_engine"] == "sqlite":
        target_db = _sqlite_target_path(target_url)
        if target_db.exists():
            raise FileExistsError("Target SQLite database already exists.")
    else:
        if not target_url.drivername.startswith("postgresql"):
            raise ValueError("A PostgreSQL backup requires a PostgreSQL target URL.")
        if not shutil.which("pg_restore"):
            raise RuntimeError("pg_restore is required to restore PostgreSQL.")
        target_db = None

    target_evidence_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="satark-restore-", dir=target_evidence_dir.parent) as temporary:
        work = Path(temporary)
        with tarfile.open(archive_path, "r:gz") as archive:
            for name in ("database.sqlite" if manifest["database_engine"] == "sqlite" else "database.dump", "evidence.tar.gz"):
                source = archive.extractfile(name)
                if source is None:
                    raise ValueError(f"Backup file cannot be read: {name}")
                with (work / name).open("xb") as handle:
                    shutil.copyfileobj(source, handle)
        staged_evidence = work / "evidence"
        _extract_evidence_archive(work / "evidence.tar.gz", staged_evidence)
        if manifest["database_engine"] == "sqlite":
            target_db.parent.mkdir(parents=True, exist_ok=True)
            staged_db = target_db.with_name(target_db.name + ".satark-restore.tmp")
            if staged_db.exists():
                staged_db.unlink()
            shutil.copy2(work / "database.sqlite", staged_db)
            os.replace(staged_db, target_db)
        else:
            safe_url, env = _pg_env(target_url)
            subprocess.run(
                ["pg_restore", "--exit-on-error", "--no-owner", "--no-acl", "--dbname", safe_url,
                 str(work / "database.dump")],
                env=env, check=True, timeout=3600,
            )
        if target_evidence_dir.exists():
            target_evidence_dir.rmdir()
        os.replace(staged_evidence, target_evidence_dir)
    return manifest


def _sqlite_target_path(url) -> Path:
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        raise ValueError("A file-backed SQLite target URL is required.")
    return Path(url.database).expanduser().resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description="SATARK backup, verification, and restore utility")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Create a database + evidence backup")
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="Verify backup archive checksums")
    verify.add_argument("archive", type=Path)
    restore = commands.add_parser("restore", help="Restore into an empty database and evidence directory")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--database-url", default=os.getenv("SATARK_DATABASE_URL", ""))
    restore.add_argument("--evidence-dir", type=Path, default=Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")))
    args = parser.parse_args()
    try:
        if args.command == "create":
            manifest = create_backup(
                args.output,
                os.getenv("SATARK_DATABASE_URL", ""),
                Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")),
            )
            print(json.dumps({"status": "created", "output": str(args.output), "manifest": manifest}, indent=2))
        elif args.command == "verify":
            print(json.dumps({"status": "verified", "manifest": verify_backup(args.archive)}, indent=2))
        else:
            if not args.database_url:
                raise ValueError("Set SATARK_DATABASE_URL or pass --database-url.")
            manifest = restore_backup(args.archive, args.database_url, args.evidence_dir)
            print(json.dumps({"status": "restored", "manifest": manifest}, indent=2))
        return 0
    except Exception as exc:
        print(f"SATARK backup operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
