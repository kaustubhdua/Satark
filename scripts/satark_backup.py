"""Create, verify, and restore a SATARK database + private-evidence backup.

Quiesce API/worker writes before creating a backup so the database snapshot and
filesystem evidence archive represent the same point in time. Encrypt the
resulting archive with an approved offline/managed key before moving it off-host.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url


def sha256_stream(handle) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return sha256_stream(handle)


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
    drivername = "postgresql" if url.drivername.startswith("postgresql") else url.drivername
    safe_url = str(url.set(drivername=drivername, password=None, username=url.username))
    return safe_url, env


@contextmanager
def _pg_auth_env(url):
    """Yield a libpq environment with a private passfile for this exact URL."""
    _, env = _pg_env(url)

    def escape_pgpass(value: str) -> str:
        return value.replace("\\", "\\\\").replace(":", "\\:")

    descriptor, filename = tempfile.mkstemp(prefix="satark-pgpass-")
    passfile = Path(filename)
    os.close(descriptor)
    try:
        os.chmod(passfile, 0o600)
        # Match the exact endpoint used by libpq rather than relying on a
        # wildcard host entry. This keeps credentials scoped to this backup
        # target and avoids host-alias mismatches in CI/container environments.
        passfile.write_text(
            ":".join(escape_pgpass(value) for value in (
                url.host or "*", str(url.port or "*"), url.database or "*",
                url.username or "*", url.password or "",
            )) + "\n",
            encoding="utf-8",
        )
        env.pop("PGPASSWORD", None)
        env["PGPASSFILE"] = str(passfile)
        yield env
    finally:
        passfile.unlink(missing_ok=True)


def _sqlite_path(url) -> Path:
    if not url.database or url.database == ":memory:":
        raise ValueError("A file-backed SQLite database is required for backups.")
    raw_path = Path(url.database).expanduser()
    if raw_path.is_symlink():
        raise FileNotFoundError("The configured SQLite database file does not exist or is unsafe.")
    path = raw_path.resolve()
    if not path.is_file():
        raise FileNotFoundError("The configured SQLite database file does not exist or is unsafe.")
    return path


def _require_postgres_bypass_rls(database_url: str, operation: str) -> None:
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            allowed = connection.execute(text("""
                SELECT rolsuper OR rolbypassrls
                FROM pg_roles
                WHERE rolname = current_user
            """)).scalar()
        if not allowed:
            raise RuntimeError(
                f"PostgreSQL {operation} requires a superuser or BYPASSRLS-capable backup role; "
                "do not use the runtime API database credential."
            )
    finally:
        engine.dispose()


def _copy_database(database_url: str, destination: Path) -> str:
    url = make_url(database_url)
    if url.drivername.startswith("sqlite"):
        source = _sqlite_path(url)
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as src:
            with sqlite3.connect(destination) as dst:
                src.backup(dst)
        return "sqlite"
    if url.drivername.startswith("postgresql"):
        _require_postgres_bypass_rls(database_url, "backup")
        if not shutil.which("pg_dump"):
            raise RuntimeError("pg_dump is required to back up PostgreSQL.")
        command = ["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", str(destination)]
        if url.host:
            command.extend(["--host", url.host])
        if url.port:
            command.extend(["--port", str(url.port)])
        if url.username:
            command.extend(["--username", url.username])
        command.extend(["--dbname", url.database])
        with _pg_auth_env(url) as env:
            subprocess.run(command, env=env, check=True, timeout=3600)
        return "postgresql"
    raise ValueError("Only SQLite and PostgreSQL SATARK databases are supported.")


def _archive_evidence(evidence_dir: Path, destination: Path) -> None:
    raw_root = evidence_dir.expanduser()
    if raw_root.is_symlink():
        raise ValueError("Evidence directory must not be a symbolic link.")
    root = raw_root.resolve()
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


def _copy_response_ledger(source_path: Path, destination: Path) -> bool:
    raw_path = source_path.expanduser()
    if raw_path.is_symlink():
        raise ValueError("FIRSTLIGHT response ledger must not be a symbolic link.")
    if not raw_path.exists():
        return False
    source = raw_path.resolve()
    if not source.is_file():
        raise ValueError("FIRSTLIGHT response ledger must be a regular file.")
    with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as src:
        with sqlite3.connect(destination) as dst:
            src.backup(dst)
            result = dst.execute("PRAGMA integrity_check").fetchone()
            if not result or result[0] != "ok":
                raise ValueError("FIRSTLIGHT response ledger failed SQLite integrity_check.")
    return True


def create_backup(output: Path, database_url: str, evidence_dir: Path, response_ledger_path: Path | None = None) -> dict[str, Any]:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"Backup already exists: {output}")
    evidence_root = evidence_dir.expanduser().resolve()
    if output == evidence_root or evidence_root in output.parents:
        raise ValueError("Store the backup outside the live evidence directory.")
    with tempfile.TemporaryDirectory(prefix="satark-backup-") as temporary:
        work = Path(temporary)
        database_file = work / "database"
        database_kind = _copy_database(database_url, database_file)
        database_name = "database.sqlite" if database_kind == "sqlite" else "database.dump"
        database_file.rename(work / database_name)
        evidence_file = work / "evidence.tar.gz"
        _archive_evidence(evidence_dir, evidence_file)
        ledger_source = response_ledger_path or (Path(os.environ["FIRSTLIGHT_RESPONSE_DB"]) if os.getenv("FIRSTLIGHT_RESPONSE_DB") else None)
        ledger_name = "firstlight-response.sqlite3"
        include_ledger = bool(ledger_source and _copy_response_ledger(ledger_source, work / ledger_name))
        files = {
            database_name: sha256_file(work / database_name),
            "evidence.tar.gz": sha256_file(evidence_file),
        }
        if include_ledger:
            files[ledger_name] = sha256_file(work / ledger_name)
        manifest = {
            "format": "satark-backup-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database_engine": database_kind,
            "evidence_root": str(evidence_root),
            "files": files,
            "restore_note": "Restore only into an empty target database and evidence directory.",
        }
        manifest_file = work / "manifest.json"
        manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary_output = output.with_name(output.name + ".tmp")
        try:
            with tarfile.open(temporary_output, "w:gz") as archive:
                archive_names = [database_name, "evidence.tar.gz"]
                if include_ledger:
                    archive_names.append(ledger_name)
                archive_names.append("manifest.json")
                for name in archive_names:
                    archive.add(work / name, arcname=name, recursive=False)
            os.chmod(temporary_output, 0o600)
            os.replace(temporary_output, output)
            os.chmod(output, 0o600)
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
        optional_ledger = {"firstlight-response.sqlite3"} if "firstlight-response.sqlite3" in by_name else set()
        if set(by_name) != expected_names | {database_name} | optional_ledger:
            raise ValueError("Backup contains unexpected files.")
        manifest_raw = archive.extractfile(by_name["manifest.json"])
        if manifest_raw is None:
            raise ValueError("Backup manifest cannot be read.")
        manifest = json.loads(manifest_raw.read().decode("utf-8"))
        if manifest.get("format") != "satark-backup-v1":
            raise ValueError("Unsupported SATARK backup format.")
        if manifest.get("database_engine") not in {"sqlite", "postgresql"}:
            raise ValueError("Unsupported database engine in backup.")
        evidence_root = manifest.get("evidence_root")
        if evidence_root is not None and (not isinstance(evidence_root, str) or not Path(evidence_root).is_absolute()):
            raise ValueError("Backup evidence root is invalid.")
        if (manifest["database_engine"] == "sqlite") != (database_name == "database.sqlite"):
            raise ValueError("Backup database file does not match its manifest.")
        expected_files = {database_name, "evidence.tar.gz"} | optional_ledger
        if set(manifest.get("files", {})) != expected_files:
            raise ValueError("Backup manifest file inventory is invalid.")
        for name in sorted(expected_files):
            source = archive.extractfile(by_name[name])
            if source is None:
                raise ValueError(f"Backup file cannot be read: {name}")
            digest = sha256_stream(source)
            if not hmac.compare_digest(digest, manifest["files"][name]):
                raise ValueError(f"Backup checksum mismatch: {name}")
        return manifest


def _extract_evidence_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination, 0o700)
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not _safe_member_name(member.name):
                raise ValueError("Evidence archive contains an unsafe or unsupported entry.")
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents:
                raise ValueError("Evidence archive path escapes its destination.")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(target.parent, 0o700)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("Evidence archive entry cannot be read.")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    shutil.copyfileobj(source, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(target, 0o600)
            except Exception:
                target.unlink(missing_ok=True)
                raise


def _infer_evidence_root(database_url: str) -> Path | None:
    """Infer the original evidence root for older v1 archives without metadata."""
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            if "satark_evidence" not in inspect(connection).get_table_names():
                return None
            rows = connection.execute(text(
                "SELECT tenant_id, case_id, object_key FROM satark_evidence"
            )).all()
        roots: set[Path] = set()
        for tenant_id, case_id, object_key in rows:
            path = Path(object_key)
            if not path.is_absolute():
                raise ValueError("Backup contains a non-absolute evidence object key.")
            parts = path.parts
            matches = [
                index for index in range(len(parts) - 1)
                if parts[index] == tenant_id and parts[index + 1] == case_id
            ]
            if len(matches) != 1:
                raise ValueError("Cannot infer the source evidence root from a stored object key.")
            roots.add(Path(*parts[:matches[0]]))
        if not roots:
            return None
        if len(roots) != 1:
            raise ValueError("Backup evidence rows reference more than one evidence root.")
        return next(iter(roots))
    finally:
        engine.dispose()


def _rebase_evidence_paths(database_url: str, source_root: Path | None, target_root: Path) -> int:
    """Rewrite absolute evidence keys after restoring the archive to a new root."""
    if source_root is None:
        source_root = _infer_evidence_root(database_url)
    if source_root is None:
        return 0
    source_root = source_root.resolve()
    target_root = target_root.resolve()
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            if "satark_evidence" not in inspect(connection).get_table_names():
                return 0
            rows = connection.execute(text(
                "SELECT id, object_key FROM satark_evidence"
            )).all()
            for evidence_id, object_key in rows:
                original = Path(object_key)
                try:
                    relative = original.relative_to(source_root)
                except ValueError as exc:
                    raise ValueError("An evidence object key is outside the backup evidence root.") from exc
                rebased = (target_root / relative).resolve()
                if target_root not in rebased.parents or not rebased.is_file():
                    raise ValueError("A restored evidence object is missing or escapes its target root.")
                connection.execute(text(
                    "UPDATE satark_evidence SET object_key = :object_key WHERE id = :evidence_id"
                ), {"object_key": str(rebased), "evidence_id": evidence_id})
            return len(rows)
    finally:
        engine.dispose()


def restore_backup(
    archive_path: Path,
    target_database_url: str,
    target_evidence_dir: Path,
    target_response_ledger_path: Path | None = None,
) -> dict[str, Any]:
    manifest = verify_backup(archive_path)
    raw_evidence_target = target_evidence_dir.expanduser()
    if raw_evidence_target.is_symlink():
        raise ValueError("Target evidence directory must not be a symbolic link.")
    target_evidence_dir = raw_evidence_target.resolve()
    if target_evidence_dir.exists() and (not target_evidence_dir.is_dir() or any(target_evidence_dir.iterdir())):
        raise FileExistsError("Target evidence directory must be empty.")
    target_evidence_dir.parent.mkdir(parents=True, exist_ok=True)
    ledger_in_archive = "firstlight-response.sqlite3" in manifest.get("files", {})
    response_target = target_response_ledger_path or (Path(os.environ["FIRSTLIGHT_RESPONSE_DB"]) if os.getenv("FIRSTLIGHT_RESPONSE_DB") else None)
    if ledger_in_archive:
        if response_target is None:
            raise ValueError("Backup contains a FIRSTLIGHT response ledger; provide --response-ledger or set FIRSTLIGHT_RESPONSE_DB.")
        if response_target.expanduser().is_symlink() or response_target.expanduser().exists():
            raise FileExistsError("Target FIRSTLIGHT response ledger must not already exist.")
    target_url = make_url(target_database_url)
    if manifest["database_engine"] == "sqlite":
        target_db = _sqlite_target_path(target_url)
        if target_db.exists():
            raise FileExistsError("Target SQLite database already exists.")
    else:
        if not target_url.drivername.startswith("postgresql"):
            raise ValueError("A PostgreSQL backup requires a PostgreSQL target URL.")
        _require_postgres_bypass_rls(target_database_url, "restore")
        if not shutil.which("pg_restore"):
            raise RuntimeError("pg_restore is required to restore PostgreSQL.")
        target_db = None

    target_evidence_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="satark-restore-", dir=target_evidence_dir.parent) as temporary:
        work = Path(temporary)
        with tarfile.open(archive_path, "r:gz") as archive:
            restore_names = ["database.sqlite" if manifest["database_engine"] == "sqlite" else "database.dump", "evidence.tar.gz"]
            if ledger_in_archive:
                restore_names.append("firstlight-response.sqlite3")
            for name in restore_names:
                source = archive.extractfile(name)
                if source is None:
                    raise ValueError(f"Backup file cannot be read: {name}")
                with (work / name).open("xb") as handle:
                    shutil.copyfileobj(source, handle)
                os.chmod(work / name, 0o600)
        staged_evidence = work / "evidence"
        _extract_evidence_archive(work / "evidence.tar.gz", staged_evidence)
        if manifest["database_engine"] == "sqlite":
            target_db.parent.mkdir(parents=True, exist_ok=True)
            staged_db = target_db.with_name(target_db.name + ".satark-restore.tmp")
            if staged_db.exists():
                staged_db.unlink()
            shutil.copy2(work / "database.sqlite", staged_db)
            os.chmod(staged_db, 0o600)
            os.replace(staged_db, target_db)
            os.chmod(target_db, 0o600)
        else:
            command = ["pg_restore", "--exit-on-error", "--no-owner", "--no-acl"]
            if target_url.host:
                command.extend(["--host", target_url.host])
            if target_url.port:
                command.extend(["--port", str(target_url.port)])
            if target_url.username:
                command.extend(["--username", target_url.username])
            command.extend(["--dbname", target_url.database, str(work / "database.dump")])
            with _pg_auth_env(target_url) as env:
                subprocess.run(command, env=env, check=True, timeout=3600)
        if target_evidence_dir.exists():
            target_evidence_dir.rmdir()
        os.replace(staged_evidence, target_evidence_dir)
        if ledger_in_archive and response_target is not None:
            response_target = response_target.expanduser().resolve()
            response_target.parent.mkdir(parents=True, exist_ok=True)
            staged_ledger = work / "firstlight-response.sqlite3"
            with sqlite3.connect(f"file:{staged_ledger}?mode=ro", uri=True) as ledger_db:
                integrity = ledger_db.execute("PRAGMA integrity_check").fetchone()
                if not integrity or integrity[0] != "ok":
                    raise ValueError("Restored FIRSTLIGHT response ledger failed integrity_check.")
            os.chmod(staged_ledger, 0o600)
            os.replace(staged_ledger, response_target)
            os.chmod(response_target, 0o600)
    source_root_value = manifest.get("evidence_root")
    source_root = Path(source_root_value) if source_root_value else None
    manifest["evidence_objects_rebased"] = _rebase_evidence_paths(
        target_database_url, source_root, target_evidence_dir
    )
    # Rebase while the restore credential still owns the restored tables and
    # retains BYPASSRLS. Only then transfer ownership to the unprivileged runtime
    # role; SET ROLE runtime here would re-enable forced RLS and block the repair.
    restore_role = os.getenv("SATARK_RESTORE_ROLE", "").strip()
    if manifest["database_engine"] == "postgresql" and restore_role:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", restore_role):
            raise ValueError("SATARK_RESTORE_ROLE is not a valid PostgreSQL role name.")
        engine = create_engine(target_database_url, pool_pre_ping=True)
        try:
            with engine.begin() as connection:
                connection.execute(text(f"REASSIGN OWNED BY satark_backup TO {restore_role}"))
        finally:
            engine.dispose()
    return manifest


def _sqlite_target_path(url) -> Path:
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        raise ValueError("A file-backed SQLite target URL is required.")
    raw_path = Path(url.database).expanduser()
    if raw_path.is_symlink():
        raise ValueError("Target SQLite database must not be a symbolic link.")
    return raw_path.resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description="SATARK backup, verification, and restore utility")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Create a database + evidence backup")
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="Verify backup archive checksums")
    verify.add_argument("archive", type=Path)
    restore = commands.add_parser("restore", help="Restore into an empty database and evidence directory")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--database-url", default=os.getenv("SATARK_BACKUP_DATABASE_URL") or os.getenv("SATARK_DATABASE_URL", ""))
    restore.add_argument("--evidence-dir", type=Path, default=Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")))
    restore.add_argument("--response-ledger", type=Path, default=Path(os.environ["FIRSTLIGHT_RESPONSE_DB"]) if os.getenv("FIRSTLIGHT_RESPONSE_DB") else None)
    args = parser.parse_args()
    try:
        if args.command == "create":
            manifest = create_backup(
                args.output,
                os.getenv("SATARK_BACKUP_DATABASE_URL") or os.getenv("SATARK_DATABASE_URL", ""),
                Path(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")),
            )
            print(json.dumps({"status": "created", "output": str(args.output), "manifest": manifest}, indent=2))
        elif args.command == "verify":
            print(json.dumps({"status": "verified", "manifest": verify_backup(args.archive)}, indent=2))
        else:
            if not args.database_url:
                raise ValueError("Set SATARK_DATABASE_URL or pass --database-url.")
            manifest = restore_backup(args.archive, args.database_url, args.evidence_dir, args.response_ledger)
            print(json.dumps({"status": "restored", "manifest": manifest}, indent=2))
        return 0
    except Exception as exc:
        print(f"SATARK backup operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
