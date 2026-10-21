#!/usr/bin/env python3
"""SATARK native Linux telemetry collector (stdlib-only, no network access).

Collects selected security-relevant lines from an operator-specified auth log
and records bounded file-integrity observations. This is a lightweight sensor,
not a replacement for kernel audit/eBPF/EDR telemetry. Run with least privilege.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FILES = 5000
AUTH_PATTERNS = (
    ("auth_failed", re.compile(r"failed password|authentication failure|invalid user|failed publickey", re.I)),
    ("auth_success", re.compile(r"accepted password|accepted publickey|successful login", re.I)),
    ("privilege_use", re.compile(r"sudo:|COMMAND=", re.I)),
    ("session_change", re.compile(r"session opened|session closed", re.I)),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify_auth_line(line: str) -> str | None:
    for event_type, pattern in AUTH_PATTERNS:
        if pattern.search(line):
            return event_type
    return None


def event_record(source: str, event_type: str, raw: bytes, observed_at: int | None = None) -> dict[str, Any]:
    return {
        "schema": "satark.native-event.v1",
        "event_id": sha256(source.encode() + b"\0" + raw),
        "observed_at_unix": int(time.time()) if observed_at is None else int(observed_at),
        "source": source,
        "event_type": event_type,
        "severity": {"auth_failed": "medium", "auth_success": "low", "privilege_use": "medium", "session_change": "low"}.get(event_type, "info"),
        "raw_sha256": sha256(raw),
        "raw_excerpt": raw[:MAX_LINE_BYTES].decode("utf-8", "replace").strip(),
        "collector": "satark-native-linux",
        "evidence_class": "observed_local_source",
    }


def parse_auth_log(path: Path, max_bytes: int = MAX_LOG_BYTES) -> list[dict[str, Any]]:
    """Read only a bounded tail; do not follow symlinks or read special files."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot stat auth log: {exc.__class__.__name__}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("auth log must be a regular non-symlink file")
    with path.open("rb") as handle:
        handle.seek(max(0, info.st_size - max_bytes))
        data = handle.read(max_bytes)
    rows = []
    for raw_line in data.splitlines():
        raw_line = raw_line[:MAX_LINE_BYTES]
        event_type = classify_auth_line(raw_line.decode("utf-8", "replace"))
        if event_type:
            rows.append(event_record(str(path), event_type, raw_line))
    return rows


def scan_files(paths: list[Path], max_files: int = MAX_FILES) -> dict[str, dict[str, Any]]:
    """Build a bounded manifest of regular files, without following symlinks."""
    manifest: dict[str, dict[str, Any]] = {}
    for root in paths:
        if len(manifest) >= max_files:
            break
        try:
            root_info = root.lstat()
        except OSError:
            continue
        if stat.S_ISREG(root_info.st_mode):
            candidates = (root,)
        elif stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode):
            candidates = root.rglob("*")
        else:
            candidates = ()
        for path in candidates:
            if len(manifest) >= max_files:
                break
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                    continue
                with path.open("rb") as handle:
                    content = handle.read(MAX_FILE_BYTES + 1)
                if len(content) > MAX_FILE_BYTES:
                    continue
                manifest[str(path)] = {
                    "size": len(content),
                    "mtime_ns": info.st_mtime_ns,
                    "sha256": sha256(content),
                }
            except OSError:
                continue
    return manifest


def integrity_events(previous: dict[str, Any], current: dict[str, Any], observed_at: int | None = None) -> list[dict[str, Any]]:
    events = []
    for path in sorted(current):
        old, new = previous.get(path), current[path]
        if old is None:
            event_type = "file_added"
        elif old.get("sha256") != new.get("sha256"):
            event_type = "file_modified"
        else:
            continue
        raw = json.dumps({"path": path, "old": old, "new": new}, sort_keys=True, separators=(",", ":")).encode()
        record = event_record("file_integrity:" + path, event_type, raw, observed_at)
        record["severity"] = "medium" if event_type == "file_modified" else "low"
        record["path"] = path
        record["previous_sha256"] = old.get("sha256") if old else None
        record["current_sha256"] = new["sha256"]
        events.append(record)
    for path in sorted(set(previous) - set(current)):
        raw = json.dumps({"path": path, "old": previous[path], "new": None}, sort_keys=True).encode()
        record = event_record("file_integrity:" + path, "file_missing", raw, observed_at)
        record["severity"] = "medium"
        record["path"] = path
        record["previous_sha256"] = previous[path].get("sha256")
        record["current_sha256"] = None
        events.append(record)
    return events


def append_hash_chain(journal: Path, events: list[dict[str, Any]]) -> int:
    """Append JSONL events with a verifiable previous-hash chain and fsync."""
    journal.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = "0" * 64
    try:
        info = journal.lstat()
    except FileNotFoundError:
        info = None
    if info is not None and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
        raise ValueError("journal must be a regular non-symlink file")
    if info is not None:
        fd = os.open(journal, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            with os.fdopen(fd, "rb", closefd=False) as handle:
                for raw in handle:
                    try:
                        existing = json.loads(raw)
                        previous_hash = existing["chain_hash"]
                    except (json.JSONDecodeError, KeyError, TypeError):
                        raise ValueError("journal is malformed; refusing to append")
        finally:
            os.close(fd)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(journal, flags, 0o600)
    written = 0
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("journal must be a regular non-symlink file")
        with os.fdopen(fd, "ab", closefd=False) as handle:
            for event in events:
                payload = {**event, "previous_chain_hash": previous_hash}
                chain_hash = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
                payload["chain_hash"] = chain_hash
                handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                previous_hash = chain_hash
                written += 1
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
    return written

def verify_hash_chain(journal: Path) -> tuple[bool, int]:
    previous_hash = "0" * 64
    count = 0
    try:
        info = journal.lstat()
    except FileNotFoundError:
        return True, 0
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False, 0
    try:
        fd = os.open(journal, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False, 0
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False, 0
        with os.fdopen(fd, "rb", closefd=False) as handle:
            for raw in handle:
                try:
                    item = json.loads(raw)
                    supplied = item.pop("chain_hash")
                    if item.get("previous_chain_hash") != previous_hash:
                        return False, count
                    calculated = sha256(json.dumps(item, sort_keys=True, separators=(",", ":")).encode())
                    if supplied != calculated:
                        return False, count
                    previous_hash = supplied
                    count += 1
                except (json.JSONDecodeError, KeyError, TypeError):
                    return False, count
    finally:
        os.close(fd)
    return True, count


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("state file is unreadable or malformed") from exc
    if not isinstance(value, dict):
        raise ValueError("state file must contain a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    auth = sub.add_parser("auth-log", help="collect selected events from a local Linux auth log")
    auth.add_argument("--path", type=Path, default=Path("/var/log/auth.log"))
    auth.add_argument("--journal", type=Path, required=True)
    fim = sub.add_parser("file-scan", help="scan explicit paths and compare with a prior manifest")
    fim.add_argument("--paths", nargs="+", type=Path, required=True)
    fim.add_argument("--state", type=Path, required=True)
    fim.add_argument("--journal", type=Path, required=True)
    verify = sub.add_parser("verify-journal", help="verify the local hash chain")
    verify.add_argument("--journal", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "auth-log":
            events = parse_auth_log(args.path)
            count = append_hash_chain(args.journal, events)
            print(json.dumps({"status": "ok", "mode": "local_auth_log", "events_appended": count, "journal": str(args.journal)}))
        elif args.command == "file-scan":
            previous = load_json(args.state)
            current = scan_files(args.paths)
            events = integrity_events(previous, current)
            count = append_hash_chain(args.journal, events)
            args.state.parent.mkdir(parents=True, exist_ok=True)
            args.state.write_text(json.dumps(current, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"status": "ok", "mode": "local_file_integrity", "files_observed": len(current), "events_appended": count, "journal": str(args.journal)}))
        else:
            ok, count = verify_hash_chain(args.journal)
            print(json.dumps({"status": "ok" if ok else "failed", "records_verified": count}))
            return 0 if ok else 2
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
