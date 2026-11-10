"""Local SQLite scan history and tamper-evident hash-chained audit records.

The chain detects edits, reordering and deletion within the retained audit log.
It is not signed, remotely anchored, or immutable against an attacker who can
rewrite the complete app-private database.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from .report import build_evidence_report, verify_evidence_report

_GENESIS = "0" * 64


def _canonical_digest(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ScanHistory:
    def __init__(self, path, max_records=5000):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_records = max_records
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                detected_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                signals_json TEXT NOT NULL,
                report_json TEXT NOT NULL DEFAULT '{}'
            )""")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(scan_history)").fetchall()}
            if "report_json" not in columns:
                db.execute("ALTER TABLE scan_history ADD COLUMN report_json TEXT NOT NULL DEFAULT '{}' ")
            db.execute("""CREATE TABLE IF NOT EXISTS scan_audit (
                sequence INTEGER PRIMARY KEY,
                history_id INTEGER NOT NULL,
                previous_entry_sha256 TEXT NOT NULL,
                entry_sha256 TEXT NOT NULL,
                entry_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_time ON scan_history(scanned_at DESC)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_scan_audit_history ON scan_audit(history_id)")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def add(self, result, *, snapshot=None):
        record = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report = build_evidence_report(record, scanned_at=scanned_at, snapshot=snapshot)
        with self._connect() as db:
            cursor = db.execute("""INSERT INTO scan_history
                (scanned_at,filename,size_bytes,sha256,detected_type,verdict,risk_level,signals_json,report_json)
                VALUES(?,?,?,?,?,?,?,?,?)""", (
                scanned_at,
                str(record.get("filename", "unnamed"))[:255],
                int(record.get("size_bytes", 0)),
                str(record.get("sha256", ""))[:64],
                str(record.get("detected_type", "unknown"))[:80],
                str(record.get("verdict", "unknown"))[:80],
                str(record.get("risk_level", "unknown"))[:24],
                json.dumps(record.get("signals", []), ensure_ascii=True)[:12000],
                "{}",
            ))
            history_id = int(cursor.lastrowid)
            latest = db.execute(
                "SELECT sequence, entry_sha256 FROM scan_audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = int(latest["sequence"]) + 1 if latest else 1
            previous = str(latest["entry_sha256"]) if latest else _GENESIS
            base_report_sha256 = report["report_sha256"]
            entry = {
                "sequence": sequence,
                "history_id": history_id,
                "scanned_at": scanned_at,
                "file_sha256": str(record.get("sha256", "")).lower(),
                "evidence_report_sha256": base_report_sha256,
                "previous_entry_sha256": previous,
            }
            entry_digest = _canonical_digest(entry)
            report["audit_chain"] = {
                "sequence": sequence,
                "previous_entry_sha256": previous,
                "evidence_report_sha256": base_report_sha256,
                "entry_sha256": entry_digest,
            }
            report_unsigned = {key: value for key, value in report.items() if key != "report_sha256"}
            report["report_sha256"] = _canonical_digest(report_unsigned)
            db.execute(
                "UPDATE scan_history SET report_json=? WHERE id=?",
                (json.dumps(report, ensure_ascii=True), history_id),
            )
            db.execute("""INSERT INTO scan_audit
                (sequence,history_id,previous_entry_sha256,entry_sha256,entry_json,created_at)
                VALUES(?,?,?,?,?,?)""", (
                sequence, history_id, previous, entry_digest,
                json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                scanned_at,
            ))
            db.execute("""DELETE FROM scan_history WHERE id NOT IN
                (SELECT id FROM scan_history ORDER BY id DESC LIMIT ?)""", (self.max_records,))
        return report

    def list_recent(self, limit=100):
        limit = max(1, min(int(limit), 500))
        with self._connect() as db:
            rows = db.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["signals"] = json.loads(item.pop("signals_json"))
            item["report"] = json.loads(item.pop("report_json", "{}"))
            items.append(item)
        return items

    def verify_audit_chain(self):
        with self._connect() as db:
            rows = db.execute("""SELECT a.*, h.report_json
                FROM scan_audit AS a
                LEFT JOIN scan_history AS h ON h.id=a.history_id
                ORDER BY a.sequence ASC""").fetchall()
            unlinked_history_records = int(db.execute("""SELECT COUNT(*)
                FROM scan_history AS h
                LEFT JOIN scan_audit AS a ON a.history_id=h.id
                WHERE a.history_id IS NULL""").fetchone()[0])
        previous = _GENESIS
        expected_sequence = 1
        report_checks = 0
        latest_sequence = int(rows[-1]["sequence"]) if rows else 0
        retained_start = max(1, latest_sequence - self.max_records + 1)
        for row in rows:
            try:
                entry = json.loads(row["entry_json"])
            except (TypeError, json.JSONDecodeError):
                return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                        "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "invalid_entry_json"}
            if int(row["sequence"]) != expected_sequence or entry.get("sequence") != expected_sequence:
                return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                        "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "sequence_gap"}
            if (int(entry.get("history_id", -1)) != int(row["history_id"]) or
                entry.get("scanned_at") != row["created_at"]):
                return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                        "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "entry_metadata_mismatch"}
            if row["previous_entry_sha256"] != previous or entry.get("previous_entry_sha256") != previous:
                return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                        "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "previous_digest_mismatch"}
            digest = _canonical_digest(entry)
            if digest != row["entry_sha256"]:
                return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                        "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "entry_digest_mismatch"}
            if not row["report_json"] and expected_sequence >= retained_start:
                return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                        "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "recent_report_missing"}
            if row["report_json"]:
                try:
                    report = json.loads(row["report_json"])
                except (TypeError, json.JSONDecodeError):
                    return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                            "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "invalid_report_json"}
                chain = report.get("audit_chain", {})
                if not verify_evidence_report(report):
                    return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                            "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "report_digest_mismatch"}
                if (report.get("scanned_at") != entry.get("scanned_at") or
                    report.get("file", {}).get("sha256") != entry.get("file_sha256")):
                    return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                            "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "report_metadata_mismatch"}
                if (chain.get("sequence") != expected_sequence or
                    chain.get("previous_entry_sha256") != previous or
                    chain.get("evidence_report_sha256") != entry.get("evidence_report_sha256") or
                    chain.get("entry_sha256") != digest):
                    return {"valid": False, "entries": len(rows), "verified_reports": report_checks,
                            "head_sha256": previous, "failed_sequence": row["sequence"], "reason": "report_audit_link_mismatch"}
                report_checks += 1
            previous = digest
            expected_sequence += 1
        return {
            "valid": True,
            "complete": unlinked_history_records == 0,
            "entries": len(rows),
            "verified_reports": report_checks,
            "unlinked_history_records": unlinked_history_records,
            "head_sha256": previous,
            "failed_sequence": None,
            "reason": None if unlinked_history_records == 0 else "legacy_history_not_chained",
            "authentication": "not_signed_or_remotely_anchored",
        }

    def clear(self):
        with self._connect() as db:
            db.execute("DELETE FROM scan_history")
            db.execute("DELETE FROM scan_audit")
