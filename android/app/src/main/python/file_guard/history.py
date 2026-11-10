"""Local SQLite scan history. Stores metadata and bounded evidence reports, never file bytes."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .report import build_evidence_report


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
            db.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_time ON scan_history(scanned_at DESC)")

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def add(self, result, *, snapshot=None):
        record = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report = build_evidence_report(record, scanned_at=scanned_at, snapshot=snapshot)
        with self._connect() as db:
            db.execute("""INSERT INTO scan_history
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
                json.dumps(report, ensure_ascii=True),
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

    def clear(self):
        with self._connect() as db:
            db.execute("DELETE FROM scan_history")
