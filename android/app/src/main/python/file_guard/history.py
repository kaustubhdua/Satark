"""Local bounded metadata-only scan history."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

class ScanHistory:
    def __init__(self, path, max_records=5000):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_records = max_records
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL,
                filename TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
                detected_type TEXT NOT NULL, verdict TEXT NOT NULL, risk_level TEXT NOT NULL,
                signals_json TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_history_time ON scan_history(scanned_at DESC)")

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def add(self, result):
        item = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        with self._connect() as db:
            db.execute("""INSERT INTO scan_history
                (scanned_at,filename,size_bytes,sha256,detected_type,verdict,risk_level,signals_json)
                VALUES(?,?,?,?,?,?,?,?)""", (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                str(item.get("filename", "unnamed"))[:255], int(item.get("size_bytes", 0)),
                str(item.get("sha256", ""))[:64], str(item.get("detected_type", "unknown"))[:80],
                str(item.get("verdict", "unknown"))[:80], str(item.get("risk_level", "unknown"))[:24],
                json.dumps(item.get("signals", []), ensure_ascii=True)[:12000]))
            db.execute("DELETE FROM scan_history WHERE id NOT IN (SELECT id FROM scan_history ORDER BY id DESC LIMIT ?)",
                       (self.max_records,))

    def list_recent(self, limit=100):
        with self._connect() as db:
            rows = db.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?",
                              (max(1, min(int(limit), 500)),)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["signals"] = json.loads(item.pop("signals_json"))
            result.append(item)
        return result
