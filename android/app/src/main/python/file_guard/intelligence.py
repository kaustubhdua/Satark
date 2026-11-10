"""Explicit-import-only local SHA-256 intelligence store. Never accesses network."""
import csv
import re
import sqlite3
from pathlib import Path

_SHA = re.compile(r"^[a-f0-9]{64}$")
_LABELS = {"malicious", "benign"}

class ThreatIntelligenceStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS hashes (
                sha256 TEXT PRIMARY KEY,
                label TEXT NOT NULL CHECK(label IN ('malicious','benign')),
                family TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL,
                dataset_date TEXT NOT NULL DEFAULT '',
                file_type TEXT NOT NULL DEFAULT ''
            )""")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(hashes)").fetchall()}
            if "file_type" not in columns:
                db.execute("ALTER TABLE hashes ADD COLUMN file_type TEXT NOT NULL DEFAULT ''")

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def lookup(self, digest):
        digest = str(digest).lower()
        if not _SHA.fullmatch(digest):
            raise ValueError("Invalid SHA-256 digest.")
        with self._connect() as db:
            row = db.execute("SELECT * FROM hashes WHERE sha256=?", (digest,)).fetchone()
        return dict(row) if row else None

    def import_csv(self, file_obj, source_name, max_rows=2_000_000):
        if not source_name or len(source_name) > 160:
            raise ValueError("A traceable dataset source name is required.")
        reader = csv.DictReader(file_obj)
        fields = {str(x).strip().lower() for x in (reader.fieldnames or [])}
        if not {"sha256", "label"}.issubset(fields):
            raise ValueError("CSV must include sha256 and label.")
        inserted = skipped = rejected = 0
        with self._connect() as db:
            for index, raw in enumerate(reader, 1):
                if index > max_rows:
                    raise ValueError("Dataset exceeds the import row limit.")
                row = {str(k).strip().lower(): (v or "").strip() for k, v in raw.items() if k}
                digest = row.get("sha256", "").lower()
                label = row.get("label", "").lower()
                if label in {"1", "malware"}:
                    label = "malicious"
                elif label == "0":
                    label = "benign"
                if not _SHA.fullmatch(digest) or label not in _LABELS:
                    rejected += 1
                    continue
                family = row.get("family", "")[:120]
                file_type = row.get("file_type", row.get("filetype", ""))[:40]
                dataset_date = row.get("dataset_date", row.get("date", row.get("first_submission_date", "")))[:40]
                prior = db.execute("SELECT label FROM hashes WHERE sha256=?", (digest,)).fetchone()
                if prior:
                    if prior["label"] != label:
                        raise ValueError("Conflicting labels for an existing hash.")
                    skipped += 1
                    continue
                db.execute(
                    """INSERT INTO hashes(sha256,label,family,source,dataset_date,file_type)
                       VALUES(?,?,?,?,?,?)""",
                    (digest, label, family, source_name, dataset_date, file_type),
                )
                inserted += 1
        return {"inserted": inserted, "skipped": skipped, "rejected": rejected}

    def clear(self):
        """Remove imported indicators without touching scan history."""
        with self._connect() as db:
            db.execute("DELETE FROM hashes")

    def stats(self):
        with self._connect() as db:
            rows = db.execute("SELECT label,COUNT(*) n FROM hashes GROUP BY label").fetchall()
            type_rows = db.execute(
                "SELECT file_type,COUNT(*) n FROM hashes GROUP BY file_type ORDER BY file_type"
            ).fetchall()
            source_count = db.execute("SELECT COUNT(DISTINCT source) n FROM hashes").fetchone()["n"]
        counts = {r["label"]: r["n"] for r in rows}
        by_file_type = {r["file_type"] or "unknown": r["n"] for r in type_rows}
        return {
            "total": sum(counts.values()),
            "malicious": counts.get("malicious", 0),
            "benign": counts.get("benign", 0),
            "by_file_type": by_file_type,
            "source_count": source_count,
        }
