from io import BytesIO, StringIO
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from file_guard.agents import fuse_evidence, route_file
from file_guard.engine import scan_bytes, scan_stream, scan_path, scan_directory
from file_guard.history import ScanHistory
from file_guard.intelligence import ThreatIntelligenceStore

class FileGuardTests(unittest.TestCase):
    def test_pdf_fingerprint_without_content_extraction(self):
        result = scan_bytes(b"%PDF-1.7\nprivate text", "note.pdf")
        self.assertEqual(result.detected_type, "PDF")
        self.assertFalse(result.content_extracted)
        self.assertFalse(result.executed)

    def test_specialist_agent_trace_is_structured(self):
        result = scan_bytes(b"%PDF-1.7 sample", "sample.pdf")
        self.assertEqual(result.agent_trace[0]["agent"], "file_router")
        self.assertIn("sha256_intelligence", result.agent_trace[0]["specialists"])
        self.assertEqual(result.agent_trace[-1]["agent"], "evidence_fusion")
        self.assertFalse(result.content_extracted)

    def test_router_adds_yara_only_when_configured(self):
        plain = route_file("file.pdf", "PDF", yara_configured=False)
        with_yara = route_file("file.pdf", "PDF", yara_configured=True)
        self.assertNotIn("local_yara", plain["specialists"])
        self.assertIn("local_yara", with_yara["specialists"])

    def test_benign_hash_never_downgrades_suspicious_metadata(self):
        result = fuse_evidence(
            [{"code": "EXTENSION_SIGNATURE_MISMATCH", "severity": "high"}],
            {"label": "benign"}, []
        )
        self.assertEqual(result["verdict"], "Suspicious")

    def test_additional_static_file_signatures(self):
        cases = [
            (b"BM" + bytes(32), "photo.bmp", "BMP image"),
            (b"II*\\x00" + bytes(32), "photo.tiff", "TIFF image"),
            (b"RIFF" + bytes(4) + b"WAVE" + bytes(16), "audio.wav", "WAV audio"),
            (bytes(4) + b"ftypisom" + bytes(16), "clip.mp4", "ISO base media / MP4"),
            (b"SQLite format 3\\x00" + bytes(16), "cache.sqlite3", "SQLite database"),
            (b"\\x1f\\x8b" + bytes(16), "archive.gz", "GZIP archive"),
        ]
        for payload, filename, expected in cases:
            with self.subTest(filename=filename):
                result = scan_bytes(payload, filename)
                self.assertEqual(result.detected_type, expected)
                self.assertFalse(result.content_extracted)
                self.assertFalse(result.executed)

    def test_signature_extension_mismatch(self):
        result = scan_bytes(b"MZ" + bytes(32), "invoice.pdf")
        self.assertEqual(result.verdict, "Suspicious")
        self.assertIn("EXTENSION_SIGNATURE_MISMATCH", [x["code"] for x in result.signals])

    def test_double_extension(self):
        result = scan_bytes(b"MZ" + bytes(32), "invoice.pdf.exe")
        self.assertIn("DOUBLE_EXTENSION", [x["code"] for x in result.signals])
        self.assertEqual(result.verdict, "Suspicious")

    def test_exact_historical_hash_match(self):
        payload = b"%PDF-1.7 test"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatIntelligenceStore(Path(tmp) / "intel.sqlite3")
            imported = store.import_csv(StringIO(f"sha256,label,family\n{digest},malicious,test\n"), "test-snapshot")
            self.assertEqual(imported["inserted"], 1)
            self.assertEqual(scan_bytes(payload, "test.pdf", intelligence=store).verdict, "Known threat")

    def test_existing_hash_database_migrates_file_type_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.sqlite3"
            with sqlite3.connect(path) as db:
                db.execute("""CREATE TABLE hashes (
                    sha256 TEXT PRIMARY KEY,
                    label TEXT NOT NULL CHECK(label IN ('malicious','benign')),
                    family TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL,
                    dataset_date TEXT NOT NULL DEFAULT ''
                )""")
            store = ThreatIntelligenceStore(path)
            with sqlite3.connect(path) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(hashes)")}
            self.assertIn("file_type", columns)
            self.assertEqual(store.stats()["total"], 0)

    def test_clear_intelligence_removes_indicators(self):
        digest = hashlib.sha256(b"fixture").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatIntelligenceStore(Path(tmp) / "intel.sqlite3")
            store.import_csv(StringIO(f"sha256,label\n{digest},malicious\n"), "snapshot")
            store.clear()
            self.assertEqual(store.stats()["total"], 0)

    def test_historical_import_retains_file_type_provenance(self):
        digest = hashlib.sha256(b"apk-fixture").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatIntelligenceStore(Path(tmp) / "intel.sqlite3")
            store.import_csv(
                StringIO(f"sha256,label,file_type,dataset_date\n{digest},1,APK,2024-12-01\n"),
                "EMBER2024-APK-train",
            )
            result = scan_bytes(b"apk-fixture", "sample.apk", intelligence=store)
            self.assertEqual(result.verdict, "Known threat")
            self.assertEqual(result.intelligence_match["file_type"], "APK")
            self.assertEqual(result.intelligence_match["dataset_date"], "2024-12-01")

    def test_conflicting_labels_rejected(self):
        digest = hashlib.sha256(b"x").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatIntelligenceStore(Path(tmp) / "intel.sqlite3")
            store.import_csv(StringIO(f"sha256,label\n{digest},benign\n"), "snapshot-a")
            with self.assertRaises(ValueError):
                store.import_csv(StringIO(f"sha256,label\n{digest},malicious\n"), "snapshot-b")

    def test_stream_size_limit(self):
        with self.assertRaises(ValueError):
            scan_stream(BytesIO(b"12345"), "x.bin", max_bytes=4)

    def test_directory_scan_and_symlink_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.pdf").write_bytes(b"%PDF-1.7")
            (root / "link.pdf").symlink_to(root / "one.pdf")
            result = scan_directory(root)
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual(result["results"][0]["filename"], "one.pdf")

    def test_scan_path_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "real.bin"
            target.write_bytes(b"test")
            link = root / "link.bin"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                scan_path(link)

    def test_history_is_bounded_and_contains_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = ScanHistory(Path(tmp) / "history.sqlite3", max_records=2)
            for i in range(3):
                history.add(scan_bytes(f"file-{i}".encode(), f"{i}.bin"))
            records = history.list_recent(10)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["filename"], "2.bin")
            self.assertNotIn("content", records[0])

if __name__ == "__main__":
    unittest.main()
