from io import BytesIO, StringIO
import hashlib
import tempfile
import unittest
from pathlib import Path

from file_guard.engine import scan_bytes, scan_stream, scan_path, scan_directory
from file_guard.history import ScanHistory
from file_guard.intelligence import ThreatIntelligenceStore

class FileGuardTests(unittest.TestCase):
    def test_pdf_fingerprint_without_content_extraction(self):
        result = scan_bytes(b"%PDF-1.7\nprivate text", "note.pdf")
        self.assertEqual(result.detected_type, "PDF")
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

    def test_clear_intelligence_removes_indicators(self):
        digest = hashlib.sha256(b"fixture").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatIntelligenceStore(Path(tmp) / "intel.sqlite3")
            store.import_csv(StringIO(f"sha256,label\n{digest},malicious\n"), "snapshot")
            store.clear()
            self.assertEqual(store.stats()["total"], 0)

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
