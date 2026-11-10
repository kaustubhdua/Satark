import json
import tempfile
import unittest
from pathlib import Path

from scripts.import_ember2024 import UPSTREAM_REVISION, convert, normalize_label

class EmberImportTests(unittest.TestCase):
    def test_label_mapping(self):
        self.assertEqual(normalize_label(0), "benign")
        self.assertEqual(normalize_label(1), "malicious")
        self.assertIsNone(normalize_label(-1))
        self.assertEqual(normalize_label(9), "invalid")

    def test_conversion_filters_unlabeled_and_chunks_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "Win32_train_000.jsonl"
            records = [
                {"sha256": "a" * 64, "label": 0, "file_type": "Win32", "first_submission_date": 1700000000},
                {"sha256": "b" * 64, "label": 1, "file_type": "Win32", "family": "family-x"},
                {"sha256": "c" * 64, "label": -1, "file_type": "Win32"},
                {"sha256": "invalid", "label": 1, "file_type": "Win32"},
            ]
            source.write_text("\n".join(json.dumps(x) for x in records), encoding="utf-8")
            manifest = convert(root, root / "out", split="train", file_type="Win32", rows_per_part=1)
            self.assertEqual(manifest["rows"]["rows_seen"], 4)
            self.assertEqual(manifest["rows"]["exported_rows"], 2)
            self.assertEqual(manifest["rows"]["unlabeled_rows"], 1)
            self.assertEqual(manifest["rows"]["invalid_rows"], 1)
            self.assertEqual(len(manifest["parts"]), 2)
            self.assertEqual(manifest["upstream_revision"], UPSTREAM_REVISION)
            self.assertEqual(manifest["dataset_repository_license"], "Apache-2.0")
            first = (root / "out" / manifest["parts"][0]["file"]).read_text(encoding="utf-8")
            self.assertIn("benign", first)
            self.assertIn("Win32", first)

    def test_challenge_split_exports_malicious_historical_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "challenge.jsonl").write_text(
                json.dumps({"sha256": "c" * 64, "label": 1, "file_type": "APK"}) + "\n",
                encoding="utf-8",
            )
            (root / "APK_train.jsonl").write_text(
                json.dumps({"sha256": "a" * 64, "label": 0, "file_type": "APK"}) + "\n",
                encoding="utf-8",
            )
            manifest = convert(root, root / "out", split="challenge", file_type="all")
            self.assertEqual(manifest["source_files"], ["challenge.jsonl"])
            self.assertEqual(manifest["rows"]["exported_rows"], 1)
            csv_text = (root / "out" / manifest["parts"][0]["file"]).read_text(encoding="utf-8")
            self.assertIn("malicious", csv_text)
            self.assertNotIn("benign", csv_text)

    def test_converter_binds_source_archive_provenance_and_rejects_tampering(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_dir = root / ".archives"
            archive_dir.mkdir()
            archive = archive_dir / "APK_train.zip"
            archive_bytes = b"verified pinned source archive bytes"
            archive.write_bytes(archive_bytes)
            source = root / "APK_train_000.jsonl"
            source.write_text(
                json.dumps({"sha256": "d" * 64, "label": 1, "file_type": "APK"}) + "\n",
                encoding="utf-8",
            )
            download_manifest = {
                "dataset": "EMBER2024",
                "dataset_revision": UPSTREAM_REVISION,
                "split": "train",
                "file_type": "APK",
                "archives": [{
                    "file": archive.name,
                    "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                    "bytes": len(archive_bytes),
                }],
                "extracted_jsonl_files": [source.name],
            }
            (root / "ember2024_download_train_apk.json").write_text(
                json.dumps(download_manifest), encoding="utf-8"
            )
            manifest = convert(root, root / "out", split="train", file_type="APK")
            self.assertEqual(manifest["source_manifest"]["dataset_revision"], UPSTREAM_REVISION)
            self.assertEqual(len(manifest["source_manifest"]["archives"]), 1)

            archive.write_bytes(archive_bytes + b"tampered")
            with self.assertRaises(ValueError):
                convert(root, root / "out", split="train", file_type="APK")

    def test_file_type_and_split_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "APK_train.jsonl").write_text(
                json.dumps({"sha256":"a"*64,"label":1,"file_type":"APK"}) + "\n", encoding="utf-8")
            (root / "PDF_test.jsonl").write_text(
                json.dumps({"sha256":"b"*64,"label":1,"file_type":"PDF"}) + "\n", encoding="utf-8")
            manifest = convert(root, root / "out", split="train", file_type="APK")
            self.assertEqual(manifest["rows"]["exported_rows"], 1)
            self.assertEqual(manifest["source_files"], ["APK_train.jsonl"])

if __name__ == "__main__":
    unittest.main()
