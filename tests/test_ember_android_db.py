import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from file_guard.intelligence import ThreatIntelligenceStore
from scripts.build_ember2024_android_db import build
from scripts.import_ember2024 import UPSTREAM_REVISION, convert


class EmberAndroidDatabaseTests(unittest.TestCase):
    def prepare(self, root):
        input_dir = root / "input"
        archive_dir = input_dir / ".archives"
        archive_dir.mkdir(parents=True)
        archive_bytes = b"pinned historical metadata archive"
        (archive_dir / "APK_train.zip").write_bytes(archive_bytes)
        source = input_dir / "APK_train_000.jsonl"
        digest = "e" * 64
        source.write_text(
            "\n".join([
                json.dumps({"sha256": digest, "label": 1, "file_type": "APK", "family": "family-a"}),
                json.dumps({"sha256": digest, "label": 1, "file_type": "APK", "family": "family-a"}),
            ]) + "\n",
            encoding="utf-8",
        )
        download_manifest = {
            "dataset": "EMBER2024",
            "dataset_revision": UPSTREAM_REVISION,
            "split": "train",
            "file_type": "APK",
            "archives": [{
                "file": "APK_train.zip",
                "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                "bytes": len(archive_bytes),
            }],
            "extracted_jsonl_files": [source.name],
        }
        (input_dir / "ember2024_download_train_apk.json").write_text(
            json.dumps(download_manifest), encoding="utf-8"
        )
        csv_dir = root / "csv"
        convert(input_dir, csv_dir, split="train", file_type="APK", rows_per_part=10)
        return input_dir, csv_dir, digest

    def test_builds_compact_hash_only_database_from_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir, csv_dir, digest = self.prepare(root)
            database = root / "ember2024-starter.sqlite3"
            metadata = build(input_dir, csv_dir, database, split="train", file_type="APK")
            self.assertEqual(metadata["dataset_revision"], UPSTREAM_REVISION)
            self.assertEqual(metadata["rows"]["unique_hashes"], 1)
            self.assertEqual(metadata["rows"]["malicious"], 1)
            self.assertEqual(metadata["rows"]["benign"], 0)
            self.assertEqual(metadata["rows"]["duplicate_same_label"], 1)
            self.assertFalse(metadata["contains_file_binaries"])
            self.assertTrue(metadata["contains_only_sha256_labels_and_metadata"])
            self.assertEqual(ThreatIntelligenceStore(database).lookup(digest)["label"], "malicious")
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), metadata["database_sha256"])
            self.assertTrue(database.with_suffix(".json").is_file())

    def test_build_rejects_tampered_csv_parts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir, csv_dir, _ = self.prepare(root)
            part = next(csv_dir.glob("*.csv"))
            part.write_text(part.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            database = root / "ember2024-starter.sqlite3"
            with self.assertRaises(ValueError):
                build(input_dir, csv_dir, database, split="train", file_type="APK")
            self.assertFalse(database.exists())
            self.assertFalse(database.with_suffix(".json").exists())

    def test_build_rejects_tampered_upstream_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir, csv_dir, _ = self.prepare(root)
            archive = input_dir / ".archives" / "APK_train.zip"
            archive.write_bytes(archive.read_bytes() + b"tampered")
            with self.assertRaises(ValueError):
                build(input_dir, csv_dir, root / "starter.sqlite3", split="train", file_type="APK")


if __name__ == "__main__":
    unittest.main()
