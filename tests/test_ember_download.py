import tempfile
import unittest
from pathlib import Path
import zipfile

from scripts.download_ember2024 import (
    ARCHIVE_INTEGRITY, DATASET_REVISION, archive_url, safe_extract_zip, selected_archives,
    download_archive,
)
import hashlib
from io import BytesIO
from unittest.mock import patch

class EmberDownloadTests(unittest.TestCase):
    def test_archive_urls_are_public_direct_file_urls(self):
        self.assertEqual(
            archive_url("APK_train.zip"),
            f"https://huggingface.co/datasets/joyce8/EMBER2024/resolve/{DATASET_REVISION}/APK_train.zip",
        )

    def test_archive_integrity_catalog_covers_all_pinned_files(self):
        self.assertEqual(len(ARCHIVE_INTEGRITY), 13)
        for filename, (digest, size) in ARCHIVE_INTEGRITY.items():
            self.assertEqual(len(digest), 64, filename)
            self.assertGreater(size, 0, filename)
        self.assertEqual(DATASET_REVISION, "8cc201a3d2a1cb2957123eb5ad996d5a3178bbcc")

    def test_download_rejects_archive_not_in_pinned_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                download_archive("untrusted.zip", Path(tmp), 1024)

    def test_download_verifies_size_and_sha256_before_publishing_archive(self):
        import zipfile
        with tempfile.TemporaryDirectory() as tmp:
            archive_bytes = BytesIO()
            with zipfile.ZipFile(archive_bytes, "w") as archive:
                archive.writestr("metadata.jsonl", '{"sha256":"' + "a" * 64 + '","label":1}\n')
            payload = archive_bytes.getvalue()
            test_digest = hashlib.sha256(payload).hexdigest()
            response = BytesIO(payload)
            response.headers = {"Content-Length": str(len(payload))}
            response.__enter__ = lambda: response
            response.__exit__ = lambda *_: None
            with patch("scripts.download_ember2024.ARCHIVE_INTEGRITY",
                       {"APK_train.zip": (test_digest, len(payload))}), \
                 patch("scripts.download_ember2024.urlopen", return_value=response):
                target = download_archive("APK_train.zip", Path(tmp), len(payload))
            self.assertTrue(target.is_file())
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), test_digest)
            target.write_bytes(payload + b"tampered")
            with patch("scripts.download_ember2024.ARCHIVE_INTEGRITY",
                       {"APK_train.zip": (test_digest, len(payload))}), \
                 patch("scripts.download_ember2024.urlopen", side_effect=OSError("offline")):
                with self.assertRaises(OSError):
                    download_archive("APK_train.zip", Path(tmp), len(payload))
            self.assertFalse(target.exists())

    def test_selected_archive_expansion(self):
        self.assertEqual(selected_archives("train", "APK"), ["APK_train.zip"])
        self.assertEqual(selected_archives("train", "PE"),
                         ["Win32_train.zip", "Win64_train.zip", "Dot_Net_train.zip"])
        self.assertEqual(selected_archives("challenge", "APK"), ["challenge.zip"])

    def test_safe_extract_and_zip_slip_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "good.zip"
            with zipfile.ZipFile(good, "w") as archive:
                archive.writestr("APK_train_000.jsonl", '{"sha256":"abc"}\n')
            extracted = safe_extract_zip(good, root / "out")
            self.assertEqual(extracted, ["APK_train_000.jsonl"])
            bad = root / "bad.zip"
            with zipfile.ZipFile(bad, "w") as archive:
                archive.writestr("../escape.jsonl", "bad")
            with self.assertRaises(ValueError):
                safe_extract_zip(bad, root / "bad-out")
            backslash = root / "backslash.zip"
            with zipfile.ZipFile(backslash, "w") as archive:
                archive.writestr("..\\outside.jsonl", "bad")
            with self.assertRaises(ValueError):
                safe_extract_zip(backslash, root / "backslash-out")

if __name__ == "__main__":
    unittest.main()
