import tempfile
import unittest
from pathlib import Path
import zipfile

from scripts.download_ember2024 import archive_url, safe_extract_zip, selected_archives

class EmberDownloadTests(unittest.TestCase):
    def test_archive_urls_are_public_direct_file_urls(self):
        self.assertEqual(
            archive_url("APK_train.zip"),
            "https://huggingface.co/datasets/joyce8/EMBER2024/resolve/main/APK_train.zip",
        )

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

if __name__ == "__main__":
    unittest.main()
