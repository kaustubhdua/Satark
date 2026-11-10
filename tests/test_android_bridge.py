"""Exercise the exact Python bridge embedded by the Android Chaquopy app."""
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ANDROID_PYTHON = Path(__file__).resolve().parents[1] / "android/app/src/main/python"
sys.path.insert(0, str(ANDROID_PYTHON))
android_bridge = importlib.import_module("android_bridge")


class AndroidBridgeTests(unittest.TestCase):
    def test_local_import_scan_history_and_clear_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = b"%PDF-1.7 /OpenAction /JavaScript bridge fixture"
            digest = hashlib.sha256(payload).hexdigest()
            csv_data = ("sha256,label,family,file_type,dataset_date\n" +
                        digest + ",malicious,fixture,PDF,2024-12-14\n").encode("utf-8")

            imported = json.loads(android_bridge.import_csv_snapshot(
                csv_data, "EMBER2024-test-snapshot", tmp
            ))
            self.assertEqual(imported["import"]["inserted"], 1)
            self.assertEqual(imported["stats"]["total"], 1)

            scanned = json.loads(android_bridge.scan_shared_file(payload, "sample.pdf", tmp))
            self.assertEqual(scanned["verdict"], "Known threat")
            self.assertFalse(scanned["content_extracted"])
            self.assertFalse(scanned["executed"])
            self.assertEqual(scanned["intelligence_match"]["dataset_date"], "2024-12-14")
            self.assertEqual(scanned["builtin_matches"][0]["rule_id"], "PDF_OPENACTION_JAVASCRIPT")

            history = json.loads(android_bridge.scan_history(tmp))
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["sha256"], digest)
            self.assertNotIn("content", history[0])
            self.assertEqual(history[0]["evidence_report"]["agent_trace"][0]["agent"], "file_router")

            report = json.loads(android_bridge.export_scan_report(tmp))
            self.assertEqual(report["product"], "SATARK File Guard")
            self.assertEqual(report["records"][0]["sha256"], digest)
            self.assertEqual(report["processing"], "local_offline")
            self.assertNotIn("content", report["records"][0])

            stats = json.loads(android_bridge.scan_stats(tmp))
            self.assertEqual(stats["malicious"], 1)
            self.assertEqual(stats["benign"], 0)

            android_bridge.clear_scan_history(tmp)
            android_bridge.clear_intelligence(tmp)
            self.assertEqual(json.loads(android_bridge.scan_history(tmp)), [])
            self.assertEqual(json.loads(android_bridge.scan_stats(tmp))["total"], 0)


if __name__ == "__main__":
    unittest.main()
