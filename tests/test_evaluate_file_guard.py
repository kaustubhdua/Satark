import csv
import hashlib
import tempfile
import unittest
from pathlib import Path

from file_guard.intelligence import ThreatIntelligenceStore
from scripts.evaluate_file_guard import calculate_metrics, evaluate


class EvaluationTests(unittest.TestCase):
    def test_metrics_calculate_precision_recall_and_false_positive_rate(self):
        rows = [
            {"actual": "malicious", "predicted_malicious": True},
            {"actual": "malicious", "predicted_malicious": False},
            {"actual": "benign", "predicted_malicious": True},
            {"actual": "benign", "predicted_malicious": False},
        ]
        metrics = calculate_metrics(rows)
        self.assertEqual(metrics["true_positive"], 1)
        self.assertEqual(metrics["false_positive"], 1)
        self.assertEqual(metrics["true_negative"], 1)
        self.assertEqual(metrics["false_negative"], 1)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["false_positive_rate"], 0.5)
        self.assertEqual(metrics["false_negative_rate"], 0.5)

    def test_local_corpus_evaluation_and_unscanned_file_reporting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            samples = root / "samples"
            samples.mkdir()
            malicious = b"%PDF-1.7 known fixture"
            (samples / "known.pdf").write_bytes(malicious)
            (samples / "clean.pdf").write_bytes(b"%PDF-1.7 clean fixture")
            (samples / "mismatch.pdf").write_bytes(b"MZ" + bytes(32))
            (samples / "missing.pdf").unlink(missing_ok=True)

            digest = hashlib.sha256(malicious).hexdigest()
            database = ThreatIntelligenceStore(root / "intel.sqlite3")
            database.import_csv(
                __import__("io").StringIO(f"sha256,label\\n{digest},malicious\\n"),
                "training-snapshot",
            )
            labels = root / "labels.csv"
            with labels.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(["path", "label"])
                writer.writerow(["known.pdf", "malicious"])
                writer.writerow(["clean.pdf", "benign"])
                writer.writerow(["mismatch.pdf", "benign"])
                writer.writerow(["missing.pdf", "malicious"])

            report = evaluate(samples, labels, database)
            self.assertEqual(report["metrics"]["true_positive"], 1)
            self.assertEqual(report["metrics"]["true_negative"], 1)
            self.assertEqual(report["metrics"]["false_positive"], 1)
            self.assertEqual(report["metrics"]["false_negative"], 0)
            self.assertEqual(len(report["errors"]), 1)
            self.assertEqual(report["by_detected_type"]["PDF"]["evaluated"], 2)
            self.assertEqual(report["by_detected_type"]["Windows executable"]["evaluated"], 1)

    def test_rejects_paths_outside_the_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            samples = root / "samples"
            samples.mkdir()
            labels = root / "labels.csv"
            labels.write_text("path,label\\n../outside.pdf,benign\\n", encoding="utf-8")
            database = ThreatIntelligenceStore(root / "intel.sqlite3")
            report = evaluate(samples, labels, database)
            self.assertEqual(report["results"], [])
            self.assertEqual(report["errors"][0]["error"], "ValueError")


if __name__ == "__main__":
    unittest.main()
