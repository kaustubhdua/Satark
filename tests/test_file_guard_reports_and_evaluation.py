import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate_file_guard import evaluate_csv
from file_guard.engine import scan_bytes
from file_guard.report import build_evidence_report, verify_evidence_report


class EvidenceReportTests(unittest.TestCase):
    def test_report_is_metadata_only_and_digest_verifies(self):
        result = scan_bytes(b"%PDF-1.7 PRIVATE-DOCUMENT-BODY", "sample.pdf")
        report = build_evidence_report(result, scanned_at="2026-11-10T12:00:00+00:00")
        self.assertEqual(report["report_schema"], "satark.file-guard.evidence/v1")
        self.assertEqual(report["file"]["sha256"], result.sha256)
        self.assertEqual(report["verdict"], result.verdict)
        self.assertFalse(report["processing"]["semantic_content_extracted"])
        self.assertFalse(report["processing"]["file_executed"])
        self.assertTrue(verify_evidence_report(report))
        self.assertNotIn("PRIVATE-DOCUMENT-BODY", json.dumps(report))

    def test_report_detects_tampering(self):
        report = build_evidence_report(scan_bytes(b"hello", "hello.bin"))
        report["assessment"]["verdict"] = "Safe"
        self.assertFalse(verify_evidence_report(report))

    def test_report_requires_sha256(self):
        with self.assertRaises(ValueError):
            build_evidence_report({"sha256": "not-a-hash"})


class EvaluationTests(unittest.TestCase):
    def test_metrics_and_abstentions_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "labels.csv"
            path.write_text(
                "expected,predicted\nmalicious,malicious\nbenign,malicious\n"
                "benign,benign\nmalicious,unknown\n",
                encoding="utf-8",
            )
            report = evaluate_csv(path)
        self.assertEqual(report["samples"], 4)
        self.assertEqual(report["abstained"], 1)
        self.assertEqual(report["abstained_malicious"], 1)
        self.assertAlmostEqual(report["precision"], 0.5)
        self.assertAlmostEqual(report["recall_conservative"], 0.5)
        self.assertAlmostEqual(report["coverage"], 0.75)
        self.assertAlmostEqual(report["detection_coverage"], 0.75)
        self.assertAlmostEqual(report["false_positive_rate"], 0.5)

    def test_invalid_label_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            path.write_text("expected,predicted\nmalicious,safe\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                evaluate_csv(path)


if __name__ == "__main__":
    unittest.main()
