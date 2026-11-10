import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate_file_guard import evaluate_csv
from file_guard.engine import scan_bytes
from file_guard.report import build_evidence_report, verify_evidence_report
from file_guard.history import ScanHistory


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


class AuditChainTests(unittest.TestCase):
    def test_hash_chained_history_verifies_and_links_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = ScanHistory(Path(tmp) / "history.sqlite3")
            first = history.add(scan_bytes(b"first", "first.bin"))
            second = history.add(scan_bytes(b"second", "second.bin"))
            self.assertEqual(first["audit_chain"]["sequence"], 1)
            self.assertEqual(second["audit_chain"]["sequence"], 2)
            self.assertEqual(
                second["audit_chain"]["previous_entry_sha256"],
                first["audit_chain"]["entry_sha256"],
            )
            self.assertTrue(verify_evidence_report(first))
            self.assertTrue(verify_evidence_report(second))
            verified = history.verify_audit_chain()
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["entries"], 2)
            self.assertEqual(verified["verified_reports"], 2)

    def test_audit_verification_detects_report_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.sqlite3"
            history = ScanHistory(path)
            history.add(scan_bytes(b"first", "first.bin"))
            with sqlite3.connect(path) as db:
                row = db.execute("SELECT id, report_json FROM scan_history LIMIT 1").fetchone()
                report = json.loads(row[1])
                report["assessment"]["verdict"] = "Safe"
                db.execute("UPDATE scan_history SET report_json=? WHERE id=?",
                           (json.dumps(report), row[0]))
            verified = history.verify_audit_chain()
            self.assertFalse(verified["valid"])
            self.assertEqual(verified["reason"], "report_digest_mismatch")

    def test_clearing_history_resets_the_local_audit_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = ScanHistory(Path(tmp) / "history.sqlite3")
            history.add(scan_bytes(b"first", "first.bin"))
            history.clear()
            verified = history.verify_audit_chain()
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["entries"], 0)
            next_report = history.add(scan_bytes(b"second", "second.bin"))
            self.assertEqual(next_report["audit_chain"]["sequence"], 1)


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
