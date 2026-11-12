"""Regression for the isolated, fixture-only Track 1 pipeline."""
from __future__ import annotations

import unittest

from scripts.firstlight_track1_demo import run_demo


class FirstlightTrack1ScenarioTests(unittest.TestCase):
    def test_complete_synthetic_investigation_pipeline(self):
        report = run_demo()

        self.assertEqual(report["input"]["records_ingested"], 5)
        self.assertEqual(report["input"]["records_rejected"], 0)
        self.assertGreaterEqual(report["detection"]["finding_count"], 3)
        self.assertEqual(report["evidence_integrity"]["checked"], 5)
        self.assertEqual(report["evidence_integrity"]["valid"], 5)
        self.assertEqual(report["evidence_integrity"]["invalid_ids"], [])
        self.assertTrue(report["audit"]["valid_hash_chain"])
        self.assertNotIn("response", report)
        self.assertTrue(all(item["evidence_ids"] for item in report["detection"]["findings"]))
        self.assertTrue(all(item["explanation"] for item in report["detection"]["findings"]))
        self.assertTrue(report["limitations"])

    def test_fixture_report_is_not_a_production_response_record(self):
        report = run_demo()
        serialized = str(report).lower()
        self.assertNotIn("response", report)
        self.assertIn("fictional", serialized)
        self.assertIn("no response action changed a real system", serialized)


if __name__ == "__main__":
    unittest.main()
