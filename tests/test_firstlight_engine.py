import unittest

from firstlight_engine import (
    append_audit,
    apply_simulated_response,
    create_demo_case,
    investigate_case,
    seal_evidence,
    verify_audit_chain,
    verify_evidence,
)


class FirstlightEngineTests(unittest.TestCase):
    def setUp(self):
        self.case = create_demo_case()
        self.evidence = [seal_evidence(event) for event in self.case["events"]]

    def test_evidence_verifies_and_tampering_is_detected(self):
        item = self.evidence[0]
        self.assertTrue(verify_evidence(item)["valid"])
        item["record"]["summary"] += " tampered"
        self.assertFalse(verify_evidence(item)["valid"])

    def test_evidence_id_cannot_be_swapped_outside_the_hashed_record(self):
        item = dict(self.evidence[0])
        item["evidence_id"] = "EV-SUBSTITUTED"
        result = verify_evidence(item)
        self.assertFalse(result["valid"])
        self.assertIn("MISMATCH", result["status"])

    def test_malformed_evidence_record_fails_closed(self):
        item = {"evidence_id": "EV-001", "record": "not-an-object", "sha256": "abc"}
        result = verify_evidence(item)
        self.assertFalse(result["valid"])
        self.assertFalse(verify_evidence(None)["valid"])

    def test_findings_reference_evidence(self):
        result = investigate_case(self.case, self.evidence)
        self.assertGreaterEqual(len(result["findings"]), 3)
        known = {item["evidence_id"] for item in self.evidence}
        for finding in result["findings"]:
            self.assertTrue(set(finding["evidence_ids"]).issubset(known))
            self.assertIn("explanation", finding)

    def test_timeline_sorts_by_instant_across_timezones(self):
        events = [dict(event) for event in self.case["events"]]
        events[0]["timestamp"] = "2026-10-10T09:00:00+02:00"
        events[1]["timestamp"] = "2026-10-10T08:00:00Z"
        evidence = [seal_evidence(event) for event in events]
        timeline = investigate_case(self.case, evidence)["timeline"]
        self.assertEqual(timeline[0]["event_id"], "EV-001")
        self.assertEqual(timeline[1]["event_id"], "EV-002")

    def test_audit_chain_detects_modification(self):
        chain = append_audit([], "created", "tester", {"case": "demo"})
        chain = append_audit(chain, "collected", "tester", {"evidence": "EV-001"})
        self.assertTrue(verify_audit_chain(chain))
        chain[0]["payload"]["case"] = "altered"
        self.assertFalse(verify_audit_chain(chain))

    def test_response_is_simulated_and_requires_explicit_approval(self):
        result = investigate_case(self.case, self.evidence)
        proposals, rejected = apply_simulated_response(result["response_proposals"], "ACT-001", False, "reviewer")
        self.assertEqual(rejected["status"], "rejected")
        proposals, approved = apply_simulated_response(proposals, "ACT-002", True, "reviewer")
        self.assertEqual(approved["status"], "simulated_success")
        self.assertTrue(approved["simulated"])
        self.assertIn("No real", approved["message"])

    def test_non_boolean_approval_fails_closed(self):
        result = investigate_case(self.case, self.evidence)
        proposals, outcome = apply_simulated_response(
            result["response_proposals"], "ACT-001", "true", "reviewer"
        )
        self.assertEqual(outcome["status"], "rejected")
        self.assertEqual(proposals[0]["status"], "rejected")

    def test_malformed_audit_entries_fail_closed(self):
        self.assertFalse(verify_audit_chain([None]))
        self.assertFalse(verify_audit_chain([{"previous_hash": "GENESIS"}]))
        self.assertFalse(verify_audit_chain(None))
        cyclic = {}
        cyclic["self"] = cyclic
        self.assertFalse(verify_audit_chain([{
            "previous_hash": "GENESIS",
            "payload": cyclic,
            "entry_hash": "not-a-valid-hash",
        }]))

    def test_unknown_action_fails_closed(self):
        with self.assertRaises(ValueError):
            apply_simulated_response([], "ACT-404", True, "reviewer")
        with self.assertRaises(ValueError):
            apply_simulated_response(None, "ACT-001", True, "reviewer")
        with self.assertRaises(ValueError):
            apply_simulated_response([None], "ACT-001", True, "reviewer")

    def test_approver_label_is_bounded(self):
        result = investigate_case(self.case, self.evidence)
        _, outcome = apply_simulated_response(
            result["response_proposals"], "ACT-001", True, "x" * 500
        )
        self.assertEqual(len(outcome["approver"]), 128)


if __name__ == "__main__":
    unittest.main()
