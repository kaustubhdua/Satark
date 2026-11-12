import unittest
from datetime import datetime, timezone

from firstlight_engine import (
    append_audit,
    investigate_case,
    prioritize_evidence,
    seal_evidence,
    verify_audit_chain,
    verify_evidence,
)


class FirstlightEngineTests(unittest.TestCase):
    def setUp(self):
        # Explicit test-only evidence fixture; production never seeds these records.
        self.case = {"case_id": "UNIT-CASE-001", "title": "Unit-test evidence fixture", "status": "investigating", "severity": "unknown"}
        self.events = [
            {"event_id": "UNIT-001", "timestamp": "2026-10-10T09:15:00Z", "source": "identity", "kind": "authentication", "summary": "Successful login from an unfamiliar source", "details": {"result": "success", "novel_source": True, "account": "analyst@example.test"}},
            {"event_id": "UNIT-002", "timestamp": "2026-10-10T09:19:00Z", "source": "endpoint", "kind": "process", "summary": "Unusual script interpreter launched", "details": {"process": "powershell.exe", "parent": "outlook.exe", "host": "UNIT-HOST-01"}},
            {"event_id": "UNIT-003", "timestamp": "2026-10-10T09:22:00Z", "source": "network", "kind": "connection", "summary": "Endpoint connected to a suspicious destination", "details": {"destination": "example.invalid", "host": "UNIT-HOST-01"}},
            {"event_id": "UNIT-004", "timestamp": "2026-10-10T09:26:00Z", "source": "filesystem", "kind": "file", "summary": "Archive created in a temporary directory", "details": {"path": "/tmp/unit-archive.zip"}},
            {"event_id": "UNIT-005", "timestamp": "2026-10-10T09:30:00Z", "source": "identity", "kind": "session", "summary": "A second session was issued", "details": {"account": "analyst@example.test"}},
        ]
        self.evidence = [seal_evidence(event) for event in self.events]

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

    def test_investigate_case_rejects_malformed_case_and_evidence_container(self):
        for malformed_case in (None, [], {}, {"case_id": ""}, {"case_id": None}):
            with self.subTest(case=malformed_case):
                with self.assertRaises(ValueError):
                    investigate_case(malformed_case, self.evidence)
        for malformed_evidence in (None, {}, "not-a-list"):
            with self.subTest(evidence=malformed_evidence):
                with self.assertRaises(ValueError):
                    investigate_case(self.case, malformed_evidence)

    def test_investigate_case_ignores_malformed_items_inside_evidence_list(self):
        result = investigate_case(self.case, [None, "bad-record", *self.evidence])
        self.assertEqual(result["case_id"], self.case["case_id"])
        self.assertTrue(result["timeline"])

    def test_findings_reference_evidence(self):
        result = investigate_case(self.case, self.evidence)
        self.assertGreaterEqual(len(result["findings"]), 3)
        known = {item["evidence_id"] for item in self.evidence}
        for finding in result["findings"]:
            self.assertTrue(set(finding["evidence_ids"]).issubset(known))
            self.assertIn("explanation", finding)

    def test_timeline_sorts_by_instant_across_timezones(self):
        events = [dict(event) for event in self.events]
        events[0]["timestamp"] = "2026-10-10T09:00:00+02:00"
        events[1]["timestamp"] = "2026-10-10T08:00:00Z"
        evidence = [seal_evidence(event) for event in events]
        timeline = investigate_case(self.case, evidence)["timeline"]
        self.assertEqual(timeline[0]["event_id"], "EV-001")
        self.assertEqual(timeline[1]["event_id"], "EV-002")

    def test_evidence_priority_uses_volatility_relevance_and_recency(self):
        now = datetime(2026, 10, 10, 9, 30, tzinfo=timezone.utc)
        priorities = prioritize_evidence(self.evidence, now=now)
        self.assertEqual(priorities[0]["evidence_id"], "EV-002")
        self.assertEqual(priorities[0]["priority"], "critical")
        self.assertTrue(any("Volatility" in reason for reason in priorities[0]["reasons"]))
        self.assertTrue(any("Recent source timestamp" in reason for reason in priorities[0]["reasons"]))
        scores = [item["priority_score"] for item in priorities]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_priority_mismatch_is_flagged_for_quarantine_not_trusted(self):
        tampered = dict(self.evidence[0])
        tampered["record"] = dict(tampered["record"], summary="Changed after sealing")
        result = prioritize_evidence([tampered])[0]
        self.assertIn("MISMATCH", result["integrity"])
        self.assertIn("Quarantine", result["recommended_next_step"])
        self.assertTrue(any("Integrity mismatch" in reason for reason in result["reasons"]))

    def test_priority_rejects_invalid_container_and_skips_malformed_items(self):
        with self.assertRaises(ValueError):
            prioritize_evidence(None)
        results = prioritize_evidence([None, {"evidence_id": "broken", "record": "bad"}])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["evidence_id"], "broken")

    def test_investigation_includes_priorities_for_evidence(self):
        result = investigate_case(self.case, self.evidence)
        known = {item["evidence_id"] for item in self.evidence}
        self.assertEqual({item["evidence_id"] for item in result["evidence_priorities"]}, known)
        self.assertTrue(all(item["priority"] in {"critical", "high", "medium", "low"}
                            for item in result["evidence_priorities"]))

    def test_audit_chain_detects_modification(self):
        chain = append_audit([], "created", "tester", {"case": "demo"})
        chain = append_audit(chain, "collected", "tester", {"evidence": "EV-001"})
        self.assertTrue(verify_audit_chain(chain))
        chain[0]["payload"]["case"] = "altered"
        self.assertFalse(verify_audit_chain(chain))

    def test_audit_append_rejects_corrupted_chain_and_invalid_inputs(self):
        chain = append_audit([], "created", "tester", {"case": "demo"})
        corrupted = [dict(chain[0], entry_hash="tampered")]
        for entries, action, actor, payload in (
            (corrupted, "next", "tester", {}),
            (None, "next", "tester", {}),
            ([], "", "tester", {}),
            ([], "next", "", {}),
            ([], "next", "tester", []),
        ):
            with self.subTest(entries=entries, action=action, actor=actor, payload=payload):
                with self.assertRaises(ValueError):
                    append_audit(entries, action, actor, payload)

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

    def test_findings_never_reference_unavailable_or_invalid_evidence(self):
        # Keep only one valid record: findings may retain their explanatory
        # labels, but unsupported references must be removed and uncertainty
        # must be explicit.
        single = [self.evidence[0]]
        result = investigate_case(self.case, single)
        valid_ids = {item["evidence_id"] for item in single}
        for finding in result["findings"]:
            self.assertTrue(set(finding["evidence_ids"]).issubset(valid_ids))
            if not finding["evidence_ids"]:
                self.assertFalse(finding["evidence_available"])
                self.assertEqual(finding["state"], "unverified")
                self.assertEqual(finding["confidence"], "low")

    def test_timeline_places_unparseable_timestamps_last(self):
        events = [dict(event) for event in self.case["events"]]
        events[0]["timestamp"] = "not-a-timestamp"
        evidence = [seal_evidence(event) for event in events]
        result = investigate_case(self.case, evidence)
        self.assertEqual(result["timeline"][-1]["event_id"], events[0]["event_id"])

    def test_audit_chain_rejects_reordered_entries(self):
        chain = append_audit([], "created", "tester", {"case": "demo"})
        chain = append_audit(chain, "reviewed", "tester", {"decision": "reject"})
        self.assertTrue(verify_audit_chain(chain))
        self.assertFalse(verify_audit_chain(list(reversed(chain))))

    def test_findings_are_derived_from_custom_evidence_ids(self):
        events = [
            {"event_id": "CASE-X-1", "timestamp": "2026-10-10T09:00:00Z", "source": "identity", "kind": "authentication", "summary": "Successful login from unfamiliar source", "details": {"result": "success", "novel_source": True, "account": "demo@example.test"}},
            {"event_id": "CASE-X-2", "timestamp": "2026-10-10T09:01:00Z", "source": "endpoint", "kind": "process", "summary": "Script launched", "details": {"process": "powershell.exe", "parent": "outlook.exe", "host": "HOST-X"}},
            {"event_id": "CASE-X-3", "timestamp": "2026-10-10T09:02:00Z", "source": "network", "kind": "connection", "summary": "Suspicious destination contacted", "details": {"destination": "example.invalid", "host": "HOST-X"}},
            {"event_id": "CASE-X-4", "timestamp": "2026-10-10T09:03:00Z", "source": "filesystem", "kind": "file", "summary": "Archive staged in temp", "details": {"path": "/tmp/archive.zip"}},
            {"event_id": "CASE-X-5", "timestamp": "2026-10-10T09:04:00Z", "source": "identity", "kind": "session", "summary": "New session issued", "details": {"account": "demo@example.test"}},
        ]
        case = {"case_id": "CASE-X", "title": "Custom unit-test fixture"}
        evidence = [seal_evidence(event) for event in events]
        result = investigate_case(case, evidence)
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Unfamiliar successful login", titles)
        self.assertIn("Unusual process ancestry", titles)
        self.assertIn("Potentially suspicious network activity", titles)
        self.assertIn("Possible data staging", titles)
        self.assertIn("Follow-on identity session", titles)
        known_ids = {item["evidence_id"] for item in evidence}
        for item in result["findings"]:
            self.assertTrue(set(item["evidence_ids"]).issubset(known_ids))
        self.assertEqual(result["case_id"], "CASE-X")
        self.assertNotIn("response_" + "proposals", result)

    def test_no_matching_rule_is_not_presented_as_a_safety_clearance(self):
        event = {
            "event_id": "CUSTOM-1",
            "timestamp": "2026-10-10T09:00:00Z",
            "source": "application",
            "kind": "notice",
            "summary": "Routine application event",
            "details": {"status": "ok"},
        }
        result = investigate_case({"case_id": "CUSTOM-CASE"}, [seal_evidence(event)])
        self.assertEqual(result["findings"][0]["state"], "unverified")
        self.assertFalse(result["findings"][0]["evidence_available"])
        self.assertIn("not a safety clearance", result["findings"][0]["explanation"])

    def test_agent_trace_is_grounded_in_current_case_and_discloses_deterministic_mode(self):
        custom_events = [
            {
                "event_id": "TRACE-1",
                "timestamp": "2026-10-10T09:00:00Z",
                "source": "identity",
                "kind": "authentication",
                "summary": "Successful login from unfamiliar source",
                "details": {"result": "success", "novel_source": True},
            },
            {
                "event_id": "TRACE-2",
                "timestamp": "2026-10-10T09:03:00Z",
                "source": "endpoint",
                "kind": "process",
                "summary": "Script launched",
                "details": {"process": "powershell.exe", "parent": "outlook.exe"},
            },
        ]
        evidence = [seal_evidence(event) for event in custom_events]
        result = investigate_case({"case_id": "TRACE-CASE"}, evidence)

        self.assertEqual(result["schema_version"], "1.1")
        self.assertFalse(result["orchestrator"]["model_agents_enabled"])
        self.assertEqual(result["orchestrator"]["mode"], "bounded_deterministic")
        self.assertEqual(result["orchestrator"]["agent_count"], len(result["agent_trace"]))
        self.assertEqual(result["agents"], result["agent_trace"])
        self.assertEqual(
            {agent["agent_id"] for agent in result["agent_trace"]},
            {"evidence_integrity", "evidence_triage", "detection_correlation",
             "timeline_reconstruction", "verification"},
        )
        known_ids = {item["evidence_id"] for item in evidence}
        for agent in result["agent_trace"]:
            self.assertEqual(agent["mode"], "deterministic")
            self.assertTrue(set(agent["evidence_ids"]).issubset(known_ids))
            self.assertGreaterEqual(agent["inputs"], 0)
            self.assertGreaterEqual(agent["outputs"], 0)
        detection = next(a for a in result["agent_trace"] if a["agent_id"] == "detection_correlation")
        self.assertEqual(detection["outputs"], len([
            finding for finding in result["findings"]
            if finding["title"] != "No rule matched — analyst review required"
        ]))

if __name__ == "__main__":
    unittest.main()
