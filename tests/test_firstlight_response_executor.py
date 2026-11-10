from datetime import datetime, timedelta, timezone
import sqlite3
import unittest

from firstlight_response_executor import ResponseExecutionError, ResponseLedger


class Clock:
    def __init__(self):
        self.value = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.value


class ResponseLedgerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.ledger = ResponseLedger(":memory:", clock=self.clock)
        self.approval = self.ledger.create_approval(
            tenant_id="tenant-a", case_id="case-a", requested_by="analyst-a",
            action="wazuh.block_ip", target="001",
            reason="Case case-a: verified suspicious activity", payload={"ip_address": "203.0.113.42"},
            idempotency_key="idem-0000000000000001", expires_in_seconds=600,
        )

    def tearDown(self):
        self.ledger.close()

    def approve(self):
        return self.ledger.decide(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                                  decided_by="approver-b", approve=True, decision_reason="Reviewed evidence")

    def test_four_eyes_prevents_self_approval(self):
        with self.assertRaisesRegex(ResponseExecutionError, "requester cannot"):
            self.ledger.decide(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                               decided_by="analyst-a", approve=True, decision_reason="self")
        self.assertEqual(self.ledger.get_approval(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a").status, "pending")

    def test_cross_tenant_or_case_cannot_read_or_decide(self):
        with self.assertRaisesRegex(ResponseExecutionError, "not found"):
            self.ledger.get_approval(self.approval.approval_id, tenant_id="tenant-b", case_id="case-a")
        with self.assertRaisesRegex(ResponseExecutionError, "not found"):
            self.ledger.decide(self.approval.approval_id, tenant_id="tenant-a", case_id="case-b",
                               decided_by="approver-b", approve=True, decision_reason="wrong case")

    def test_payload_allowlist_and_idempotency(self):
        with self.assertRaisesRegex(ResponseExecutionError, "payload"):
            self.ledger.create_approval(tenant_id="tenant-a", case_id="case-a", requested_by="analyst-a",
                action="wazuh.block_ip", target="001", reason="reason", payload={"shell": "bad"},
                idempotency_key="idem-0000000000000002")
        with self.assertRaisesRegex(ResponseExecutionError, "idempotency"):
            self.ledger.create_approval(tenant_id="tenant-a", case_id="case-a", requested_by="analyst-a",
                action="wazuh.disable_account", target="001", reason="reason", payload={"username": "lab-user"},
                idempotency_key="idem-0000000000000001")

    def test_expired_approval_cannot_execute(self):
        self.approve()
        self.clock.value += timedelta(minutes=11)
        with self.assertRaisesRegex(ResponseExecutionError, "expired"):
            self.ledger.execute_approved(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                                         executor_id="executor-c", handler=lambda _: self.fail("must not call handler"))
        self.assertEqual(self.ledger.get_approval(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a").status, "expired")

    def test_execution_is_single_claim_and_submission_is_not_verification(self):
        self.approve()
        calls = []
        outcome = self.ledger.execute_approved(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            executor_id="executor-c", handler=lambda item: calls.append(item) or {"status": "submitted", "provider_reference": "action-123", "detail": "accepted"})
        self.assertEqual(outcome.status, "submitted")
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.ledger.get_approval(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a").status, "submitted")
        with self.assertRaisesRegex(ResponseExecutionError, "Only an approved"):
            self.ledger.execute_approved(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                                         executor_id="executor-c", handler=lambda _: self.fail("must not retry"))
        verified = self.ledger.record_verification(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            verifier_id="verifier-d", status="verified", provider_reference="action-123", detail="Provider state independently checked")
        self.assertEqual(verified.status, "verified")

    def test_legacy_action_without_executor_identity_fails_closed(self):
        self.approve()
        self.ledger.execute_approved(
            self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            executor_id="executor-c",
            handler=lambda _: {"status": "submitted", "provider_reference": "action-legacy", "detail": "accepted"},
        )
        self.ledger._db.execute(
            "UPDATE response_approvals SET executor_id=NULL WHERE approval_id=?",
            (self.approval.approval_id,),
        )
        with self.assertRaisesRegex(ResponseExecutionError, "legacy action"):
            self.ledger.record_verification(
                self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                verifier_id="independent-reviewer", status="verified",
                provider_reference="action-legacy", detail="must be reconciled manually",
            )

    def test_verification_requires_independent_identity(self):
        self.approve()
        self.ledger.execute_approved(
            self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            executor_id="executor-c",
            handler=lambda _: {"status": "submitted", "provider_reference": "action-independent", "detail": "accepted"},
        )
        for identity in ("analyst-a", "approver-b", "executor-c"):
            with self.subTest(identity=identity):
                with self.assertRaisesRegex(ResponseExecutionError, "Independent verification"):
                    self.ledger.record_verification(
                        self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                        verifier_id=identity, status="verified", provider_reference="action-independent",
                        detail="must be independently verified",
                    )
        verified = self.ledger.record_verification(
            self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            verifier_id="independent-reviewer", status="verified", provider_reference="action-independent",
            detail="Provider state checked independently",
        )
        self.assertEqual(verified.status, "verified")

    def test_ambiguous_provider_exception_is_unknown_and_not_retried(self):
        self.approve()
        outcome = self.ledger.execute_approved(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            executor_id="executor-c", handler=lambda _: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(outcome.status, "unknown")
        with self.assertRaisesRegex(ResponseExecutionError, "Only an approved"):
            self.ledger.execute_approved(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                                         executor_id="executor-c", handler=lambda _: self.fail("must not retry"))
        self.ledger.record_verification(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            verifier_id="verifier-d", status="failed", provider_reference="action-123", detail="Provider shows no action")
        self.assertEqual(self.ledger.get_approval(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a").status, "failed")

    def test_audit_chain_verifies_and_events_are_append_only(self):
        self.approve()
        self.assertTrue(self.ledger.verify_audit_chain())
        events = self.ledger.list_audit_events(tenant_id="tenant-a", case_id="case-a")
        self.assertEqual([e["event_type"] for e in events], ["approval.requested", "approval.approved"])
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._db.execute("UPDATE response_audit_events SET event_type='tampered' WHERE sequence=1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._db.execute("DELETE FROM response_audit_events WHERE sequence=1")
        self.assertTrue(self.ledger.verify_audit_chain())

    def test_restart_recovery_marks_in_flight_action_unknown_without_retry(self):
        self.approve()
        self.ledger._db.execute("UPDATE response_approvals SET status='executing' WHERE approval_id=?", (self.approval.approval_id,))
        self.assertEqual(self.ledger.recover_interrupted_executions(), 1)
        current = self.ledger.get_approval(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a")
        self.assertEqual(current.status, "unknown")
        self.assertEqual(self.ledger.recover_interrupted_executions(), 0)
        with self.assertRaisesRegex(ResponseExecutionError, "Only an approved"):
            self.ledger.execute_approved(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                                         executor_id="executor-c", handler=lambda _: self.fail("must not retry"))
        self.assertTrue(self.ledger.verify_audit_chain())

    def test_approved_action_binding_cannot_be_mutated_after_creation(self):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "binding is immutable"):
            self.ledger._db.execute(
                "UPDATE response_approvals SET target='different-device' WHERE approval_id=?",
                (self.approval.approval_id,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "binding is immutable"):
            self.ledger._db.execute(
                "UPDATE response_approvals SET payload_json='{}' WHERE approval_id=?",
                (self.approval.approval_id,),
            )
        self.assertEqual(self.ledger.get_approval(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a").target, "001")

    def test_denial_is_terminal(self):
        denied = self.ledger.decide(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
            decided_by="approver-b", approve=False, decision_reason="Insufficient evidence")
        self.assertEqual(denied.status, "denied")
        with self.assertRaisesRegex(ResponseExecutionError, "Only an approved"):
            self.ledger.execute_approved(self.approval.approval_id, tenant_id="tenant-a", case_id="case-a",
                                         executor_id="executor-c", handler=lambda _: self.fail("must not call"))


if __name__ == "__main__":
    unittest.main()
