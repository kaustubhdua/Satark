from __future__ import annotations

import hashlib
import json

from firstlight_investigation_worker import InvestigationJobWorker

TENANT = "11111111-1111-4111-8111-111111111111"
CASE = "22222222-2222-4222-8222-222222222222"
ACTOR = "33333333-3333-4333-8333-333333333333"
JOB = "44444444-4444-4444-8444-444444444444"


def _event():
    record = {
        "event_id": "wazuh-alert-1",
        "timestamp": "2026-10-20T08:00:00Z",
        "source": "Wazuh",
        "kind": "authentication",
        "summary": "Successful login from a new source",
        "details": {"account": "analyst@example.test", "source_ip": "192.0.2.10", "result": "success", "novel_source": True},
    }
    browser_digest = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return {
        "id": "55555555-5555-4555-8555-555555555555",
        "tenant_id": TENANT, "case_id": CASE,
        "source_label": "Wazuh", "event_kind": "authentication",
        "observed_at": "2026-10-20T08:00:00Z",
        "summary": "Successful login from a new source",
        "source_sha256": "a" * 64, "record_sha256": "b" * 64,
        "metadata": {
            "local_evidence_id": "wazuh-alert-1", "browser_event_timestamp": "2026-10-20T08:00:00Z",
            "browser_record_sha256": browser_digest,
            "source_details": {"account": "analyst@example.test", "source_ip": "192.0.2.10", "result": "success", "novel_source": True},
        },
        "created_at": "2026-10-20T08:01:00Z",
    }


class FakeRest:
    def __init__(self, *, member=True, evidence=None):
        self.member = member
        self.evidence = [_event()] if evidence is None else evidence
        self.finished = []
        self.findings = []
        self.reports = []
        self.job = {"id": JOB, "tenant_id": TENANT, "case_id": CASE, "requested_by": ACTOR,
                    "attempts": 1, "max_attempts": 3, "run_version": "1.0"}
    def request(self, method, table, *, query=None, body=None, prefer=None):
        if method == "POST" and table == "rpc/satark_claim_investigation_job":
            return [self.job]
        if method == "POST" and table == "rpc/satark_finish_investigation_job":
            self.finished.append(body)
            return [body]
        if method == "GET" and table == "satark_cases":
            return [{"id": CASE, "tenant_id": TENANT, "title": "Test incident", "status": "open"}]
        if method == "GET" and table == "satark_memberships":
            return [{"tenant_id": TENANT, "user_id": ACTOR, "role": "analyst"}] if self.member else []
        if method == "GET" and table == "satark_evidence":
            return self.evidence
        if method == "POST" and table == "satark_findings":
            self.findings.append(body); return None
        if method == "POST" and table == "satark_reports":
            self.reports.append(body); return None
        raise AssertionError((method, table, query, body))


def test_worker_claims_persists_deterministic_result_findings_and_report():
    rest = FakeRest()
    outcome = InvestigationJobWorker(rest).run_once()
    assert outcome["status"] == "succeeded"
    assert outcome["job_id"] == JOB
    assert len(outcome["result_sha256"]) == 64
    assert rest.finished[0]["p_status"] == "succeeded"
    result = rest.finished[0]["p_result"]
    assert result["case_id"] == CASE
    assert result["evidence_count"] == 1
    assert result["investigation"]["status"] if "status" in result["investigation"] else result["investigation"]["orchestrator"]["status"] == "completed"
    assert rest.reports[0]["snapshot_sha256"] == rest.finished[0]["p_result_sha256"]
    assert rest.reports[0]["created_by"] == ACTOR


def test_worker_fails_closed_if_requester_lost_case_membership():
    rest = FakeRest(member=False)
    outcome = InvestigationJobWorker(rest).run_once()
    assert outcome["status"] == "failed"
    assert outcome["error_code"] == "requester_not_member"
    assert rest.finished[0]["p_status"] == "queued"


def test_worker_does_not_claim_when_queue_is_empty():
    class Empty(FakeRest):
        def request(self, method, table, *, query=None, body=None, prefer=None):
            if table == "rpc/satark_claim_investigation_job":
                return []
            return super().request(method, table, query=query, body=body, prefer=prefer)
    assert InvestigationJobWorker(Empty()).run_once() == {"status": "idle"}
