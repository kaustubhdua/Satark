from __future__ import annotations

from datetime import datetime, timedelta, timezone

import hashlib
import pytest

from firstlight_wazuh_worker import SupabaseRestError, SupabaseServiceRest, WazuhSupabaseWorker, _retry_delay, _safe_error_code


TENANT = "11111111-1111-4111-8111-111111111111"
CASE = "22222222-2222-4222-8222-222222222222"
ACTOR = "33333333-3333-4333-8333-333333333333"


def event(doc_id: str, timestamp: str):
    import hashlib
    source = {"@timestamp": timestamp, "rule": {"id": "5710", "level": 8, "description": "Lab alert"}}
    digest = hashlib.sha256(__import__("json").dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    snapshot = __import__("json").dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "source_snapshot_json": snapshot,
        "event_id": "wazuh-" + doc_id,
        "timestamp": timestamp,
        "kind": "security_alert",
        "summary": "Lab alert",
        "details": {"index": "wazuh-alerts-*", "document_id": doc_id, "rule_id": "5710", "rule_level": 8,
                    "rule_groups": [], "agent_id": "004", "agent_name": "lab", "manager_name": "mgr",
                    "location": "test", "decoder_name": "test", "data": {}, "source_record_sha256": digest},
        "provenance": {"index": "wazuh-alerts-*", "document_id": doc_id, "source_record_sha256": digest},
    }


class FakeRest:
    def __init__(self):
        self.evidence = {}
        self.checkpoint = None

    def upload_source_snapshot(self, *, tenant_id, case_id, digest, snapshot):
        import hashlib
        assert hashlib.sha256(snapshot.encode("utf-8")).hexdigest() == digest
        return f"{tenant_id}/{case_id}/wazuh/{digest}.json"

    def request(self, method, table, *, query=None, body=None, prefer=None):
        if method == "GET" and table == "satark_cases":
            return [{"id": CASE, "tenant_id": TENANT}]
        if method == "GET" and table == "satark_memberships":
            return [{"tenant_id": TENANT, "user_id": ACTOR, "role": "analyst"}]
        if method == "GET" and table == "satark_ingestion_checkpoints":
            return [self.checkpoint] if self.checkpoint else []
        if method == "POST" and table == "satark_evidence":
            self.evidence.setdefault(body["record_sha256"], body)
            return None
        if method == "POST" and table == "satark_ingestion_checkpoints":
            self.checkpoint = body
            return None
        raise AssertionError(f"unexpected REST request: {method} {table}")


class FakeWazuh:
    class Config:
        index_pattern = "wazuh-alerts-*"
        allowed_agent_ids = ("004",)
    config = Config()

    def __init__(self, events):
        self.events = events
        self.calls = []

    def fetch_alerts(self, *, limit, since, until, offset, include_source_snapshot=False):
        self.calls.append({"limit": limit, "since": since, "until": until, "offset": offset})
        return self.events[offset:offset + limit]


def test_source_snapshot_upload_rejects_objects_over_bucket_limit_before_network_io():
    client = SupabaseServiceRest(
        base_url="https://example.supabase.co",
        service_role_key="x" * 40,
    )
    snapshot = "x" * (4 * 1024 * 1024 + 1)
    digest = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()
    with pytest.raises(SupabaseRestError, match="4 MiB object limit"):
        client.upload_source_snapshot(
            tenant_id=TENANT, case_id=CASE, digest=digest, snapshot=snapshot,
        )


def test_worker_persists_pages_idempotently_and_advances_checkpoint():
    rest = FakeRest()
    now = datetime.now(timezone.utc)
    initial_since = (now - timedelta(minutes=5)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    alerts = [
        event("one", (now - timedelta(seconds=40)).isoformat(timespec="milliseconds").replace("+00:00", "Z")),
        event("two", (now - timedelta(seconds=20)).isoformat(timespec="milliseconds").replace("+00:00", "Z")),
    ]
    wazuh = FakeWazuh(alerts)
    worker = WazuhSupabaseWorker(
        rest=rest, wazuh=wazuh, tenant_id=TENANT, case_id=CASE, actor_id=ACTOR,
        page_size=2, overlap_seconds=60, initial_since=initial_since,
    )
    result = worker.run_once()
    assert result["status"] == "ok"
    assert result["fetched"] == 2
    assert len(rest.evidence) == 2
    first_record = next(iter(rest.evidence.values()))
    assert first_record["metadata"]["persisted_by_worker"] is True
    assert len(first_record["metadata"]["browser_record_sha256"]) == 64
    assert first_record["metadata"]["browser_event_timestamp"].endswith("Z")
    assert first_record["metadata"]["source_object_path"].endswith(".json")
    assert first_record["metadata"]["source_provider"] == "wazuh-indexer"
    assert first_record["metadata"]["source_index"] == "wazuh-alerts-*"
    assert first_record["metadata"]["source_document_id"] in {"one", "two"}
    second = worker.run_once()
    assert second["status"] == "ok"
    assert len(rest.evidence) == 2
    assert rest.checkpoint["last_status"] == "ok"
    assert rest.checkpoint["last_event_timestamp"] == wazuh.calls[-1]["until"]
    assert rest.checkpoint["last_event_timestamp"] > alerts[-1]["timestamp"]
    assert [call["offset"] for call in wazuh.calls] == [0, 2, 0, 2]


def test_worker_advances_checkpoint_after_a_successful_empty_window():
    rest = FakeRest()
    wazuh = FakeWazuh([])
    initial_since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    worker = WazuhSupabaseWorker(
        rest=rest, wazuh=wazuh, tenant_id=TENANT, case_id=CASE, actor_id=ACTOR,
        page_size=10, overlap_seconds=60, initial_since=initial_since,
    )
    result = worker.run_once()
    assert result["status"] == "ok"
    assert result["fetched"] == 0
    assert rest.checkpoint["last_event_timestamp"] == wazuh.calls[0]["until"]
    assert rest.checkpoint["last_event_timestamp"] > initial_since


def test_worker_does_not_advance_checkpoint_when_a_page_fails():
    rest = FakeRest()
    class BrokenWazuh(FakeWazuh):
        def fetch_alerts(self, **kwargs):
            raise RuntimeError("fixture failure")
    worker = WazuhSupabaseWorker(
        rest=rest, wazuh=BrokenWazuh([]), tenant_id=TENANT, case_id=CASE, actor_id=ACTOR,
        page_size=10, initial_since="2026-10-20T07:00:00Z",
    )
    try:
        worker.run_once()
        assert False, "expected failure"
    except RuntimeError as exc:
        assert "fixture failure" in str(exc)
    assert rest.checkpoint["last_status"] == "error"
    assert rest.checkpoint["last_event_timestamp"] == "2026-10-20T07:00:00.000Z"


def test_worker_rejects_missing_authorized_tenant_membership():
    class NoMembership(FakeRest):
        def request(self, method, table, *, query=None, body=None, prefer=None):
            if method == "GET" and table == "satark_memberships":
                return []
            return super().request(method, table, query=query, body=body, prefer=prefer)
    try:
        WazuhSupabaseWorker(
            rest=NoMembership(), wazuh=FakeWazuh([]), tenant_id=TENANT, case_id=CASE, actor_id=ACTOR,
            initial_since="2026-10-20T07:00:00Z",
        )
        assert False, "expected configuration failure"
    except ValueError as exc:
        assert "actor" in str(exc)


def test_source_snapshot_verifier_rejects_cross_case_paths_before_network_io():
    client = SupabaseServiceRest(
        base_url="https://example.supabase.co",
        service_role_key="x" * 40,
    )
    with pytest.raises(SupabaseRestError, match="path or digest is invalid"):
        client.verify_source_snapshot(
            tenant_id=TENANT, case_id=CASE,
            path=f"{TENANT}/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/wazuh/{'a' * 64}.json",
            digest="a" * 64,
        )



def test_worker_error_logging_uses_categories_not_exception_text():
    error = SupabaseRestError("credential=super-secret-token endpoint=https://private.example")
    code = _safe_error_code(error)
    assert code == "supabase_request_error"
    assert "super-secret-token" not in code
    assert "private.example" not in code



def test_wazuh_retry_backoff_is_exponential_and_capped():
    assert [_retry_delay(30, attempt) for attempt in (1, 2, 3, 4)] == [30, 60, 120, 240]
    assert _retry_delay(3600, 3) == 900
    with pytest.raises(ValueError):
        _retry_delay(0, 1)
    with pytest.raises(ValueError):
        _retry_delay(30, 0)

def test_worker_revalidates_actor_membership_before_each_poll():
    class RevocableMembershipRest(FakeRest):
        def __init__(self):
            super().__init__()
            self.membership_allowed = True

        def request(self, method, table, *, query=None, body=None, prefer=None):
            if method == "GET" and table == "satark_memberships" and not self.membership_allowed:
                return []
            return super().request(method, table, query=query, body=body, prefer=prefer)

    rest = RevocableMembershipRest()
    wazuh = FakeWazuh([])
    worker = WazuhSupabaseWorker(
        rest=rest, wazuh=wazuh, tenant_id=TENANT, case_id=CASE, actor_id=ACTOR,
        initial_since="2026-10-20T07:00:00Z",
    )
    # The worker was valid at process startup, but the actor is removed later.
    rest.membership_allowed = False
    with pytest.raises(ValueError, match="actor"):
        worker.run_once()
    assert wazuh.calls == []
    assert rest.checkpoint is None

def test_worker_does_not_persist_a_page_if_membership_is_revoked_during_fetch():
    class RevocableMembershipRest(FakeRest):
        def __init__(self):
            super().__init__()
            self.membership_allowed = True

        def request(self, method, table, *, query=None, body=None, prefer=None):
            if method == "GET" and table == "satark_memberships" and not self.membership_allowed:
                return []
            return super().request(method, table, query=query, body=body, prefer=prefer)

    rest = RevocableMembershipRest()

    class RevokingWazuh(FakeWazuh):
        def fetch_alerts(self, **kwargs):
            page = super().fetch_alerts(**kwargs)
            rest.membership_allowed = False
            return page

    worker = WazuhSupabaseWorker(
        rest=rest, wazuh=RevokingWazuh([event("revoked-during-fetch", "2026-10-20T07:01:00Z")]),
        tenant_id=TENANT, case_id=CASE, actor_id=ACTOR,
        initial_since="2026-10-20T07:00:00Z",
    )
    with pytest.raises(ValueError, match="actor"):
        worker.run_once()
    assert rest.evidence == {}
    assert rest.checkpoint is None

