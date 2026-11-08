from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

import satark_backend as backend
from firstlight_wazuh_worker import WazuhSatarkWorker, WorkerConfigurationError, _retry_delay, _safe_error_code


TENANT = "11111111-1111-4111-8111-111111111111"
CASE = "22222222-2222-4222-8222-222222222222"
ACTOR = "33333333-3333-4333-8333-333333333333"


@pytest.fixture()
def database(monkeypatch, tmp_path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    backend.SessionLocal.configure(bind=engine)
    backend.Base.metadata.drop_all(engine)
    backend.Base.metadata.create_all(engine)
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    db = backend.SessionLocal()
    user = backend.User(id=ACTOR, email="wazuh@example.test", password_hash="test-only")
    db.add(user)
    db.flush()
    db.add(backend.Tenant(id=TENANT, name="Wazuh Lab", created_by=ACTOR))
    db.flush()
    db.add(backend.Membership(tenant_id=TENANT, user_id=ACTOR, role="analyst"))
    db.add(backend.Case(id=CASE, tenant_id=TENANT, title="Wazuh test case", created_by=ACTOR))
    db.commit()
    db.close()
    yield tmp_path / "evidence"
    backend.Base.metadata.drop_all(engine)
    engine.dispose()


def event(doc_id: str, timestamp: str):
    source = {"@timestamp": timestamp, "_id": doc_id, "rule": {"id": "5710", "level": 8, "description": "Lab alert"}}
    snapshot = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(snapshot.encode()).hexdigest()
    return {
        "source_snapshot_json": snapshot,
        "event_id": "wazuh-" + doc_id,
        "timestamp": timestamp,
        "kind": "security_alert",
        "summary": "Lab alert",
        "details": {"index": "wazuh-alerts-*", "document_id": doc_id, "rule_id": "5710", "rule_level": 8,
                    "rule_groups": ["authentication_failed"], "agent_id": "004", "agent_name": "lab",
                    "manager_name": "mgr", "location": "test", "decoder_name": "test", "data": {},
                    "source_record_sha256": digest},
        "provenance": {"index": "wazuh-alerts-*", "document_id": doc_id, "source_record_sha256": digest},
    }


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


def seed_worker(wazuh, **kwargs):
    return WazuhSatarkWorker(
        wazuh=wazuh, tenant_id=TENANT, case_id=CASE, actor_id=ACTOR,
        initial_since="2026-10-20T07:00:00Z", **kwargs,
    )


def test_worker_persists_private_source_snapshot_evidence_and_checkpoint(database):
    timestamp = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    wazuh = FakeWazuh([event("one", timestamp), event("two", timestamp)])
    worker = seed_worker(wazuh, page_size=2, overlap_seconds=60)
    result = worker.run_once()
    assert result["status"] == "ok"
    assert result["fetched"] == 2
    assert result["persisted"] == 2

    db = backend.SessionLocal()
    rows = db.scalars(select(backend.Evidence).where(
        backend.Evidence.tenant_id == TENANT, backend.Evidence.case_id == CASE
    )).all()
    assert len(rows) == 2
    first = rows[0]
    assert first.source_label == "Wazuh"
    assert first.content_type == "application/json"
    assert first.metadata_json["provider"] == "wazuh-indexer"
    assert len(first.metadata_json["browser_record_sha256"]) == 64
    assert first.metadata_json["source_snapshot_preserved"] is True
    assert first.metadata_json["source_object_path"].endswith(".json")
    raw = open(first.object_key, "rb").read()
    assert hashlib.sha256(raw).hexdigest() == first.source_sha256
    checkpoint = db.scalar(select(backend.IngestionCheckpoint))
    assert checkpoint.last_status == "ok"
    assert checkpoint.last_batch_count == 2
    assert db.scalar(select(backend.AuditEvent).where(
        backend.AuditEvent.event_type == "wazuh.evidence.ingested"
    )) is not None
    db.close()


def test_worker_is_idempotent_when_overlapping_wazuh_window_replays_events(database):
    timestamp = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    wazuh = FakeWazuh([event("replay", timestamp)])
    worker = seed_worker(wazuh, page_size=10, overlap_seconds=300)
    assert worker.run_once()["fetched"] == 1
    replay = worker.run_once()
    assert replay["fetched"] == 1
    assert replay["persisted"] == 0
    db = backend.SessionLocal()
    assert len(db.scalars(select(backend.Evidence)).all()) == 1
    db.close()


def test_worker_advances_checkpoint_after_empty_window(database):
    worker = seed_worker(FakeWazuh([]), page_size=10)
    result = worker.run_once()
    assert result["status"] == "ok"
    assert result["fetched"] == 0
    db = backend.SessionLocal()
    checkpoint = db.scalar(select(backend.IngestionCheckpoint))
    assert checkpoint is not None
    checkpoint_time = checkpoint.last_event_timestamp
    if checkpoint_time.tzinfo is None:
        checkpoint_time = checkpoint_time.replace(tzinfo=timezone.utc)
    assert checkpoint_time > datetime(2026, 10, 20, tzinfo=timezone.utc)
    db.close()


def test_worker_does_not_advance_checkpoint_when_wazuh_page_fails(database):
    class BrokenWazuh(FakeWazuh):
        def fetch_alerts(self, **kwargs):
            raise RuntimeError("synthetic fixture failure")
    worker = seed_worker(BrokenWazuh([]))
    with pytest.raises(RuntimeError, match="synthetic fixture failure"):
        worker.run_once()
    db = backend.SessionLocal()
    checkpoint = db.scalar(select(backend.IngestionCheckpoint))
    assert checkpoint.last_status == "error"
    checkpoint_time = checkpoint.last_event_timestamp
    if checkpoint_time.tzinfo is None:
        checkpoint_time = checkpoint_time.replace(tzinfo=timezone.utc)
    assert checkpoint_time == datetime(2026, 10, 20, 7, 0, tzinfo=timezone.utc)
    db.close()


def test_worker_revalidates_membership_before_poll_and_before_persist(database):
    wazuh = FakeWazuh([])
    worker = seed_worker(wazuh)
    db = backend.SessionLocal()
    membership = db.scalar(select(backend.Membership).where(backend.Membership.user_id == ACTOR))
    db.delete(membership)
    db.commit()
    db.close()
    with pytest.raises(WorkerConfigurationError, match="actor"):
        worker.run_once()
    assert wazuh.calls == []


def test_worker_rejects_membership_revocation_during_wazuh_fetch(database):
    timestamp = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    db = backend.SessionLocal()
    class RevokingWazuh(FakeWazuh):
        def fetch_alerts(self, **kwargs):
            page = super().fetch_alerts(**kwargs)
            membership = db.scalar(select(backend.Membership).where(backend.Membership.user_id == ACTOR))
            db.delete(membership)
            db.commit()
            return page
    wazuh = RevokingWazuh([event("revoked-during-fetch", timestamp)])
    worker = seed_worker(wazuh)
    with pytest.raises(WorkerConfigurationError, match="actor"):
        worker.run_once()
    assert wazuh.calls
    assert db.scalars(select(backend.Evidence)).all() == []
    assert db.scalars(select(backend.IngestionCheckpoint)).all() == []
    db.close()


def test_worker_rejects_invalid_event_before_creating_source_object(database):
    malformed = event("bad", "2026-10-20T07:01:00Z")
    malformed["summary"] = ""
    worker = seed_worker(FakeWazuh([]))
    with pytest.raises(WorkerConfigurationError, match="no usable summary"):
        worker._save_event(malformed)
    assert not list(database.rglob("*.json"))


def test_worker_rejects_source_digest_mismatch(database):
    malformed = event("bad-digest", "2026-10-20T07:01:00Z")
    malformed["provenance"]["source_record_sha256"] = "0" * 64
    worker = seed_worker(FakeWazuh([]))
    with pytest.raises(WorkerConfigurationError, match="digest is invalid"):
        worker._save_event(malformed)


def test_worker_error_categories_never_expose_exception_payloads():
    error = WorkerConfigurationError("credential=private-token endpoint=https://internal")
    code = _safe_error_code(error)
    assert code == "configuration_error"
    assert "private-token" not in code
    assert "internal" not in code


def test_wazuh_retry_backoff_is_exponential_and_capped():
    assert [_retry_delay(30, attempt) for attempt in (1, 2, 3, 4)] == [30, 60, 120, 240]
    assert _retry_delay(3600, 3) == 900
    with pytest.raises(ValueError):
        _retry_delay(0, 1)
    with pytest.raises(ValueError):
        _retry_delay(30, 0)
