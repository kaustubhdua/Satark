from __future__ import annotations

import hashlib
import os
from pathlib import Path
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

import satark_backend as backend
from firstlight_investigation_worker import InvestigationJobWorker
from firstlight_engine import investigate_case


@pytest.fixture()
def database(monkeypatch, tmp_path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    backend.SessionLocal.configure(bind=engine)
    backend.Base.metadata.drop_all(engine)
    backend.Base.metadata.create_all(engine)
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    yield engine
    backend.Base.metadata.drop_all(engine)
    engine.dispose()


def seed_job():
    db = backend.SessionLocal()
    user = backend.User(email="worker@example.test", password_hash="not-used")
    db.add(user)
    db.flush()
    tenant = backend.Tenant(name="IR", created_by=user.id)
    db.add(tenant)
    db.flush()
    db.add(backend.Membership(tenant_id=tenant.id, user_id=user.id, role="owner"))
    case = backend.Case(tenant_id=tenant.id, title="Suspicious login", created_by=user.id)
    db.add(case)
    db.flush()
    job = backend.InvestigationJob(tenant_id=tenant.id, case_id=case.id, requested_by=user.id)
    db.add(job)
    db.commit()
    result = (tenant.id, case.id, user.id, job.id)
    db.close()
    return result


def test_worker_claims_and_persists_investigation(database):
    tenant_id, case_id, user_id, job_id = seed_job()
    worker = InvestigationJobWorker()
    outcome = worker.run_once()
    assert outcome["status"] == "succeeded"
    assert outcome["job_id"] == job_id
    db = backend.SessionLocal()
    job = db.get(backend.InvestigationJob, job_id)
    report = db.scalar(select(backend.Report).where(backend.Report.case_id == case_id))
    assert job.status == "succeeded"
    assert len(job.result_sha256) == 64
    assert report is not None
    assert report.snapshot_sha256 == job.result_sha256
    db.close()


def test_worker_uses_normalized_wazuh_metadata_to_create_evidence_linked_findings(database):
    tenant_id, case_id, user_id, job_id = seed_job()
    root = Path(os.environ["SATARK_EVIDENCE_DIR"])
    object_dir = root / tenant_id / case_id / "wazuh"
    object_dir.mkdir(parents=True, exist_ok=True)
    raw = b'{"@timestamp":"2026-11-09T10:00:00Z","rule":{"id":"5710","level":8}}'
    evidence_id = "44444444-4444-4444-8444-444444444444"
    object_path = object_dir / "wazuh-source.json"
    object_path.write_bytes(raw)
    db = backend.SessionLocal()
    db.add(backend.Evidence(
        id=evidence_id, tenant_id=tenant_id, case_id=case_id, object_key=str(object_path),
        source_label="Wazuh", event_kind="security_alert",
        observed_at=backend.utcnow(), summary="Wazuh authentication alert",
        source_sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw),
        content_type="application/json", original_filename="wazuh-source.json",
        metadata_json={"provider": "wazuh-indexer", "rule_level": 8,
                       "rule_groups": ["authentication_failed"], "agent_id": "004"},
        created_by=user_id,
    ))
    db.commit()
    db.close()
    result = InvestigationJobWorker().run_once()
    assert result["status"] == "succeeded"
    db = backend.SessionLocal()
    job = db.get(backend.InvestigationJob, job_id)
    findings = db.scalars(select(backend.Finding).where(
        backend.Finding.tenant_id == tenant_id, backend.Finding.case_id == case_id
    )).all()
    assert job.result["investigation"]["findings"]
    assert any(evidence_id in row.evidence_refs for row in findings)
    assert any("Wazuh" in row.title for row in findings)
    db.close()


def test_worker_is_idle_when_queue_is_empty(database):
    assert InvestigationJobWorker().run_once() == {"status": "idle"}


def test_worker_retries_failure_then_marks_job_failed(database, monkeypatch):
    tenant_id, case_id, user_id, job_id = seed_job()
    monkeypatch.setattr("firstlight_investigation_worker.investigate_case",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic failure")))
    worker = InvestigationJobWorker()
    assert worker.run_once()["status"] == "failed"
    db = backend.SessionLocal()
    job = db.get(backend.InvestigationJob, job_id)
    assert job.status == "queued"
    assert job.attempts == 1
    job.max_attempts = 1
    db.commit()
    db.close()
    assert worker.run_once()["status"] == "idle"
    db = backend.SessionLocal()
    job = db.get(backend.InvestigationJob, job_id)
    assert job.status == "failed"
    assert job.error_code == "retry_limit_reached"
    db.close()


def test_worker_uses_expired_lease_for_recovery(database):
    tenant_id, case_id, user_id, job_id = seed_job()
    db = backend.SessionLocal()
    job = db.get(backend.InvestigationJob, job_id)
    job.status = "running"
    job.lease_until = backend.utcnow() - timedelta(seconds=1)
    db.commit()
    db.close()
    assert InvestigationJobWorker().run_once()["status"] == "succeeded"
