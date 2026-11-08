from __future__ import annotations

import hashlib
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
    assert worker.run_once()["status"] == "failed"
    db = backend.SessionLocal()
    job = db.get(backend.InvestigationJob, job_id)
    assert job.status == "failed"
    assert job.error_code == "retry_limit_reached" or job.error_code == "investigation_failed"
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
