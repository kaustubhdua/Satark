from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker

import satark_backend as backend
from firstlight_api import app
from firstlight_investigation_worker import InvestigationJobWorker


@pytest.mark.skipif(not os.getenv("SATARK_TEST_POSTGRES_URL"), reason="PostgreSQL integration URL is not configured")
def test_postgres_signup_tenant_evidence_idempotent_job_and_worker(monkeypatch, tmp_path):
    url = os.environ["SATARK_TEST_POSTGRES_URL"]
    engine = create_engine(url, pool_pre_ping=True)
    backend.SessionLocal.configure(bind=engine)
    backend.Base.metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    monkeypatch.setenv("SATARK_DATABASE_URL", url)
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    alembic_config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(alembic_config, "head")
    try:
        with TestClient(app, base_url="http://testserver") as client:
            headers = {"Origin": "http://testserver"}
            signup = client.post("/api/auth/signup", json={
                "email": "postgres@example.test", "password": "Correct-Horse-Battery-42"
            }, headers=headers)
            assert signup.status_code == 201, signup.text
            workspace = client.post("/api/workspaces", json={"name": "PostgreSQL IR"}, headers=headers)
            assert workspace.status_code == 201, workspace.text
            tenant_id = workspace.json()["id"]
            case = client.post("/api/cases", json={
                "tenant_id": tenant_id, "title": "Synthetic unfamiliar login", "severity": "high"
            }, headers=headers)
            assert case.status_code == 201, case.text
            case_id = case.json()["case"]["id"]

            evidence = client.post("/api/evidence", data={
                "tenant_id": tenant_id, "case_id": case_id, "source_label": "test sensor",
                "event_kind": "authentication", "observed_at": "2026-11-09T12:00:00+00:00",
                "summary": "Successful login from a new source",
            }, files={"file": ("event.txt", b"successful login from a new source", "text/plain")}, headers=headers)
            assert evidence.status_code == 201, evidence.text
            evidence_id = evidence.json()["evidence"]["id"]
            verified = client.get(f"/api/evidence/{evidence_id}/verify", params={"tenant_id": tenant_id})
            assert verified.status_code == 200
            assert verified.json()["matched"] is True

            payload = {"tenant_id": tenant_id, "case_id": case_id, "idempotency_key": "postgres-job-0001"}
            first = client.post("/api/firstlight/jobs", json=payload, headers=headers)
            second = client.post("/api/firstlight/jobs", json=payload, headers=headers)
            assert first.status_code == 202, first.text
            assert second.status_code == 202, second.text
            job_id = first.json()["job"]["id"]
            assert second.json()["job"]["id"] == job_id

            result = InvestigationJobWorker().run_once()
            assert result["status"] == "succeeded"
            assert result["job_id"] == job_id
            status = client.get("/api/firstlight/jobs", params={"tenant_id": tenant_id, "job_id": job_id})
            assert status.status_code == 200
            assert status.json()["job"]["status"] == "succeeded"
            assert len(status.json()["job"]["result_sha256"]) == 64
            db = backend.SessionLocal()
            findings = db.scalars(select(backend.Finding).where(
                backend.Finding.tenant_id == tenant_id, backend.Finding.case_id == case_id
            )).all()
            assert len(findings) == 1
            assert evidence_id in findings[0].evidence_refs

            audit_event = db.scalar(select(backend.AuditEvent).where(
                backend.AuditEvent.tenant_id == tenant_id
            ).limit(1))
            assert audit_event is not None
            with pytest.raises(DBAPIError, match="append-only"):
                db.execute(text(
                    "UPDATE satark_audit_events SET event_type = 'tampered' WHERE id = :event_id"
                ), {"event_id": audit_event.id})
                db.commit()
            db.rollback()
            with pytest.raises(DBAPIError, match="append-only"):
                db.execute(text(
                    "DELETE FROM satark_audit_events WHERE id = :event_id"
                ), {"event_id": audit_event.id})
                db.commit()
            db.rollback()
            db.close()
    finally:
        backend.Base.metadata.drop_all(engine)
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
        engine.dispose()
