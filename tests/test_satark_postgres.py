from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text, event
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
    with engine.connect() as connection:
        protected = connection.execute(text("""
            SELECT relname, relrowsecurity, relforcerowsecurity
            FROM pg_class
            WHERE relname IN ('satark_tenants', 'satark_cases', 'satark_case_notes',
                'satark_evidence', 'satark_findings', 'satark_reports',
                'satark_audit_events', 'satark_approvals',
                'satark_ingestion_checkpoints', 'satark_investigation_jobs')
        """)).all()
        assert len(protected) == 10
        assert all(row.relrowsecurity and row.relforcerowsecurity for row in protected)
    # Exercise RLS as a non-owner, non-superuser application role. PostgreSQL
    # superusers bypass RLS even when FORCE ROW LEVEL SECURITY is enabled.
    with engine.begin() as connection:
        connection.exec_driver_sql("""
            DO $
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'satark_app_test') THEN
                    EXECUTE 'DROP OWNED BY satark_app_test';
                    EXECUTE 'DROP ROLE satark_app_test';
                END IF;
                CREATE ROLE satark_app_test NOLOGIN;
            END
            $
        """)
        connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO satark_app_test")
        connection.exec_driver_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO satark_app_test")

    def use_application_role(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("SET ROLE satark_app_test")
        cursor.close()

    event.listen(engine, "connect", use_application_role)
    engine.dispose()
    try:
        with TestClient(app, base_url="http://testserver") as client:
            headers = {"Origin": "http://testserver"}
            signup = client.post("/api/auth/signup", json={
                "email": "postgres@example.test", "password": "Correct-Horse-Battery-42"
            }, headers=headers)
            assert signup.status_code == 201, signup.text
            user_id = signup.json()["user"]["id"]
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
            backend.set_rls_user_context(db, user_id)
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

            # A different account and tenant must remain invisible even when
            # application code issues an unscoped SQL query.
            outsider = TestClient(app, base_url="http://testserver")
            outsider_signup = outsider.post("/api/auth/signup", json={
                "email": "postgres-outsider@example.test", "password": "Correct-Horse-Battery-42"
            }, headers=headers)
            assert outsider_signup.status_code == 201
            outsider_workspace = outsider.post("/api/workspaces", json={"name": "Other Tenant"}, headers=headers)
            assert outsider_workspace.status_code == 201
            outsider_tenant_id = outsider_workspace.json()["id"]
            db = backend.SessionLocal()
            backend.set_rls_user_context(db, user_id)
            assert db.scalar(select(backend.Case).where(
                backend.Case.tenant_id == outsider_tenant_id
            )) is None
            db.add(backend.Case(
                tenant_id=outsider_tenant_id, title="RLS write attempt",
                created_by=user_id,
            ))
            with pytest.raises(DBAPIError):
                db.flush()
            db.rollback()
            db.close()
            outsider.close()
    finally:
        event.remove(engine, "connect", use_application_role)
        engine.dispose()
        backend.Base.metadata.drop_all(engine)
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
            connection.exec_driver_sql("DROP OWNED BY satark_app_test")
            connection.exec_driver_sql("DROP ROLE IF EXISTS satark_app_test")
        engine.dispose()
