from __future__ import annotations

import os
import uuid
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text, event
from sqlalchemy.exc import DBAPIError
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import make_url

from scripts.satark_backup import create_backup, restore_backup, verify_backup

import satark_backend as backend
from firstlight_api import app
from firstlight_investigation_worker import InvestigationJobWorker
from firstlight_wazuh_worker import WazuhSatarkWorker


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
            WHERE relname IN ('satark_tenants', 'satark_memberships', 'satark_cases', 'satark_case_notes',
                'satark_evidence', 'satark_findings', 'satark_reports',
                'satark_audit_events', 'satark_approvals',
                'satark_ingestion_checkpoints', 'satark_investigation_jobs', 'satark_workspace_invitations')
        """)).all()
        assert len(protected) == 12
        assert all(row.relrowsecurity and row.relforcerowsecurity for row in protected)
    # Exercise RLS as a non-owner, non-superuser application role. PostgreSQL
    # superusers bypass RLS even when FORCE ROW LEVEL SECURITY is enabled.
    with engine.begin() as connection:
        connection.exec_driver_sql("""
            DO $body$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'satark_app_test') THEN
                    EXECUTE 'DROP OWNED BY satark_app_test';
                    EXECUTE 'DROP ROLE satark_app_test';
                END IF;
                EXECUTE 'CREATE ROLE satark_app_test NOLOGIN';
            END
            $body$
        """)
        connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO satark_app_test")
        connection.exec_driver_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO satark_app_test")

    def use_application_role(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("SET ROLE satark_app_test")
        cursor.close()

    event.listen(engine, "connect", use_application_role)
    engine.dispose()
    monkeypatch.setattr(backend, "engine", engine)
    monkeypatch.setattr(backend, "DB_URL", url)
    try:
        with TestClient(app, base_url="http://testserver") as client:
            readiness = client.get("/api/health/storage")
            assert readiness.status_code == 200, readiness.text
            assert readiness.json()["schema_revision"] == "20261109_0010"
            assert readiness.json()["tenant_rls"] is True
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

            monkeypatch.setenv("SATARK_SMTP_HOST", "smtp.example.test")
            monkeypatch.setenv("SATARK_SMTP_FROM", "security@example.test")
            monkeypatch.setenv("SATARK_PUBLIC_BASE_URL", "https://satark.example")
            invitation_email = {}
            monkeypatch.setattr(
                backend, "send_workspace_invitation_email",
                lambda recipient, url, role: invitation_email.update({"recipient": recipient, "url": url, "role": role}),
            )
            invitation = client.post("/api/workspaces/invitations", json={
                "tenant_id": tenant_id, "email": "postgres-invitee@example.test", "role": "viewer",
            }, headers=headers)
            assert invitation.status_code == 201, invitation.text
            invitation_token = invitation_email["url"].split("token=", 1)[1]
            invitee = TestClient(app, base_url="http://testserver")
            invitee_signup = invitee.post("/api/auth/signup", json={
                "email": "postgres-invitee@example.test", "password": "Correct-Horse-Battery-42",
            }, headers=headers)
            assert invitee_signup.status_code == 201, invitee_signup.text
            invitee_id = invitee_signup.json()["user"]["id"]
            invitation_accept = invitee.post(
                "/api/workspaces/invitations/accept", json={"token": invitation_token}, headers=headers,
            )
            assert invitation_accept.status_code == 200, invitation_accept.text
            assert invitee.get("/api/workspaces").json()["workspaces"][0]["role"] == "viewer"
            visible_members = client.get("/api/workspaces/members", params={"tenant_id": tenant_id})
            assert visible_members.status_code == 200, visible_members.text
            assert len(visible_members.json()["members"]) == 2

            owner_db = backend.SessionLocal()
            backend.set_rls_user_context(owner_db, user_id)
            owner_user = owner_db.get(backend.User, user_id)
            backend.require_membership(owner_db, owner_user, tenant_id, {"owner"})
            invitee_membership = owner_db.scalar(select(backend.Membership).where(
                backend.Membership.tenant_id == tenant_id,
                backend.Membership.user_id == invitee_id,
            ))
            assert invitee_membership is not None and invitee_membership.role == "viewer"
            owner_db.close()
            invitee_db = backend.SessionLocal()
            backend.set_rls_user_context(invitee_db, invitee_id)
            visible_owner_membership = invitee_db.scalar(select(backend.Membership).where(
                backend.Membership.tenant_id == tenant_id,
                backend.Membership.user_id == user_id,
            ))
            # Workspace members can view the other memberships in their own
            # tenant; RLS must hide other tenants, not co-members.
            assert visible_owner_membership is not None
            assert visible_owner_membership.role == "owner"
            invitee_db.close()

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

            # The Wazuh worker must bind its actor identity before touching
            # RLS-protected evidence, checkpoint and audit tables.
            source = {"@timestamp": (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat(),
                "_id": "postgres-wazuh-1", "rule": {"id": "5710", "level": 8, "description": "Postgres lab alert"}}
            source_json = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            source_digest = hashlib.sha256(source_json.encode()).hexdigest()
            wazuh_event = {
                "source_snapshot_json": source_json,
                "event_id": "wazuh-postgres-1",
                "timestamp": source["@timestamp"],
                "kind": "security_alert",
                "summary": "Postgres lab alert",
                "details": {"index": "wazuh-alerts-*", "document_id": "postgres-wazuh-1",
                    "rule_id": "5710", "rule_level": 8, "rule_groups": ["authentication_failed"],
                    "agent_id": "004", "agent_name": "lab", "manager_name": "mgr",
                    "location": "test", "decoder_name": "test", "data": {},
                    "source_record_sha256": source_digest},
                "provenance": {"index": "wazuh-alerts-*", "document_id": "postgres-wazuh-1",
                    "source_record_sha256": source_digest},
            }
            class FakeWazuh:
                class Config:
                    index_pattern = "wazuh-alerts-*"
                    allowed_agent_ids = ("004",)
                config = Config()
                def fetch_alerts(self, *, limit, since, until, offset, include_source_snapshot=False):
                    return [wazuh_event][offset:offset + limit]
            wazuh_worker = WazuhSatarkWorker(
                wazuh=FakeWazuh(), tenant_id=tenant_id, case_id=case_id,
                actor_id=user_id, initial_since="2026-11-08T00:00:00Z", page_size=1,
            )
            wazuh_result = wazuh_worker.run_once()
            assert wazuh_result["status"] == "ok", wazuh_result
            db = backend.SessionLocal()
            backend.set_rls_user_context(db, user_id)
            assert db.scalar(select(backend.IngestionCheckpoint).where(
                backend.IngestionCheckpoint.tenant_id == tenant_id
            )) is not None
            assert db.scalar(select(backend.Evidence.id).where(
                backend.Evidence.tenant_id == tenant_id,
                backend.Evidence.event_kind == "security_alert",
            )) is not None
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
            visible_memberships = db.scalars(select(backend.Membership)).all()
            assert visible_memberships
            assert {row.user_id for row in visible_memberships} == {user_id, invitee_id}
            db.add(backend.Case(
                tenant_id=outsider_tenant_id, title="RLS write attempt",
                created_by=user_id,
            ))
            with pytest.raises(DBAPIError):
                db.flush()
            db.rollback()
            db.close()
            outsider.close()
            invitee.close()

            # Exercise a real PostgreSQL dump/restore and verify absolute evidence
            # object keys are rebased to the restored private volume.
            backup_archive = tmp_path / "postgres-backup.tar.gz"
            backup_manifest = create_backup(backup_archive, url, tmp_path / "evidence")
            assert backup_manifest["database_engine"] == "postgresql"
            assert verify_backup(backup_archive)["format"] == "satark-backup-v1"
            target_name = "satark_restore_" + uuid.uuid4().hex[:12]
            admin_url = make_url(url).set(drivername="postgresql", database="postgres")
            target_url = str(make_url(url).set(database=target_name))
            target_engine = None
            try:
                with psycopg.connect(admin_url.render_as_string(hide_password=False), autocommit=True) as admin:
                    admin.execute(f'CREATE DATABASE "{target_name}"')
                restored_evidence = tmp_path / "restored-postgres-evidence"
                restored_manifest = restore_backup(backup_archive, target_url, restored_evidence)
                assert restored_manifest["evidence_objects_rebased"] >= 1
                target_engine = create_engine(target_url, pool_pre_ping=True)
                with target_engine.connect() as connection:
                    object_keys = connection.execute(text(
                        "SELECT object_key FROM satark_evidence"
                    )).scalars().all()
                assert object_keys
                assert all(Path(key).is_file() for key in object_keys)
                assert all(restored_evidence.resolve() in Path(key).resolve().parents for key in object_keys)
            finally:
                if target_engine is not None:
                    target_engine.dispose()
                with psycopg.connect(admin_url.render_as_string(hide_password=False), autocommit=True) as admin:
                    admin.execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                        (target_name,),
                    )
                    admin.execute(f'DROP DATABASE IF EXISTS "{target_name}"')
    finally:
        event.remove(engine, "connect", use_application_role)
        engine.dispose()
        # TestClient/worker teardown can leave an idle PostgreSQL session
        # holding a relation lock. This database is dedicated to this CI job;
        # terminate its remaining sessions before dropping the test schema.
        admin_url = make_url(url).set(drivername="postgresql", database="postgres")
        test_database = make_url(url).database
        with psycopg.connect(admin_url.render_as_string(hide_password=False), autocommit=True) as admin:
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (test_database,),
            )
        cleanup_engine = create_engine(
            url,
            pool_pre_ping=True,
            connect_args={"options": "-c lock_timeout=5s -c statement_timeout=30s"},
        )
        try:
            backend.Base.metadata.drop_all(cleanup_engine)
            with cleanup_engine.begin() as connection:
                connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
                connection.exec_driver_sql("DROP OWNED BY satark_app_test")
                connection.exec_driver_sql("DROP ROLE IF EXISTS satark_app_test")
        finally:
            cleanup_engine.dispose()
