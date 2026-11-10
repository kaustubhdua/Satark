from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import satark_backend as backend
import firstlight_response_api as response_api
from firstlight_api import app
from integrations.response_actions import ActionResult


@pytest.fixture()
def response_app(monkeypatch, tmp_path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    backend.SessionLocal.configure(bind=engine)
    backend.Base.metadata.drop_all(engine)
    backend.Base.metadata.create_all(engine)
    monkeypatch.setenv("FIRSTLIGHT_RESPONSE_DB", str(tmp_path / "response.sqlite3"))
    monkeypatch.delenv("SATARK_ENABLE_LIVE_RESPONSE", raising=False)
    monkeypatch.delenv("MICROSOFT_TENANT_ID", raising=False)
    monkeypatch.delenv("MICROSOFT_CLIENT_ID", raising=False)
    monkeypatch.delenv("MICROSOFT_CLIENT_SECRET", raising=False)

    db = backend.SessionLocal()
    users = []
    for index in range(1, 5):
        user = backend.User(email=f"operator{index}@example.test", password_hash="not-used")
        db.add(user)
        db.flush()
        users.append(user)
    tenant = backend.Tenant(name="FIRSTLIGHT lab", created_by=users[0].id)
    db.add(tenant)
    db.flush()
    for user, role in zip(users, ("analyst", "owner", "responder", "owner")):
        db.add(backend.Membership(tenant_id=tenant.id, user_id=user.id, role=role))
    case = backend.Case(tenant_id=tenant.id, title="Authorized lab incident", created_by=users[0].id)
    db.add(case)
    db.commit()
    ids = {
        "tenant": tenant.id,
        "case": case.id,
        "users": [user.id for user in users],
    }
    db.close()

    active_user = [None]

    def override_user():
        return active_user[0]

    def override_db():
        session = backend.SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[response_api.current_user] = override_user
    app.dependency_overrides[response_api.db_session] = override_db
    with TestClient(app) as client:
        yield client, ids, active_user
    app.dependency_overrides.clear()
    backend.Base.metadata.drop_all(engine)
    engine.dispose()


def test_response_workflow_is_persistent_four_eyes_and_disabled_by_default(response_app, monkeypatch):
    client, ids, active_user = response_app
    tenant_id, case_id = ids["tenant"], ids["case"]
    requester, approver, executor, verifier = ids["users"]
    active_user[0] = backend.SessionLocal().get(backend.User, requester)

    status = client.get(f"/api/firstlight/live-response/status?tenant_id={tenant_id}&case_id={case_id}")
    assert status.status_code == 200
    assert status.json()["enabled"] is False

    created = client.post("/api/firstlight/live-response/approvals", json={
        "tenant_id": tenant_id,
        "case_id": case_id,
        "action": "defender.isolate_device",
        "target": "device-lab-01",
        "reason": "Contain a confirmed test endpoint during the authorized lab exercise.",
        "payload": {"isolation_type": "Selective"},
        "idempotency_key": "response-test-00000001",
        "expires_in_seconds": 600,
    })
    assert created.status_code == 201
    approval_id = created.json()["approval"]["approval_id"]

    active_user[0] = backend.SessionLocal().get(backend.User, approver)
    decision = client.patch("/api/firstlight/live-response/approvals", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "decision": "approved", "reason": "Reviewed the authorized test evidence.",
    })
    assert decision.status_code == 200
    assert decision.json()["approval"]["status"] == "approved"

    # A requester cannot approve their own action; and an approved action cannot run
    # while the global live-response feature flag is disabled.
    active_user[0] = backend.SessionLocal().get(backend.User, executor)
    blocked = client.post("/api/firstlight/live-response/execute", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "confirmation": "CONFIRM ISOLATE device-lab-01",
    })
    assert blocked.status_code == 503

    with response_api._ledger_scope() as ledger:
        assert ledger.get_approval(approval_id, tenant_id=tenant_id, case_id=case_id).status == "approved"

    monkeypatch.setenv("SATARK_ENABLE_LIVE_RESPONSE", "true")
    monkeypatch.setenv("MICROSOFT_TENANT_ID", "00000000-0000-4000-8000-000000000001")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "test-secret")
    monkeypatch.setattr(response_api, "isolate_defender_device", lambda target, **kwargs: ActionResult(
        "Microsoft Defender for Endpoint", "isolate_device", target, "submitted",
        "Mock provider accepted the lab request.", "mde-action-123",
    ))
    executed = client.post("/api/firstlight/live-response/execute", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "confirmation": "CONFIRM ISOLATE device-lab-01",
    })
    assert executed.status_code == 200
    assert executed.json()["outcome"]["status"] == "submitted"
    assert executed.json()["outcome"]["provider_reference"] == "mde-action-123"

    active_user[0] = backend.SessionLocal().get(backend.User, verifier)
    verified = client.post("/api/firstlight/live-response/verify", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "status": "verified", "provider_reference": "mde-action-123",
        "detail": "Independently checked the authorized lab machine action in Defender.",
    })
    assert verified.status_code == 200
    assert verified.json()["approval"]["status"] == "verified"
    assert verified.json()["verification_kind"] == "independent_operator_attestation"

    listing = client.get(f"/api/firstlight/live-response/approvals?tenant_id={tenant_id}&case_id={case_id}")
    assert listing.status_code == 200
    assert len(listing.json()["approvals"]) == 1
    audit = client.get(f"/api/firstlight/live-response/audit?tenant_id={tenant_id}&case_id={case_id}")
    assert audit.status_code == 200
    assert audit.json()["chain_valid"] is True
    assert [event["event_type"] for event in audit.json()["events"]] == [
        "approval.requested", "approval.approved", "execution.claimed",
        "execution.submitted", "verification.verified",
    ]


def test_response_api_rejects_unknown_actions(response_app):
    client, ids, active_user = response_app
    active_user[0] = backend.SessionLocal().get(backend.User, ids["users"][0])
    body = {
        "tenant_id": ids["tenant"], "case_id": ids["case"],
        "action": "shell.execute", "target": "host", "reason": "Not permitted",
        "payload": {"command": "whoami"}, "idempotency_key": "response-test-00000002",
    }
    rejected = client.post("/api/firstlight/live-response/approvals", json=body)
    assert rejected.status_code == 409
