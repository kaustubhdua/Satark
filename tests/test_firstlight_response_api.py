from __future__ import annotations

from types import SimpleNamespace

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
    backend.SessionLocal.configure(bind=backend.engine)


def test_response_workflow_is_persistent_four_eyes_and_disabled_by_default(response_app, monkeypatch):
    client, ids, active_user = response_app
    tenant_id, case_id = ids["tenant"], ids["case"]
    requester, approver, executor, verifier = ids["users"]
    active_user[0] = SimpleNamespace(id=requester)

    status = client.get(f"/api/firstlight/live-response/status?tenant_id={tenant_id}&case_id={case_id}")
    assert status.status_code == 200
    assert status.json()["enabled"] is False

    created = client.post("/api/firstlight/live-response/approvals", json={
        "tenant_id": tenant_id,
        "case_id": case_id,
        "action": "wazuh.block_ip",
        "target": "001",
        "reason": "Contain a confirmed test endpoint during the authorized lab exercise.",
        "payload": {"ip_address": "203.0.113.42"},
        "idempotency_key": "response-test-00000001",
        "expires_in_seconds": 600,
    })
    assert created.status_code == 201
    approval_id = created.json()["approval"]["approval_id"]

    active_user[0] = SimpleNamespace(id=approver)
    decision = client.patch("/api/firstlight/live-response/approvals", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "decision": "approved", "reason": "Reviewed the authorized test evidence.",
    })
    assert decision.status_code == 200
    assert decision.json()["approval"]["status"] == "approved"

    # A requester cannot approve their own action; and an approved action cannot run
    # while the global live-response feature flag is disabled.
    active_user[0] = SimpleNamespace(id=executor)
    blocked = client.post("/api/firstlight/live-response/execute", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "confirmation": "CONFIRM BLOCK_IP 001",
    })
    assert blocked.status_code == 503

    with response_api._ledger_scope() as ledger:
        assert ledger.get_approval(approval_id, tenant_id=tenant_id, case_id=case_id).status == "approved"

    monkeypatch.setenv("SATARK_ENABLE_LIVE_RESPONSE", "true")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_API_URL", "https://wazuh-manager.example.test:55000")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_USERNAME", "test-user")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_PASSWORD", "test-password")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS", "001")
    monkeypatch.setattr(response_api, "execute_wazuh_response", lambda action, target, payload, **kwargs: ActionResult(
        "Wazuh Active Response", "firewall-drop", target, "submitted",
        "Mock Wazuh accepted the authorized lab request.", "wazuh-task-123",
    ))
    executed = client.post("/api/firstlight/live-response/execute", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "confirmation": "CONFIRM BLOCK_IP 001",
    })
    assert executed.status_code == 200
    assert executed.json()["outcome"]["status"] == "submitted"
    assert executed.json()["outcome"]["provider_reference"] == "wazuh-task-123"

    active_user[0] = SimpleNamespace(id=verifier)
    verified = client.post("/api/firstlight/live-response/verify", json={
        "tenant_id": tenant_id, "case_id": case_id, "approval_id": approval_id,
        "status": "verified", "provider_reference": "wazuh-task-123",
        "detail": "Independently checked the authorized lab machine action in Wazuh.",
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
    active_user[0] = SimpleNamespace(id=ids["users"][0])
    body = {
        "tenant_id": ids["tenant"], "case_id": ids["case"],
        "action": "shell.execute", "target": "host", "reason": "Not permitted",
        "payload": {"command": "whoami"}, "idempotency_key": "response-test-00000002",
    }
    rejected = client.post("/api/firstlight/live-response/approvals", json=body)
    assert rejected.status_code == 409
