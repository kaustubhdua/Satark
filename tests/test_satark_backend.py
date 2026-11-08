from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import satark_backend as backend
from firstlight_api import app


@pytest.fixture()
def client(monkeypatch):
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    backend.SessionLocal.configure(bind=test_engine)
    backend.Base.metadata.drop_all(test_engine)
    backend.Base.metadata.create_all(test_engine)
    monkeypatch.setattr(backend, "engine", test_engine)
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client
    backend.Base.metadata.drop_all(test_engine)
    test_engine.dispose()


def origin():
    return {"Origin": "http://testserver"}


def register(client, email):
    response = client.post("/api/auth/signup", json={"email": email, "password": "Correct-Horse-Battery-42"}, headers=origin())
    assert response.status_code == 201, response.text
    assert "satark_session" in response.cookies
    assert "access_token" not in response.json()
    return response.json()["user"]["id"]


def test_self_hosted_signup_login_and_cookie_session(client):
    user_id = register(client, "analyst@example.test")
    session = client.get("/api/auth/session")
    assert session.status_code == 200
    assert session.json()["user"]["id"] == user_id

    client.post("/api/auth/logout", headers=origin())
    assert client.get("/api/auth/session").status_code == 401

    login = client.post("/api/auth/login", json={"email": "analyst@example.test", "password": "Correct-Horse-Battery-42"}, headers=origin())
    assert login.status_code == 200
    assert client.get("/api/auth/session").status_code == 200


def test_workspace_case_and_tenant_isolation(client):
    register(client, "owner-a@example.test")
    workspace = client.post("/api/workspaces", json={"name": "Blue Team"}, headers=origin())
    assert workspace.status_code == 201, workspace.text
    tenant_id = workspace.json()["id"]
    members = client.get("/api/workspaces/members", params={"tenant_id": tenant_id})
    assert members.status_code == 200
    assert members.json()["members"] == [{"user_id": members.json()["members"][0]["user_id"], "email": "owner-a@example.test", "role": "owner"}]

    created = client.post("/api/cases", json={"tenant_id": tenant_id, "title": "Suspicious login", "severity": "high"}, headers=origin())
    assert created.status_code == 201, created.text
    case = created.json()["case"]
    assert case["tenant_id"] == tenant_id

    listed = client.get("/api/cases", params={"tenant_id": tenant_id})
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()["cases"]] == [case["id"]]

    # A second independent account cannot enumerate or mutate the first tenant.
    client.post("/api/auth/logout", headers=origin())
    register(client, "outsider@example.test")
    denied = client.get("/api/cases", params={"tenant_id": tenant_id})
    assert denied.status_code == 403
    denied_members = client.get("/api/workspaces/members", params={"tenant_id": tenant_id})
    assert denied_members.status_code == 403
    denied_create = client.post("/api/cases", json={"tenant_id": tenant_id, "title": "IDOR attempt"}, headers=origin())
    assert denied_create.status_code == 403


def test_notes_findings_and_reports_are_workspace_scoped(client):
    register(client, "responder@example.test")
    tenant_id = client.post("/api/workspaces", json={"name": "IR Team"}, headers=origin()).json()["id"]
    case = client.post("/api/cases", json={"tenant_id": tenant_id, "title": "Phishing"}, headers=origin()).json()["case"]
    note = client.post("/api/cases/notes", json={"tenant_id": tenant_id, "case_id": case["id"], "body": "Preserve original message"}, headers=origin())
    assert note.status_code == 201
    findings = client.post("/api/findings", json={
        "tenant_id": tenant_id, "case_id": case["id"], "finding_key": "sender-domain",
        "title": "Lookalike sender domain", "severity": "high", "detail": "Domain differs by one character.",
    }, headers=origin())
    assert findings.status_code == 201
    report = client.post("/api/reports", json={
        "tenant_id": tenant_id, "case_id": case["id"], "title": "Initial triage",
        "snapshot": {"summary": "Synthetic test", "finding_count": 1},
    }, headers=origin())
    assert report.status_code == 201
    assert len(report.json()["report"]["snapshot_sha256"]) == 64


def test_cookie_mutation_rejects_cross_origin(client):
    register(client, "csrf@example.test")
    response = client.post("/api/workspaces", json={"name": "No CSRF"}, headers={"Origin": "https://attacker.example"})
    assert response.status_code == 403


def test_health_reports_self_hosted_storage(client):
    response = client.get("/api/health/storage")
    assert response.status_code == 200
    assert response.json()["provider"] == "self-hosted"

def test_cookie_mutation_rejects_same_host_wrong_scheme(client):
    register(client, "csrf-scheme@example.test")
    response = client.post(
        "/api/workspaces",
        json={"name": "Scheme mismatch"},
        headers={"Origin": "https://testserver"},
    )
    assert response.status_code == 403

def test_empty_bearer_header_does_not_bypass_cookie_csrf(client):
    register(client, "csrf-empty-bearer@example.test")
    response = client.post(
        "/api/workspaces",
        json={"name": "Empty bearer bypass"},
        headers={"Origin": "https://attacker.example", "Authorization": "Bearer "},
    )
    assert response.status_code == 403

def test_session_refresh_rotates_and_revokes_previous_cookie(client):
    register(client, "rotate@example.test")
    old_token = client.cookies.get("satark_session")
    before = client.get("/api/auth/session")
    assert before.status_code == 200
    assert before.json()["expires_in"] > 0

    refreshed = client.post("/api/auth/refresh", headers=origin())
    assert refreshed.status_code == 200, refreshed.text
    new_token = client.cookies.get("satark_session")
    assert new_token and new_token != old_token
    assert refreshed.json()["user"]["email"] == "rotate@example.test"

    stale_client = TestClient(app, base_url="http://testserver")
    stale_client.cookies.set("satark_session", old_token)
    assert stale_client.get("/api/auth/session").status_code == 401
    assert client.get("/api/auth/session").status_code == 200

def test_workspace_owner_can_add_change_and_remove_members(client):
    owner_id = register(client, "workspace-owner@example.test")
    tenant_id = client.post(
        "/api/workspaces", json={"name": "Managed Team"}, headers=origin()
    ).json()["id"]

    member_client = TestClient(app, base_url="http://testserver")
    member_id = register(member_client, "workspace-member@example.test")

    added = client.post("/api/workspaces/members", json={
        "tenant_id": tenant_id, "email": "workspace-member@example.test", "role": "viewer",
    }, headers=origin())
    assert added.status_code == 201, added.text
    assert added.json()["member"]["user_id"] == member_id
    assert added.json()["member"]["role"] == "viewer"

    workspaces = member_client.get("/api/workspaces")
    assert workspaces.status_code == 200
    assert workspaces.json()["workspaces"][0]["role"] == "viewer"
    denied_write = member_client.post("/api/cases", json={
        "tenant_id": tenant_id, "title": "Viewer cannot create",
    }, headers=origin())
    assert denied_write.status_code == 403

    changed = client.patch("/api/workspaces/members", json={
        "tenant_id": tenant_id, "user_id": member_id, "role": "analyst",
    }, headers=origin())
    assert changed.status_code == 200, changed.text
    allowed_write = member_client.post("/api/cases", json={
        "tenant_id": tenant_id, "title": "Analyst can create",
    }, headers=origin())
    assert allowed_write.status_code == 201, allowed_write.text

    removed = client.delete(
        "/api/workspaces/members",
        params={"tenant_id": tenant_id, "user_id": member_id},
        headers=origin(),
    )
    assert removed.status_code == 200, removed.text
    assert member_client.get("/api/cases", params={"tenant_id": tenant_id}).status_code == 403

    last_owner = client.delete(
        "/api/workspaces/members",
        params={"tenant_id": tenant_id, "user_id": owner_id},
        headers=origin(),
    )
    assert last_owner.status_code == 409

def test_password_recovery_uses_single_use_token_and_revokes_sessions(client, monkeypatch):
    register(client, "recover@example.test")
    captured = {}
    monkeypatch.setenv("SATARK_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SATARK_SMTP_FROM", "security@example.test")
    monkeypatch.setenv("SATARK_PUBLIC_BASE_URL", "http://localhost:3000")
    monkeypatch.setattr(
        backend, "send_password_reset_email",
        lambda recipient, url: captured.update({"recipient": recipient, "url": url}),
    )

    requested = client.post(
        "/api/auth/password-reset/request",
        json={"email": "recover@example.test"},
        headers=origin(),
    )
    assert requested.status_code == 202
    assert requested.json()["ok"] is True
    assert captured["recipient"] == "recover@example.test"
    token = captured["url"].split("token=", 1)[1]
    assert token

    completed = client.post(
        "/api/auth/password-reset/complete",
        json={"token": token, "password": "New-Correct-Horse-42"},
        headers=origin(),
    )
    assert completed.status_code == 200, completed.text
    assert client.get("/api/auth/session").status_code == 401
    assert client.post("/api/auth/login", json={
        "email": "recover@example.test", "password": "Correct-Horse-Battery-42",
    }, headers=origin()).status_code == 401
    assert client.post("/api/auth/login", json={
        "email": "recover@example.test", "password": "New-Correct-Horse-42",
    }, headers=origin()).status_code == 200

    replay = client.post(
        "/api/auth/password-reset/complete",
        json={"token": token, "password": "Another-Correct-Horse-43"},
        headers=origin(),
    )
    assert replay.status_code == 400


def test_password_recovery_response_does_not_enumerate_unknown_accounts(client, monkeypatch):
    monkeypatch.setenv("SATARK_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SATARK_SMTP_FROM", "security@example.test")
    monkeypatch.setenv("SATARK_PUBLIC_BASE_URL", "http://localhost:3000")
    monkeypatch.setattr(backend, "send_password_reset_email", lambda *_: pytest.fail("must not send for unknown account"))
    response = client.post(
        "/api/auth/password-reset/request",
        json={"email": "missing@example.test"},
        headers=origin(),
    )
    assert response.status_code == 202
    assert response.json()["ok"] is True

def test_login_failures_trigger_database_backed_cooldown(client, monkeypatch):
    register(client, "throttle@example.test")

    class AlwaysWrongPassword:
        def verify(self, *_args):
            return False

    monkeypatch.setattr(backend, "PASSWORDS", AlwaysWrongPassword())
    for _ in range(10):
        response = client.post("/api/auth/login", json={
            "email": "throttle@example.test", "password": "Wrong-Password-123",
        }, headers=origin())
        assert response.status_code == 401
    locked = client.post("/api/auth/login", json={
        "email": "throttle@example.test", "password": "Correct-Horse-Battery-42",
    }, headers=origin())
    assert locked.status_code == 429
