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
    response = client.post("/api/auth/signup", json={"email": email, "password": "Correct-Horse-Battery-42"})
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

    login = client.post("/api/auth/login", json={"email": "analyst@example.test", "password": "Correct-Horse-Battery-42"})
    assert login.status_code == 200
    assert client.get("/api/auth/session").status_code == 200


def test_workspace_case_and_tenant_isolation(client):
    register(client, "owner-a@example.test")
    workspace = client.post("/api/workspaces", json={"name": "Blue Team"}, headers=origin())
    assert workspace.status_code == 201, workspace.text
    tenant_id = workspace.json()["id"]

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


def test_health_does_not_require_supabase(client):
    response = client.get("/api/health/storage")
    assert response.status_code == 200
    assert response.json()["provider"] == "self-hosted"
