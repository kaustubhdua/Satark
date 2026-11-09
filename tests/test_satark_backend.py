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

    audit_events = client.get("/api/audit/events", params={
        "tenant_id": tenant_id, "case_id": case["id"],
    })
    assert audit_events.status_code == 200
    sequences = [event["sequence"] for event in audit_events.json()["events"]]
    assert sequences == sorted(set(sequences))
    audit_check = client.get("/api/audit/verify", params={"tenant_id": tenant_id})
    assert audit_check.status_code == 200
    assert audit_check.json()["chain_valid"] is True


def test_cookie_mutation_rejects_cross_origin(client):
    register(client, "csrf@example.test")
    response = client.post("/api/workspaces", json={"name": "No CSRF"}, headers={"Origin": "https://attacker.example"})
    assert response.status_code == 403


def test_health_reports_self_hosted_storage(client):
    response = client.get("/api/health/storage")
    assert response.status_code == 200
    assert response.json()["provider"] == "self-hosted"
    assert response.json()["schema_ready"] is True
    assert response.json()["tenant_rls"] is False

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
    # Reuse of a rotated token revokes the rest of that login family.
    assert client.get("/api/auth/session").status_code == 401
    # A new login creates a fresh family and is not affected by the old replay.
    fresh_login = client.post("/api/auth/login", json={
        "email": "rotate@example.test", "password": "Correct-Horse-Battery-42",
    }, headers=origin())
    assert fresh_login.status_code == 200
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


def test_email_validation_is_bounded_and_accepts_common_addresses():
    assert backend.valid_email_address("analyst+alerts@example.test")
    assert backend.valid_email_address("a.b-c_d@example.co")
    assert not backend.valid_email_address("!@!." + "!.".join(["x"] * 1000))
    assert not backend.valid_email_address("missing-at.example.test")
    assert not backend.valid_email_address("a..b@example.test")
    assert not backend.valid_email_address("user@-example.test")


def test_evidence_directory_rejects_untrusted_path_segments(monkeypatch, tmp_path):
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(tmp_path / "private"))
    tenant_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    case_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    directory = backend.evidence_directory(tenant_id, case_id)
    assert directory == (tmp_path / "private" / tenant_id / case_id).resolve()
    with pytest.raises(backend.HTTPException):
        backend.evidence_directory("../../outside", case_id)


def test_stored_evidence_path_rejects_paths_outside_private_root(monkeypatch, tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("not evidence", encoding="utf-8")
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(private))
    with pytest.raises(backend.HTTPException):
        backend.stored_evidence_path(str(outside))


def test_evidence_objects_are_written_with_private_permissions(monkeypatch, tmp_path):
    root = tmp_path / "private-evidence"
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(root))
    tenant_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    case_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    object_dir = backend.evidence_directory(tenant_id, case_id)
    object_path = backend.write_private_evidence_object(object_dir, "evidence-1", b"private evidence")
    assert object_path.read_bytes() == b"private evidence"
    assert object_path.stat().st_mode & 0o777 == 0o600
    assert object_dir.stat().st_mode & 0o777 == 0o700
    assert root.stat().st_mode & 0o777 == 0o700


def test_untrusted_evidence_download_is_attachment_with_nosniff(client):
    register(client, "evidence-content@example.test")
    tenant_id = client.post("/api/workspaces", json={"name": "Evidence"}, headers=origin()).json()["id"]
    case = client.post("/api/cases", json={
        "tenant_id": tenant_id, "title": "Untrusted upload",
    }, headers=origin()).json()["case"]
    uploaded = client.post(
        "/api/evidence",
        data={
            "tenant_id": tenant_id,
            "case_id": case["id"],
            "observed_at": "2026-11-09T00:00:00+00:00",
            "source_label": "Untrusted HTML",
            "event_kind": "file",
            "summary": "Test active content handling",
        },
        files={"file": ("payload.html", b"<script>alert(1)</script>", "text/html")},
        headers=origin(),
    )
    assert uploaded.status_code == 201, uploaded.text
    evidence = uploaded.json()["evidence"]
    assert evidence["content_type"] == "application/octet-stream"
    downloaded = client.get(
        f"/api/evidence/{evidence['id']}/download",
        params={"tenant_id": tenant_id},
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert downloaded.headers["content-security-policy"] == "sandbox"
    assert downloaded.headers["content-disposition"].startswith("attachment;")
    assert downloaded.content == b"<script>alert(1)</script>"


def test_email_verification_is_single_use_and_blocks_unverified_login(client, monkeypatch):
    monkeypatch.setenv("SATARK_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("SATARK_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SATARK_SMTP_FROM", "security@example.test")
    monkeypatch.setenv("SATARK_PUBLIC_BASE_URL", "https://satark.example")
    captured = {}
    monkeypatch.setattr(
        backend, "send_email_verification_email",
        lambda recipient, url: captured.update({"recipient": recipient, "url": url}),
    )
    created = client.post(
        "/api/auth/signup",
        json={"email": "verify@example.test", "password": "Correct-Horse-Battery-42"},
        headers=origin(),
    )
    assert created.status_code == 201, created.text
    assert created.json()["verification_required"] is True
    assert "satark_session" not in client.cookies
    assert captured["recipient"] == "verify@example.test"
    token = captured["url"].split("token=", 1)[1]

    blocked = client.post(
        "/api/auth/login",
        json={"email": "verify@example.test", "password": "Correct-Horse-Battery-42"},
        headers=origin(),
    )
    assert blocked.status_code == 403

    completed = client.post(
        "/api/auth/email-verification/complete",
        json={"token": token},
        headers=origin(),
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["ok"] is True

    replay = client.post(
        "/api/auth/email-verification/complete",
        json={"token": token},
        headers=origin(),
    )
    assert replay.status_code == 400

    login = client.post(
        "/api/auth/login",
        json={"email": "verify@example.test", "password": "Correct-Horse-Battery-42"},
        headers=origin(),
    )
    assert login.status_code == 200, login.text
    assert client.get("/api/auth/session").status_code == 200


def test_email_verification_requires_delivery_configuration_before_signup(client, monkeypatch):
    monkeypatch.setenv("SATARK_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.delenv("SATARK_SMTP_HOST", raising=False)
    monkeypatch.delenv("SATARK_SMTP_FROM", raising=False)
    monkeypatch.delenv("SATARK_PUBLIC_BASE_URL", raising=False)
    response = client.post(
        "/api/auth/signup",
        json={"email": "no-mail@example.test", "password": "Correct-Horse-Battery-42"},
        headers=origin(),
    )
    assert response.status_code == 503
    assert client.post(
        "/api/auth/login",
        json={"email": "no-mail@example.test", "password": "Correct-Horse-Battery-42"},
        headers=origin(),
    ).status_code == 401


def test_totp_mfa_enrollment_recovery_code_login_and_disable(client, monkeypatch):
    key = backend.Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("SATARK_MFA_ENCRYPTION_KEY", key)
    monkeypatch.setenv("SATARK_REQUIRE_MFA", "true")
    register(client, "mfa-user@example.test")

    status = client.get("/api/auth/mfa/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is False
    blocked_workspace = client.get("/api/workspaces")
    assert blocked_workspace.status_code == 403

    started = client.post("/api/auth/mfa/enroll/start", headers=origin())
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    assert started.json()["otpauth_uri"].startswith("otpauth://totp/")

    code = backend.totp_at(secret, int(backend.time.time()))
    confirmed = client.post("/api/auth/mfa/enroll/confirm", json={"code": code}, headers=origin())
    assert confirmed.status_code == 200, confirmed.text
    assert client.get("/api/workspaces").status_code == 200
    recovery_codes = confirmed.json()["recovery_codes"]
    monkeypatch.setenv("SATARK_MFA_ENCRYPTION_KEY", backend.Fernet.generate_key().decode("ascii"))
    assert client.get("/api/health/storage").status_code == 503
    monkeypatch.setenv("SATARK_MFA_ENCRYPTION_KEY", key)
    assert client.get("/api/health/storage").status_code == 200
    assert len(recovery_codes) == 10
    assert len(set(recovery_codes)) == 10
    assert client.get("/api/auth/mfa/status").json() == {"enabled": True, "required": True, "recovery_codes_remaining": 10}

    client.post("/api/auth/logout", headers=origin())
    missing_code = client.post("/api/auth/login", json={
        "email": "mfa-user@example.test", "password": "Correct-Horse-Battery-42",
    }, headers=origin())
    assert missing_code.status_code == 401

    next_code = backend.totp_at(secret, int(backend.time.time()) + 30)
    totp_login = client.post("/api/auth/login", json={
        "email": "mfa-user@example.test",
        "password": "Correct-Horse-Battery-42",
        "mfa_code": next_code,
    }, headers=origin())
    assert totp_login.status_code == 200, totp_login.text
    client.post("/api/auth/logout", headers=origin())
    replayed_totp = client.post("/api/auth/login", json={
        "email": "mfa-user@example.test",
        "password": "Correct-Horse-Battery-42",
        "mfa_code": next_code,
    }, headers=origin())
    assert replayed_totp.status_code == 401

    recovery_login = client.post("/api/auth/login", json={
        "email": "mfa-user@example.test",
        "password": "Correct-Horse-Battery-42",
        "mfa_code": recovery_codes[0],
    }, headers=origin())
    assert recovery_login.status_code == 200, recovery_login.text
    assert client.get("/api/auth/mfa/status").json()["recovery_codes_remaining"] == 9

    disable_recovery_code = recovery_codes[1]
    disabled = client.post("/api/auth/mfa/disable", json={
        "password": "Correct-Horse-Battery-42", "code": disable_recovery_code,
    }, headers=origin())
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["enabled"] is False
    assert client.get("/api/auth/session").status_code == 401


def test_totp_mfa_fails_closed_without_encryption_key(client, monkeypatch):
    monkeypatch.delenv("SATARK_MFA_ENCRYPTION_KEY", raising=False)
    register(client, "mfa-unconfigured@example.test")
    response = client.post("/api/auth/mfa/enroll/start", headers=origin())
    assert response.status_code == 503


def test_workspace_invitation_can_onboard_unregistered_account_and_is_single_use(client, monkeypatch):
    register(client, "invite-owner@example.test")
    tenant_id = client.post(
        "/api/workspaces", json={"name": "Invitations"}, headers=origin()
    ).json()["id"]
    monkeypatch.setenv("SATARK_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SATARK_SMTP_FROM", "security@example.test")
    monkeypatch.setenv("SATARK_PUBLIC_BASE_URL", "https://satark.example")
    sent = {}
    monkeypatch.setattr(
        backend, "send_workspace_invitation_email",
        lambda recipient, url, role: sent.update({"recipient": recipient, "url": url, "role": role}),
    )

    created = client.post("/api/workspaces/invitations", json={
        "tenant_id": tenant_id, "email": "new-member@example.test", "role": "analyst",
    }, headers=origin())
    assert created.status_code == 201, created.text
    invitation_id = created.json()["invitation"]["id"]
    token = sent["url"].split("token=", 1)[1]
    assert sent["recipient"] == "new-member@example.test"
    assert sent["role"] == "analyst"

    listed = client.get("/api/workspaces/invitations", params={"tenant_id": tenant_id})
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["invitations"]] == [invitation_id]

    outsider = TestClient(app, base_url="http://testserver")
    register(outsider, "wrong-recipient@example.test")
    wrong_account = outsider.post(
        "/api/workspaces/invitations/accept", json={"token": token}, headers=origin()
    )
    assert wrong_account.status_code == 403

    invitee = TestClient(app, base_url="http://testserver")
    register(invitee, "new-member@example.test")
    accepted = invitee.post(
        "/api/workspaces/invitations/accept", json={"token": token}, headers=origin()
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["tenant"]["id"] == tenant_id
    assert accepted.json()["tenant"]["role"] == "analyst"
    assert invitee.get("/api/workspaces").json()["workspaces"][0]["id"] == tenant_id

    replay = invitee.post(
        "/api/workspaces/invitations/accept", json={"token": token}, headers=origin()
    )
    assert replay.status_code == 400

    second = client.post("/api/workspaces/invitations", json={
        "tenant_id": tenant_id, "email": "revoke-member@example.test", "role": "viewer",
    }, headers=origin())
    assert second.status_code == 201
    second_token = sent["url"].split("token=", 1)[1]
    revoked = client.delete("/api/workspaces/invitations", params={
        "tenant_id": tenant_id, "invitation_id": second.json()["invitation"]["id"],
    }, headers=origin())
    assert revoked.status_code == 200

    revoked_user = TestClient(app, base_url="http://testserver")
    register(revoked_user, "revoke-member@example.test")
    rejected = revoked_user.post(
        "/api/workspaces/invitations/accept", json={"token": second_token}, headers=origin()
    )
    assert rejected.status_code == 400
    outsider.close()
    invitee.close()
    revoked_user.close()


def test_mandatory_mfa_gate_allows_only_enrollment_until_factor_is_enabled(client, monkeypatch):
    monkeypatch.setenv("SATARK_REQUIRE_MFA", "true")
    monkeypatch.setenv("SATARK_MFA_ENCRYPTION_KEY", backend.Fernet.generate_key().decode("ascii"))
    register(client, "mandatory-mfa@example.test")
    assert client.get("/api/auth/session").status_code == 200
    assert client.get("/api/auth/mfa/status").json()["enabled"] is False
    assert client.get("/api/auth/mfa/status").json()["required"] is True
    blocked = client.post("/api/workspaces", json={"name": "Must enroll first"}, headers=origin())
    assert blocked.status_code == 403

    started = client.post("/api/auth/mfa/enroll/start", headers=origin())
    assert started.status_code == 200, started.text
    code = backend.totp_at(started.json()["secret"], int(backend.time.time()))
    confirmed = client.post("/api/auth/mfa/enroll/confirm", json={"code": code}, headers=origin())
    assert confirmed.status_code == 200, confirmed.text

    allowed = client.post("/api/workspaces", json={"name": "MFA protected"}, headers=origin())
    assert allowed.status_code == 201, allowed.text


def test_auto_schema_bootstrap_refuses_postgresql_without_alembic_migrations(monkeypatch):
    monkeypatch.setenv("SATARK_AUTO_CREATE_SCHEMA", "true")
    monkeypatch.setattr(backend, "DB_URL", "postgresql+psycopg://satark:secret@localhost/satark")
    with pytest.raises(RuntimeError, match="Apply reviewed Alembic migrations"):
        backend.initialize_self_hosted_backend()


def test_storage_health_fails_when_local_schema_is_incomplete(client):
    backend.Base.metadata.tables["satark_mfa_factors"].drop(backend.engine)
    response = client.get("/api/health/storage")
    assert response.status_code == 503

def test_storage_health_fails_when_mandatory_security_controls_are_misconfigured(client, monkeypatch):
    monkeypatch.setenv("SATARK_REQUIRE_MFA", "true")
    monkeypatch.delenv("SATARK_MFA_ENCRYPTION_KEY", raising=False)
    response = client.get("/api/health/storage")
    assert response.status_code == 503

    monkeypatch.setenv("SATARK_MFA_ENCRYPTION_KEY", backend.Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("SATARK_REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.delenv("SATARK_SMTP_HOST", raising=False)
    monkeypatch.delenv("SATARK_SMTP_FROM", raising=False)
    response = client.get("/api/health/storage")
    assert response.status_code == 503

    monkeypatch.setenv("SATARK_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SATARK_SMTP_FROM", "security@example.test")
    monkeypatch.setenv("SATARK_PUBLIC_BASE_URL", "https://satark.example")
    response = client.get("/api/health/storage")
    assert response.status_code == 200
    assert response.json()["security_controls"] == {
        "mandatory_mfa": True, "mandatory_email_verification": True,
    }
