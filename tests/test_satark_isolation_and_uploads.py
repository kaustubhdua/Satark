"""Negative tests for roadmap P0.2 (tenant isolation) and P0.3/P1.2 (hostile uploads).

Each test uses distinct identities and asserts the *actual* outcome, not just that
a request was rejected.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import satark_backend as backend
from firstlight_api import app

PASSWORD = "Correct-Horse-Battery-42"


def origin():
    return {"Origin": "http://testserver"}


@pytest.fixture()
def make_client(monkeypatch, tmp_path):
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    backend.SessionLocal.configure(bind=engine)
    backend.Base.metadata.drop_all(engine)
    backend.Base.metadata.create_all(engine)
    monkeypatch.setattr(backend, "engine", engine)
    clients: list[TestClient] = []

    def factory(email: str) -> TestClient:
        c = TestClient(app, base_url="http://testserver")
        c.__enter__()
        clients.append(c)
        r = c.post("/api/auth/signup", json={"email": email, "password": PASSWORD}, headers=origin())
        assert r.status_code == 201, r.text
        return c

    yield factory
    for c in clients:
        c.__exit__(None, None, None)
    backend.Base.metadata.drop_all(engine)
    engine.dispose()


def new_tenant_with_case(c: TestClient, name: str):
    tenant = c.post("/api/workspaces", json={"name": name}, headers=origin()).json()["id"]
    case = c.post("/api/cases", json={"tenant_id": tenant, "title": f"{name} case"}, headers=origin()).json()["case"]["id"]
    return tenant, case


def upload(c, tenant, case, payload=b"hello evidence", name="a.txt", mime="text/plain"):
    return c.post(
        "/api/evidence",
        data={"tenant_id": tenant, "case_id": case, "observed_at": "2026-11-09T00:00:00+00:00",
              "source_label": "log", "event_kind": "file", "summary": "test"},
        files={"file": (name, payload, mime)}, headers=origin(),
    )


# ---- Cross-tenant isolation -------------------------------------------------

def test_tenant_b_cannot_touch_tenant_a_evidence_by_id(make_client):
    alice, mallory = make_client("alice@example.test"), make_client("mallory@example.test")
    tenant_a, case_a = new_tenant_with_case(alice, "A")
    tenant_b, case_b = new_tenant_with_case(mallory, "B")
    evidence_id = upload(alice, tenant_a, case_a, b"secret-a").json()["evidence"]["id"]

    # Mallory names her own tenant but Alice's evidence id: must not leak or verify.
    for path in (f"/api/evidence/{evidence_id}/download", f"/api/evidence/{evidence_id}/verify"):
        assert mallory.get(path, params={"tenant_id": tenant_b}).status_code == 404
        # Naming Alice's tenant is refused on membership.
        assert mallory.get(path, params={"tenant_id": tenant_a}).status_code == 403

    assert mallory.get("/api/evidence", params={"tenant_id": tenant_a, "case_id": case_a}).status_code == 403
    assert upload(mallory, tenant_a, case_a).status_code == 403
    # Mallory's own tenant with Alice's case id finds no such case.
    assert upload(mallory, tenant_b, case_a).status_code == 404
    # Alice's data is intact.
    assert alice.get(f"/api/evidence/{evidence_id}/download", params={"tenant_id": tenant_a}).content == b"secret-a"


def test_tenant_b_cannot_read_or_forge_reports_and_findings_for_tenant_a(make_client):
    alice, mallory = make_client("alice2@example.test"), make_client("mallory2@example.test")
    tenant_a, case_a = new_tenant_with_case(alice, "A2")
    tenant_b, _ = new_tenant_with_case(mallory, "B2")
    report = alice.post("/api/reports", json={"tenant_id": tenant_a, "case_id": case_a, "title": "R",
                                                "snapshot": {"summary": "x"}}, headers=origin())
    assert report.status_code == 201
    report_id = report.json()["report"]["id"]

    assert mallory.get(f"/api/reports/{report_id}", params={"tenant_id": tenant_b}).status_code == 404
    assert mallory.get(f"/api/reports/{report_id}", params={"tenant_id": tenant_a}).status_code == 403
    assert mallory.get("/api/findings", params={"tenant_id": tenant_a, "case_id": case_a}).status_code == 403
    forged = mallory.post("/api/findings", json={"tenant_id": tenant_a, "case_id": case_a, "finding_key": "k",
                                                  "title": "forged", "severity": "high", "detail": "d"}, headers=origin())
    assert forged.status_code == 403
    assert mallory.get("/api/audit/verify", params={"tenant_id": tenant_a}).status_code == 403
    assert mallory.get("/api/audit/events", params={"tenant_id": tenant_a, "case_id": case_a}).status_code == 403


def test_unauthenticated_requests_are_rejected_on_every_data_route(make_client):
    owner = make_client("owner3@example.test")
    tenant, case = new_tenant_with_case(owner, "A3")
    anon = TestClient(app, base_url="http://testserver")
    for path, params in (
        ("/api/cases", {"tenant_id": tenant}), ("/api/findings", {"tenant_id": tenant, "case_id": case}),
        ("/api/reports", {"tenant_id": tenant, "case_id": case}), ("/api/evidence", {"tenant_id": tenant, "case_id": case}),
        ("/api/audit/verify", {"tenant_id": tenant}), ("/api/workspaces", {}),
    ):
        assert anon.get(path, params=params).status_code == 401, path


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "../../etc/passwd", "00000000-0000-0000-0000-00000000000", "' OR 1=1 --"])
def test_malformed_identifiers_are_rejected_not_executed(make_client, bad_id):
    c = make_client("ids@example.test")
    tenant, case = new_tenant_with_case(c, "IDs")
    upload(c, tenant, case, b"real evidence")
    assert c.get("/api/cases", params={"tenant_id": bad_id}).status_code in {400, 403, 404, 422}
    # A bogus case id inside an authorised tenant is parameterised, not interpolated:
    # it must never error out and must never return the tenant's real rows.
    listed = c.get("/api/evidence", params={"tenant_id": tenant, "case_id": bad_id})
    assert listed.status_code in {200, 400, 403, 404, 422}
    if listed.status_code == 200:
        assert listed.json()["evidence"] == []
    assert c.get(f"/api/evidence/{bad_id}/verify", params={"tenant_id": tenant}).status_code in {400, 404, 422}


def test_viewer_is_read_only_across_evidence_findings_and_reports(make_client):
    owner, viewer = make_client("owner4@example.test"), make_client("viewer4@example.test")
    tenant, case = new_tenant_with_case(owner, "Roles")
    assert owner.post("/api/workspaces/members", json={"tenant_id": tenant, "email": "viewer4@example.test",
                                                          "role": "viewer"}, headers=origin()).status_code == 201
    evidence_id = upload(owner, tenant, case, b"owner data").json()["evidence"]["id"]

    assert viewer.get("/api/evidence", params={"tenant_id": tenant, "case_id": case}).status_code == 200
    assert viewer.get(f"/api/evidence/{evidence_id}/download", params={"tenant_id": tenant}).content == b"owner data"
    assert upload(viewer, tenant, case).status_code == 403
    assert viewer.post("/api/findings", json={"tenant_id": tenant, "case_id": case, "finding_key": "k", "title": "t",
                                               "severity": "low", "detail": "d"}, headers=origin()).status_code == 403
    assert viewer.post("/api/firstlight/investigate", json={"tenant_id": tenant, "case_id": case},
                       headers=origin()).status_code == 403


def test_member_removed_loses_access_immediately(make_client):
    owner, member = make_client("owner5@example.test"), make_client("member5@example.test")
    tenant, case = new_tenant_with_case(owner, "Removal")
    added = owner.post("/api/workspaces/members", json={"tenant_id": tenant, "email": "member5@example.test",
                                                        "role": "analyst"}, headers=origin())
    member_id = added.json()["member"]["user_id"]
    assert member.get("/api/cases", params={"tenant_id": tenant}).status_code == 200
    removed = owner.delete("/api/workspaces/members", params={"tenant_id": tenant, "user_id": member_id}, headers=origin())
    assert removed.status_code in {200, 204}, removed.text
    assert member.get("/api/cases", params={"tenant_id": tenant}).status_code == 403


# ---- Hostile / malformed uploads --------------------------------------------

def test_empty_and_oversized_uploads_are_rejected_with_413(make_client):
    c = make_client("size@example.test")
    tenant, case = new_tenant_with_case(c, "Size")
    assert upload(c, tenant, case, b"").status_code == 413
    assert upload(c, tenant, case, b"x" * (backend.MAX_UPLOAD + 1)).status_code == 413
    assert upload(c, tenant, case, b"x" * backend.MAX_UPLOAD).status_code == 201
    assert c.get("/api/evidence", params={"tenant_id": tenant, "case_id": case}).json()["evidence"][0]["size_bytes"] == backend.MAX_UPLOAD


def test_uploads_between_2_and_4_mib_are_accepted(make_client):
    """Regression: a global 2 MiB request cap used to reject files the API advertises as valid (up to 4 MiB)."""
    c = make_client("mid@example.test")
    tenant, case = new_tenant_with_case(c, "Mid")
    three_mib = b"a" * (3 * 1024 * 1024)
    r = upload(c, tenant, case, three_mib)
    assert r.status_code == 201, r.text
    got = c.get(f"/api/evidence/{r.json()['evidence']['id']}/download", params={"tenant_id": tenant})
    assert got.content == three_mib


def test_json_routes_keep_the_tight_body_limit(make_client):
    c = make_client("json@example.test")
    tenant, _ = new_tenant_with_case(c, "Json")
    big = {"tenant_id": tenant, "title": "x" * (3 * 1024 * 1024)}
    assert c.post("/api/cases", json=big, headers=origin()).status_code == 413


@pytest.mark.parametrize("payload,mime", [
    (b"MZ\x90\x00 not a pdf", "application/pdf"),
    (b"<html>not a png</html>", "image/png"),
    (b"GIF89a not jpeg", "image/jpeg"),
    (b"not a zip", "application/zip"),
    (b"text with a NUL\x00 byte", "text/plain"),
])
def test_declared_type_must_match_file_signature(make_client, payload, mime):
    c = make_client("sig@example.test")
    tenant, case = new_tenant_with_case(c, "Sig")
    assert upload(c, tenant, case, payload, "f.bin", mime).status_code == 415
    assert c.get("/api/evidence", params={"tenant_id": tenant, "case_id": case}).json()["evidence"] == []


def test_polyglot_and_executable_content_is_stored_inert_as_octet_stream(make_client):
    c = make_client("poly@example.test")
    tenant, case = new_tenant_with_case(c, "Poly")
    # PE header declared as an unknown type: kept, never trusted, never executed.
    pe = b"MZ\x90\x00" + b"\x00" * 64
    r = upload(c, tenant, case, pe, "invoice.pdf.exe", "application/x-msdownload")
    assert r.status_code == 201, r.text
    assert r.json()["evidence"]["content_type"] == "application/octet-stream"
    # A PDF header followed by script content is still served as an attachment under a sandbox CSP.
    pdf = upload(c, tenant, case, b"%PDF-1.7\n<script>alert(1)</script>", "x.pdf", "application/pdf")
    assert pdf.status_code == 201
    got = c.get(f"/api/evidence/{pdf.json()['evidence']['id']}/download", params={"tenant_id": tenant})
    assert got.headers["content-security-policy"] == "sandbox"
    assert got.headers["x-content-type-options"] == "nosniff"
    assert got.headers["content-disposition"].startswith("attachment;")


@pytest.mark.parametrize("filename", ["../../etc/passwd", "..\\..\\windows\\system32\\cmd.exe", 'a";b.txt', "line\r\nbreak.txt", "a" * 400 + ".txt"])
def test_hostile_filenames_are_sanitised_and_never_escape_storage(make_client, tmp_path, filename):
    c = make_client("names@example.test")
    tenant, case = new_tenant_with_case(c, "Names")
    r = upload(c, tenant, case, b"payload", filename)
    assert r.status_code == 201, r.text
    stored_name = r.json()["evidence"]["original_filename"]
    assert all(ch.isalnum() or ch in "._-" for ch in stored_name) and len(stored_name) <= 100
    got = c.get(f"/api/evidence/{r.json()['evidence']['id']}/download", params={"tenant_id": tenant})
    assert got.status_code == 200 and "\n" not in got.headers["content-disposition"]
    root = (tmp_path / "evidence").resolve()
    for path in root.rglob("*"):
        assert root in path.resolve().parents or path.resolve() == root
    assert not (tmp_path / "etc").exists()


def test_missing_timezone_on_upload_is_rejected_and_leaves_no_object(make_client, tmp_path):
    c = make_client("tz@example.test")
    tenant, case = new_tenant_with_case(c, "TZ")
    r = c.post("/api/evidence", data={"tenant_id": tenant, "case_id": case, "observed_at": "2026-11-09T00:00:00",
                                       "source_label": "l", "event_kind": "k", "summary": "s"},
               files={"file": ("a.txt", b"data", "text/plain")}, headers=origin())
    assert r.status_code == 400
    root = tmp_path / "evidence"
    assert not root.exists() or not [p for p in root.rglob("*") if p.is_file()]


# ---- Interrupted-network retries / idempotency ------------------------------

def test_retried_upload_is_not_duplicated(make_client):
    c = make_client("retry@example.test")
    tenant, case = new_tenant_with_case(c, "Retry")
    assert upload(c, tenant, case, b"same bytes").status_code == 201
    assert upload(c, tenant, case, b"same bytes").status_code == 409  # client retry after a lost response
    rows = c.get("/api/evidence", params={"tenant_id": tenant, "case_id": case}).json()["evidence"]
    assert len(rows) == 1
    # Identical bytes in a *different* case are legitimate separate evidence.
    other = c.post("/api/cases", json={"tenant_id": tenant, "title": "other"}, headers=origin()).json()["case"]["id"]
    assert upload(c, tenant, other, b"same bytes").status_code == 201


def test_audit_chain_stays_valid_after_mixed_success_and_failure(make_client):
    c = make_client("audit@example.test")
    tenant, case = new_tenant_with_case(c, "Audit")
    upload(c, tenant, case, b"one")
    upload(c, tenant, case, b"one")        # duplicate: 409
    upload(c, tenant, case, b"")           # empty: 413
    upload(c, tenant, case, b"two")
    check = c.get("/api/audit/verify", params={"tenant_id": tenant})
    assert check.status_code == 200 and check.json()["chain_valid"] is True
