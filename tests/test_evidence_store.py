from __future__ import annotations

import hashlib
import os
import unittest
import io
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import evidence_store
import satark_backend as backend
from firstlight_api import app


class FakeClientError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Minimal in-memory stand-in for the boto3 S3 client."""

    def __init__(self):
        self.objects: dict[tuple[str, str], dict] = {}
        self.fail = False

    def put_object(self, Bucket, Key, Body, **extra):
        if self.fail:
            raise RuntimeError("endpoint down")
        self.objects[(Bucket, Key)] = {"Body": Body, **extra}

    def get_object(self, Bucket, Key):
        if self.fail:
            raise RuntimeError("endpoint down")
        try:
            return {"Body": io.BytesIO(self.objects[(Bucket, Key)]["Body"])}
        except KeyError:
            raise FakeClientError("NoSuchKey")

    def delete_object(self, Bucket, Key):
        self.objects.pop((Bucket, Key), None)


@pytest.fixture()
def fake_s3(monkeypatch):
    fake = FakeS3()
    monkeypatch.setattr(evidence_store, "client_factory", lambda: fake)
    monkeypatch.setenv("SATARK_EVIDENCE_BACKEND", "s3")
    monkeypatch.setenv("SATARK_S3_BUCKET", "satark-evidence")
    monkeypatch.setenv("SATARK_S3_PREFIX", "prod/")
    monkeypatch.setenv("SATARK_S3_SSE", "AES256")
    return fake


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("SATARK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    backend.SessionLocal.configure(bind=engine)
    backend.Base.metadata.drop_all(engine)
    backend.Base.metadata.create_all(engine)
    monkeypatch.setattr(backend, "engine", engine)
    with TestClient(app, base_url="http://testserver") as c:
        yield c
    backend.Base.metadata.drop_all(engine)
    engine.dispose()


def origin():
    return {"Origin": "http://testserver"}


def setup_case(client, email="s3@example.test"):
    r = client.post("/api/auth/signup", json={"email": email, "password": "Correct-Horse-Battery-42"}, headers=origin())
    assert r.status_code == 201, r.text
    tenant = client.post("/api/workspaces", json={"name": "S3 Team"}, headers=origin()).json()["id"]
    case = client.post("/api/cases", json={"tenant_id": tenant, "title": "Stored in S3"}, headers=origin()).json()["case"]
    return tenant, case["id"]


def upload(client, tenant, case, payload=b"login from 203.0.113.9", name="auth.txt"):
    return client.post(
        "/api/evidence",
        data={"tenant_id": tenant, "case_id": case, "observed_at": "2026-11-09T00:00:00+00:00",
              "source_label": "auth log", "event_kind": "authentication", "summary": "Test evidence"},
        files={"file": (name, payload, "text/plain")}, headers=origin(),
    )


def test_s3_upload_download_verify_roundtrip(client, fake_s3):
    tenant, case = setup_case(client)
    payload = b"12 failed logins then success"
    uploaded = upload(client, tenant, case, payload)
    assert uploaded.status_code == 201, uploaded.text
    evidence_id = uploaded.json()["evidence"]["id"]

    # Exactly one object, in the pinned bucket under the configured prefix, encrypted at rest.
    ((bucket, key), stored), = fake_s3.objects.items()
    assert bucket == "satark-evidence"
    assert key == f"prod/{tenant}/{case}/{evidence_id}"
    assert stored["Body"] == payload
    assert stored["ServerSideEncryption"] == "AES256"
    assert stored["Metadata"]["sha256"] == hashlib.sha256(payload).hexdigest()

    verified = client.get(f"/api/evidence/{evidence_id}/verify", params={"tenant_id": tenant})
    assert verified.status_code == 200 and verified.json()["matched"] is True

    downloaded = client.get(f"/api/evidence/{evidence_id}/download", params={"tenant_id": tenant})
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert downloaded.headers["content-disposition"].startswith("attachment;")
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert downloaded.headers["content-security-policy"] == "sandbox"


def test_s3_tampered_object_fails_integrity(client, fake_s3):
    tenant, case = setup_case(client)
    evidence_id = upload(client, tenant, case).json()["evidence"]["id"]
    for obj in fake_s3.objects.values():
        obj["Body"] = b"tampered after upload"
    assert client.get(f"/api/evidence/{evidence_id}/verify", params={"tenant_id": tenant}).json()["matched"] is False
    assert client.get(f"/api/evidence/{evidence_id}/download", params={"tenant_id": tenant}).status_code == 409


def test_s3_missing_object_is_404_and_outage_is_503(client, fake_s3):
    tenant, case = setup_case(client)
    evidence_id = upload(client, tenant, case).json()["evidence"]["id"]
    fake_s3.fail = True
    assert client.get(f"/api/evidence/{evidence_id}/verify", params={"tenant_id": tenant}).status_code == 503
    fake_s3.fail = False
    fake_s3.objects.clear()
    assert client.get(f"/api/evidence/{evidence_id}/verify", params={"tenant_id": tenant}).status_code == 404


def test_s3_upload_outage_is_503_and_stores_no_row(client, fake_s3):
    tenant, case = setup_case(client)
    fake_s3.fail = True
    assert upload(client, tenant, case).status_code == 503
    fake_s3.fail = False
    assert client.get("/api/evidence", params={"tenant_id": tenant, "case_id": case}).json()["evidence"] == []


def test_duplicate_upload_discards_orphan_object(client, fake_s3):
    tenant, case = setup_case(client)
    assert upload(client, tenant, case).status_code == 201
    assert upload(client, tenant, case).status_code == 409
    assert len(fake_s3.objects) == 1


def test_imported_record_and_investigation_use_s3(client, fake_s3):
    tenant, case = setup_case(client)
    r = client.post("/api/evidence/records", json={
        "tenant_id": tenant, "case_id": case, "source_label": "wazuh", "event_kind": "authentication",
        "summary": "Successful login after repeated failures", "observed_at": "2026-11-09T00:00:00Z",
        "metadata": {"agent": "001"}}, headers=origin())
    assert r.status_code == 201, r.text
    assert len(fake_s3.objects) == 1
    inv = client.post("/api/firstlight/investigate", json={"tenant_id": tenant, "case_id": case}, headers=origin())
    assert inv.status_code == 200, inv.text
    assert inv.json()["integrity_summary"] == {"total": 1, "verified": 1, "mismatched": 0}


def test_filesystem_rows_remain_readable_after_switching_to_s3(client, monkeypatch, fake_s3):
    tenant, case = setup_case(client)
    monkeypatch.setenv("SATARK_EVIDENCE_BACKEND", "filesystem")
    old_id = upload(client, tenant, case, b"written before migration", "old.txt").json()["evidence"]["id"]
    monkeypatch.setenv("SATARK_EVIDENCE_BACKEND", "s3")
    new_id = upload(client, tenant, case, b"written after migration", "new.txt").json()["evidence"]["id"]
    for evidence_id, expected in ((old_id, b"written before migration"), (new_id, b"written after migration")):
        got = client.get(f"/api/evidence/{evidence_id}/download", params={"tenant_id": tenant})
        assert got.status_code == 200 and got.content == expected


def test_store_refuses_other_buckets_and_traversal(fake_s3):
    with pytest.raises(evidence_store.EvidenceNotFound):
        evidence_store.get_object("s3://attacker-bucket/prod/x")
    with pytest.raises(evidence_store.EvidenceNotFound):
        evidence_store.get_object("s3://satark-evidence/other-prefix/x")
    with pytest.raises(evidence_store.EvidenceNotFound):
        evidence_store.get_object("s3://satark-evidence/prod/../secrets")


def test_store_requires_canonical_uuids_and_bucket(monkeypatch, fake_s3):
    with pytest.raises(evidence_store.EvidenceStoreError):
        evidence_store.build_location("../x", str(uuid.uuid4()), str(uuid.uuid4()))
    monkeypatch.delenv("SATARK_S3_BUCKET")
    with pytest.raises(evidence_store.EvidenceStoreError):
        evidence_store.build_location(str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4()))


def test_invalid_backend_name_is_rejected(monkeypatch):
    monkeypatch.setenv("SATARK_EVIDENCE_BACKEND", "ftp")
    with pytest.raises(evidence_store.EvidenceStoreError):
        evidence_store.backend_name()


class DatabaseUrlNormalisationTests(unittest.TestCase):
    def _url(self, value):
        import importlib
        import satark_backend
        old = os.environ.get("SATARK_DATABASE_URL")
        os.environ["SATARK_DATABASE_URL"] = value
        try:
            return satark_backend.database_url()
        finally:
            if old is None:
                os.environ.pop("SATARK_DATABASE_URL", None)
            else:
                os.environ["SATARK_DATABASE_URL"] = old

    def test_managed_host_schemes_select_the_psycopg_driver(self):
        self.assertEqual(self._url("postgres://u:p@h:5432/d"), "postgresql+psycopg://u:p@h:5432/d")
        self.assertEqual(self._url("postgresql://u:p@h/d?sslmode=require"), "postgresql+psycopg://u:p@h/d?sslmode=require")

    def test_explicit_driver_and_sqlite_are_untouched(self):
        self.assertEqual(self._url("postgresql+psycopg://u:p@h/d"), "postgresql+psycopg://u:p@h/d")
        self.assertEqual(self._url("sqlite:////tmp/x.db"), "sqlite:////tmp/x.db")
