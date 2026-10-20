from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

import firstlight_api
from firstlight_engine import sha256_record

client = TestClient(firstlight_api.app, headers={"Authorization": "Bearer test-only-token-" + "x" * 40})


@pytest.fixture(autouse=True)
def require_api_token(monkeypatch):
    # All ordinary endpoint tests exercise the same fail-closed auth posture as deployment.
    monkeypatch.setenv("FIRSTLIGHT_API_TOKEN", "test-only-token-" + "x" * 40)


def evidence(event_id: str, summary: str = "Routine application notice", kind: str = "notice") -> dict:
    item = {
        "id": event_id,
        "time": "2026-10-11T09:14:00Z",
        "source": "synthetic test",
        "kind": kind,
        "summary": summary,
    }
    record = {
        "event_id": item["id"],
        "timestamp": item["time"],
        "source": item["source"],
        "kind": item["kind"],
        "summary": item["summary"],
        "details": {},
    }
    item["digest"] = sha256_record(record)
    return item


def test_health_is_no_store_and_not_production_ready():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["production_ready"] is False
    assert response.headers["cache-control"] == "no-store"


def test_shared_api_returns_engine_trace_and_verified_evidence():
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-TEST", "title": "Synthetic test", "evidence": [
            evidence("EV-1", "Successful login from a new browser profile", "authentication")
        ]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["case_id"] == "CASE-TEST"
    assert payload["integrity_summary"] == {"total": 1, "verified": 1, "mismatched": 0}
    assert payload["investigation"]["orchestrator"]["mode"] == "bounded_deterministic"
    assert payload["investigation"]["agent_trace"]
    assert payload["limitations"]


def test_tampered_digest_is_quarantined_and_not_referenced():
    item = evidence("EV-1", "Successful login from a new browser profile", "authentication")
    item["summary"] = "Changed after hashing: routine notice"
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-TAMPER", "evidence": [item]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["integrity_summary"]["mismatched"] == 1
    assert payload["integrity"][0]["valid"] is False
    assert all(not finding["evidence_ids"] for finding in payload["investigation"]["findings"])
    assert payload["investigation"]["timeline"][0]["integrity"].startswith("HASH MISMATCH")


def test_duplicate_evidence_ids_are_rejected():
    item = evidence("EV-1")
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-DUP", "evidence": [item, item]},
    )
    assert response.status_code == 422


def test_api_token_is_enforced_when_configured(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_API_TOKEN", "t" * 40)
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-AUTH", "evidence": []},
    )
    assert response.status_code == 401
    allowed = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-AUTH", "evidence": []},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert allowed.status_code == 200
    monkeypatch.delenv("FIRSTLIGHT_API_TOKEN", raising=False)


def test_missing_api_token_fails_closed(monkeypatch):
    monkeypatch.delenv("FIRSTLIGHT_API_TOKEN", raising=False)
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-AUTH", "evidence": []},
    )
    assert response.status_code == 503


def test_short_api_token_fails_closed(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_API_TOKEN", "weak")
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-AUTH", "evidence": []},
    )
    assert response.status_code == 503
    monkeypatch.delenv("FIRSTLIGHT_API_TOKEN", raising=False)



def test_chunked_oversized_request_is_rejected_without_content_length():
    # A streaming iterable avoids relying on Content-Length for the limit.
    chunks = iter([
        b'{"case_id":"CASE-OVERSIZE","title":"Oversized","evidence":[],"padding":"',
        b"x" * (2 * 1024 * 1024),
        b'"}',
    ])
    response = client.post(
        "/api/v1/cases/investigate",
        content=chunks,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body is too large"



def test_wazuh_alert_route_requires_separate_long_sync_token(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "w" * 40)
    response = client.get("/api/v1/integrations/wazuh/alerts")
    assert response.status_code == 401
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", raising=False)


def test_wazuh_alert_route_returns_bounded_read_only_events(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "w" * 40)
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_TENANT_ID", "11111111-1111-4111-8111-111111111111")
    monkeypatch.setattr(firstlight_api, "fetch_configured_alerts", lambda limit, since, order: [
        {"event_id": "wazuh-abc", "timestamp": "2026-10-20T08:00:00Z", "source": "wazuh",
         "kind": "security_alert", "summary": "Test alert", "details": {}, "provenance": {}}
    ])
    response = client.get(
        "/api/v1/integrations/wazuh/alerts?limit=10&tenant_id=11111111-1111-4111-8111-111111111111",
        headers={"Authorization": "Bearer " + "w" * 40},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "wazuh-indexer"
    assert payload["persisted"] is False
    assert payload["count"] == 1
    assert payload["events"][0]["event_id"] == "wazuh-abc"
    assert payload["events"][0]["event_id"] == "wazuh-abc"
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", raising=False)
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_TENANT_ID", raising=False)


def test_wazuh_alert_route_rejects_cross_tenant_access(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "w" * 40)
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_TENANT_ID", "11111111-1111-4111-8111-111111111111")
    response = client.get(
        "/api/v1/integrations/wazuh/alerts?tenant_id=22222222-2222-4222-8222-222222222222",
        headers={"Authorization": "Bearer " + "w" * 40},
    )
    assert response.status_code == 403
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", raising=False)
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_TENANT_ID", raising=False)


def test_wazuh_alert_route_rejects_bad_page_size(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "w" * 40)
    response = client.get(
        "/api/v1/integrations/wazuh/alerts?limit=9999",
        headers={"Authorization": "Bearer " + "w" * 40},
    )
    assert response.status_code == 422
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", raising=False)


def test_health_reports_ollama_disabled_without_blocking_deterministic_mode(monkeypatch):
    monkeypatch.delenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", raising=False)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["ollama"] == {"status": "disabled", "model_available": False}
    assert response.json()["model_agents_enabled"] is False


def test_health_reports_model_missing_without_exposing_runtime_configuration(monkeypatch):
    from types import SimpleNamespace
    import ai_provider

    class FakeClient:
        def __init__(self, timeout):
            assert timeout == 5
        class Models:
            @staticmethod
            def list():
                return SimpleNamespace(data=[SimpleNamespace(id="different-model:latest")])
        models = Models()

    monkeypatch.setenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", "true")
    monkeypatch.setenv("FIRSTLIGHT_OLLAMA_MODEL", "qwen2.5:3b")
    monkeypatch.setattr(ai_provider, "LocalOllamaClient", FakeClient)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["ollama"] == {"status": "model_missing", "model_available": False}
    assert "qwen2.5:3b" not in response.text



def test_ollama_readiness_reports_configured_model_without_claiming_availability(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", "false")
    monkeypatch.setenv("FIRSTLIGHT_OLLAMA_MODEL", "qwen2.5:3b")
    status = firstlight_api._ollama_readiness()
    assert status["status"] == "disabled"
    assert status["model_available"] is False
    assert status["configured_model"] == "qwen2.5:3b"
    assert "latency_ms" not in status


def test_ollama_readiness_reports_installed_model_and_latency(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", "true")
    monkeypatch.setenv("FIRSTLIGHT_OLLAMA_MODEL", "qwen2.5:3b")
    fake = SimpleNamespace(models=SimpleNamespace(list=lambda: SimpleNamespace(data=[SimpleNamespace(id="qwen2.5:3b")])))
    monkeypatch.setattr("ai_provider.LocalOllamaClient", lambda timeout: fake)
    status = firstlight_api._ollama_readiness()
    assert status["status"] == "ready"
    assert status["model_available"] is True
    assert status["installed_model"] == "qwen2.5:3b"
    assert isinstance(status["latency_ms"], int)
    assert status["latency_ms"] >= 0
