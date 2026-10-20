"""Integration tests for the read-only live Wazuh investigation API."""
from __future__ import annotations

from fastapi.testclient import TestClient

import firstlight_api

client = TestClient(firstlight_api.app)
SYNC_TOKEN = "test-wazuh-sync-token-" + "x" * 40
TENANT = "123e4567-e89b-42d3-a456-426614174000"


def live_event():
    return {
        "event_id": "wazuh-0123456789abcdef0123456789abcdef",
        "timestamp": "2026-10-20T08:00:00.000Z",
        "source": "wazuh",
        "kind": "security_alert",
        "summary": "Multiple authentication failures",
        "details": {
            "provider": "wazuh-indexer",
            "index": "wazuh-alerts-4.x-2026.10.20",
            "document_id": "source-alert-1",
            "rule_id": "5710",
            "rule_level": 8,
            "agent_id": "004",
            "agent_name": "lab-workstation",
            "source_record_sha256": "a" * 64,
            "data": {"srcip": "192.0.2.10"},
        },
        "provenance": {
            "provider": "wazuh-indexer",
            "source_record_sha256": "a" * 64,
        },
    }


def configure(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", SYNC_TOKEN)
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_TENANT_ID", TENANT)


def test_live_wazuh_investigation_returns_real_connector_records_as_read_only(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(firstlight_api, "fetch_configured_alerts", lambda **kwargs: [live_event()])
    response = client.post(
        "/api/v1/integrations/wazuh/investigate",
        headers={"Authorization": "Bearer " + SYNC_TOKEN},
        params={"tenant_id": TENANT, "limit": 1},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["mode"] == "live_read_only_investigation"
    assert payload["persisted"] is False
    assert payload["fetched_count"] == 1
    assert payload["integrity_summary"] == {"total": 1, "verified": 1, "mismatched": 0}
    assert payload["evidence"][0]["evidence_id"] == live_event()["event_id"]
    assert len(payload["evidence"][0]["sha256"]) == 64
    assert payload["investigation"]["case_id"] == payload["case_id"]
    assert any("does not independently verify" in item for item in payload["limitations"])


def test_live_wazuh_investigation_rejects_missing_or_wrong_sync_token(monkeypatch):
    configure(monkeypatch)
    response = client.post(
        "/api/v1/integrations/wazuh/investigate",
        params={"tenant_id": TENANT},
    )
    assert response.status_code == 401


def test_live_wazuh_investigation_rejects_cross_tenant_request(monkeypatch):
    configure(monkeypatch)
    response = client.post(
        "/api/v1/integrations/wazuh/investigate",
        headers={"Authorization": "Bearer " + SYNC_TOKEN},
        params={"tenant_id": "123e4567-e89b-42d3-a456-426614174001"},
    )
    assert response.status_code == 403


def test_live_wazuh_investigation_reports_empty_result_without_fabricating_events(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(firstlight_api, "fetch_configured_alerts", lambda **kwargs: [])
    response = client.post(
        "/api/v1/integrations/wazuh/investigate",
        headers={"Authorization": "Bearer " + SYNC_TOKEN},
        params={"tenant_id": TENANT},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["fetched_count"] == 0
    assert payload["investigation"] is None
    assert payload["integrity_summary"] == {"total": 0, "verified": 0, "mismatched": 0}


def test_live_wazuh_investigation_caps_page_size(monkeypatch):
    configure(monkeypatch)
    response = client.post(
        "/api/v1/integrations/wazuh/investigate",
        headers={"Authorization": "Bearer " + SYNC_TOKEN},
        params={"tenant_id": TENANT, "limit": 101},
    )
    assert response.status_code == 422
