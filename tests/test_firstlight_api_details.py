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
    tenant_id = "123e4567-e89b-42d3-a456-426614174000"
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "w" * 40)
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_TENANT_ID", tenant_id)
    monkeypatch.setattr(firstlight_api, "fetch_configured_alerts", lambda limit, since, order: [
        {"event_id": "wazuh-abc", "timestamp": "2026-10-20T08:00:00Z", "source": "wazuh",
         "kind": "security_alert", "summary": "Test alert", "details": {}, "provenance": {}}
    ])
    response = client.get(
        f"/api/v1/integrations/wazuh/alerts?limit=10&tenant_id={tenant_id}",
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


def test_wazuh_alert_route_rejects_bad_page_size(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "w" * 40)
    response = client.get(
        "/api/v1/integrations/wazuh/alerts?limit=9999",
        headers={"Authorization": "Bearer " + "w" * 40},
    )
    assert response.status_code == 422
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", raising=False)


def test_structured_details_are_hash_verified_and_used_by_deterministic_engine():
    details = {"rule": "unusual_parent_child", "process": "powershell.exe", "parent": "outlook.exe", "host": "LAB-01"}
    record = {
        "event_id": "wazuh-process-1",
        "timestamp": "2026-10-20T08:00:00.000Z",
        "source": "Wazuh",
        "kind": "process",
        "summary": "Unusual script interpreter launched",
        "details": details,
    }
    item = {
        "id": record["event_id"], "time": record["timestamp"], "source": record["source"],
        "kind": record["kind"], "summary": record["summary"], "details": details,
        "digest": sha256_record(record),
    }
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-WAZUH-DETAILS", "title": "Wazuh lab event", "evidence": [item]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["integrity_summary"] == {"total": 1, "verified": 1, "mismatched": 0}
    assert any(finding["title"] == "Unusual process ancestry" for finding in payload["investigation"]["findings"])


def test_structured_details_are_bounded():
    item = evidence("EV-DETAILS")
    item["details"] = {"oversized": "x" * (16 * 1024 + 1)}
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-DETAILS-OVERSIZE", "evidence": [item]},
    )
    assert response.status_code == 422


def test_wazuh_source_rule_level_becomes_a_cautious_evidence_linked_finding():
    details = {"provider": "wazuh-indexer", "rule_id": "5710", "rule_level": 12, "rule_groups": ["authentication_failed"]}
    record = {
        "event_id": "wazuh-alert-12",
        "timestamp": "2026-10-20T08:00:00.000Z",
        "source": "Wazuh",
        "kind": "security_alert",
        "summary": "Authentication failures detected",
        "details": details,
    }
    response = client.post(
        "/api/v1/cases/investigate",
        json={"case_id": "CASE-WAZUH-LEVEL", "evidence": [{
            "id": record["event_id"], "time": record["timestamp"], "source": record["source"],
            "kind": record["kind"], "summary": record["summary"], "details": details,
            "digest": sha256_record(record),
        }]},
    )
    assert response.status_code == 200
    payload = response.json()
    finding = next(row for row in payload["investigation"]["findings"] if row["title"] == "Wazuh source detection alert")
    assert finding["severity"] == "critical"
    assert finding["rule_id"] == "FL-WAZUH-001"
    assert finding["rule_version"] == "1.0.0"
    assert finding["attack_techniques"] == []
    assert finding["evidence_ids"] == ["wazuh-alert-12"]
    assert "not an independently calibrated probability" in finding["explanation"]
