from __future__ import annotations

from datetime import datetime, timezone
import hashlib

import pytest

from scripts.firstlight_live_wazuh_investigation import build_live_report, run_live_investigation


def alert(doc_id: str = "doc-1", level: int = 12) -> dict:
    source_hash = hashlib.sha256(doc_id.encode()).hexdigest()
    return {
        "event_id": "wazuh-" + hashlib.sha256(("alerts:" + doc_id).encode()).hexdigest()[:32],
        "timestamp": "2026-10-20T08:00:00.000Z",
        "source": "wazuh",
        "kind": "security_alert",
        "summary": "Multiple authentication failures",
        "details": {
            "provider": "wazuh-indexer",
            "index": "wazuh-alerts-4.x-2026.10.20",
            "document_id": doc_id,
            "rule_id": "5710",
            "rule_level": level,
            "rule_groups": ["authentication_failed"],
            "agent_id": "004",
            "agent_name": "lab-workstation",
            "source_record_sha256": source_hash,
        },
        "provenance": {
            "provider": "wazuh-indexer",
            "index": "wazuh-alerts-4.x-2026.10.20",
            "document_id": doc_id,
            "source_timestamp": "2026-10-20T08:00:00.000Z",
            "source_record_sha256": source_hash,
        },
    }


def test_live_report_preserves_real_source_provenance_without_creating_response_proposals():
    report = build_live_report(
        [alert()],
        since="2026-10-20T00:00:00.000Z",
        until="2026-10-20T23:59:59.000Z",
        generated_at="2026-10-20T09:00:00Z",
    )
    assert report["collection"]["mode"] == "live_configured_wazuh_indexer"
    assert report["collection"]["alerts_returned"] == 1
    assert report["collection"]["evidence_integrity_valid"] == 1
    assert report["collection"]["source_records"][0]["document_id"] == "doc-1"
    assert report["case"]["source"] == "wazuh-indexer"
    assert report["response"]["mode"] == "not_configured"
    assert report["response"]["live_action_executed"] is False
    assert report["response"]["proposals"] == []
    assert report["investigation"]["findings"]
    assert all(item["evidence_ids"] for item in report["investigation"]["findings"] if item["state"] == "supported")


def test_live_report_rejects_empty_or_non_wazuh_input():
    with pytest.raises(ValueError, match="no alerts"):
        build_live_report([], since="2026-10-20T00:00:00Z", until="2026-10-20T01:00:00Z")
    with pytest.raises(ValueError, match="provenance-bearing Wazuh"):
        build_live_report(
            [{"event_id": "fake", "source": "endpoint"}],
            since="2026-10-20T00:00:00Z",
            until="2026-10-20T01:00:00Z",
        )


def test_run_live_investigation_uses_bounded_query_and_rejects_reversed_window():
    calls = {}

    def fetcher(**kwargs):
        calls.update(kwargs)
        return [alert()]

    report = run_live_investigation(
        since="2026-10-20T00:00:00Z",
        until="2026-10-20T01:00:00+00:00",
        limit=7,
        fetcher=fetcher,
    )
    assert calls == {
        "limit": 7,
        "since": "2026-10-20T00:00:00.000Z",
        "until": "2026-10-20T01:00:00.000Z",
        "order": "asc",
    }
    assert report["collection"]["alerts_returned"] == 1

    with pytest.raises(ValueError, match="earlier than or equal"):
        run_live_investigation(
            since="2026-10-20T02:00:00Z",
            until="2026-10-20T01:00:00Z",
            fetcher=fetcher,
        )
