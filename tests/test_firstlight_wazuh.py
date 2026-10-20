from __future__ import annotations

import base64
import json
from io import BytesIO

import pytest

import firstlight_wazuh as wazuh


def hit(*, doc_id="abc-1", index="wazuh-alerts-4.x-2026.10.20", timestamp="2026-10-20T08:00:00.000Z"):
    return {
        "_id": doc_id,
        "_index": index,
        "_source": {
            "@timestamp": timestamp,
            "rule": {"id": "5710", "level": 8, "description": "Multiple authentication failures", "groups": ["authentication_failed"]},
            "agent": {"id": "004", "name": "lab-workstation"},
            "manager": {"name": "wazuh-manager"},
            "data": {"srcip": "192.0.2.10"},
            "location": "EventChannel",
            "decoder": {"name": "windows_eventchannel"},
            "full_log": "Example lab alert",
        },
    }


def config(**overrides):
    values = {
        "base_url": "https://wazuh-indexer.internal:9200",
        "username": "firstlight-reader",
        "password": "not-a-real-secret",
        "index_pattern": "wazuh-alerts-*",
        "timeout_seconds": 8,
        "allow_http": False,
        "allowed_agent_ids": ("004",),
    }
    values.update(overrides)
    return wazuh.WazuhIndexerConfig(**values)


def test_normalize_alert_preserves_provenance_and_stable_identity():
    first = wazuh.normalize_alert(hit())
    second = wazuh.normalize_alert(hit())
    assert first["event_id"] == second["event_id"]
    assert first["source"] == "wazuh"
    assert first["kind"] == "security_alert"
    assert first["timestamp"] == "2026-10-20T08:00:00.000Z"
    assert first["details"]["rule_id"] == "5710"
    assert first["details"]["agent_name"] == "lab-workstation"
    assert len(first["provenance"]["source_record_sha256"]) == 64
    assert first["provenance"]["provider"] == "wazuh-indexer"
    assert "source_snapshot_json" not in first
    preserved = wazuh.normalize_alert(hit(), include_source_snapshot=True)
    snapshot = preserved["source_snapshot_json"]
    assert json.loads(snapshot) == hit()["_source"]
    import hashlib
    assert hashlib.sha256(snapshot.encode("utf-8")).hexdigest() == preserved["provenance"]["source_record_sha256"]


def test_normalize_alert_rejects_naive_or_missing_timestamp():
    with pytest.raises(ValueError, match="timezone"):
        wazuh.normalize_alert(hit(timestamp="2026-10-20T08:00:00"))
    malformed = hit()
    del malformed["_source"]["@timestamp"]
    with pytest.raises(ValueError, match="timestamp"):
        wazuh.normalize_alert(malformed)


def test_config_requires_https_by_default(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_URL", "http://wazuh-indexer:9200")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_USERNAME", "reader")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", "secret")
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_ALLOW_HTTP", raising=False)
    with pytest.raises(wazuh.WazuhConfigurationError, match="HTTPS"):
        wazuh.WazuhIndexerConfig.from_env()


def test_config_requires_an_explicit_agent_allowlist(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_URL", "https://wazuh-indexer:9200")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_USERNAME", "reader")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", "secret")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS", raising=False)
    with pytest.raises(wazuh.WazuhConfigurationError, match="ALLOWED_AGENT_IDS"):
        wazuh.WazuhIndexerConfig.from_env()


def test_config_rejects_credentials_in_url_and_unsafe_index(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_URL", "https://reader:secret@wazuh-indexer:9200")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_USERNAME", "reader")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", "secret")
    with pytest.raises(wazuh.WazuhConfigurationError):
        wazuh.WazuhIndexerConfig.from_env()
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_URL", "https://wazuh-indexer:9200")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_USERNAME", "reader")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", "secret")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_INDEX_PATTERN", "../other-index")
    with pytest.raises(wazuh.WazuhConfigurationError, match="index pattern"):
        wazuh.WazuhIndexerConfig.from_env()


def test_fetch_alerts_sends_bounded_query_and_basic_auth(monkeypatch):
    seen = {}

    class Response(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["auth"] = request.get_header("Authorization")
        seen["payload"] = json.loads(request.data)
        return Response(json.dumps({"hits": {"hits": [hit()]}}).encode())

    monkeypatch.setattr(wazuh, "_open_url", fake_urlopen)
    result = wazuh.WazuhIndexerClient(config()).fetch_alerts(limit=10, since="2026-10-20T00:00:00Z", until="2026-10-20T23:59:00Z", offset=20, order="desc")
    assert len(result) == 1
    assert seen["url"] == "https://wazuh-indexer.internal:9200/wazuh-alerts-*/_search"
    assert seen["timeout"] == 8
    assert seen["auth"] == "Basic " + base64.b64encode(b"firstlight-reader:not-a-real-secret").decode()
    assert seen["payload"]["size"] == 10
    assert seen["payload"]["from"] == 20
    assert {"terms": {"agent.id": ["004"]}} in seen["payload"]["query"]["bool"]["filter"]
    assert {"range": {"@timestamp": {"gte": "2026-10-20T00:00:00.000Z", "lte": "2026-10-20T23:59:00.000Z"}}} in seen["payload"]["query"]["bool"]["filter"]
    assert seen["payload"]["track_total_hits"] is False
    assert seen["payload"]["sort"][0]["@timestamp"]["order"] == "desc"


@pytest.mark.parametrize("limit", [0, -1, 501, True])
def test_fetch_alerts_rejects_unbounded_page_sizes(limit):
    with pytest.raises(ValueError, match="limit"):
        wazuh.WazuhIndexerClient(config()).fetch_alerts(limit=limit)


def test_fetch_alerts_fails_closed_on_malformed_hit(monkeypatch):
    class Response(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    monkeypatch.setattr(wazuh, "_open_url", lambda *args, **kwargs: Response(b'{"hits":{"hits":[{"_source":{}}]}}'))
    with pytest.raises(wazuh.WazuhConnectorError, match="malformed"):
        wazuh.WazuhIndexerClient(config()).fetch_alerts()
