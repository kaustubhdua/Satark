from __future__ import annotations

import pytest

import integrations.response_actions as actions


def configure(monkeypatch):
    monkeypatch.setenv("SATARK_ENABLE_LIVE_RESPONSE", "true")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_API_URL", "https://wazuh-manager.example.test:55000")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_USERNAME", "lab-user")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_PASSWORD", "lab-password")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS", "001,002")


def test_preflight_requires_explicit_agent_allowlist(monkeypatch):
    configure(monkeypatch)
    with pytest.raises(actions.ResponseIntegrationError, match="not in"):
        actions.preflight_live_response("wazuh.block_ip", "003", "CONFIRM BLOCK_IP 003")


def test_preflight_rejects_arbitrary_action_and_wrong_confirmation(monkeypatch):
    configure(monkeypatch)
    with pytest.raises(actions.ResponseIntegrationError, match="not allowlisted"):
        actions.preflight_live_response("wazuh.run_shell", "001", "CONFIRM RUN 001")
    with pytest.raises(actions.ResponseIntegrationError, match="Explicit confirmation"):
        actions.preflight_live_response("wazuh.block_ip", "001", "yes")


def test_block_ip_sends_only_fixed_command_to_one_allowlisted_agent(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(actions, "_token", lambda: "fake-jwt")
    captured = {}

    def fake_request(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return 200, {"error": 0, "data": {"affected_items": ["001"], "failed_items": []}}

    monkeypatch.setattr(actions, "_request", fake_request)
    result = actions.execute_wazuh_response(
        "wazuh.block_ip", "001", {"ip_address": "203.0.113.9"},
        confirmation="CONFIRM BLOCK_IP 001", reason="Authorized disposable lab exercise",
    )
    assert result.provider == "Wazuh Active Response"
    assert result.status == "submitted"
    assert "/active-response?agents_list=001" in captured["url"]
    assert captured["method"] == "PUT"
    assert captured["headers"]["Authorization"] == "Bearer fake-jwt"
    assert captured["body"] == {"command": "firewall-drop", "arguments": ["203.0.113.9"], "custom": False}


def test_disable_account_uses_allowlisted_builtin_and_strict_username(monkeypatch):
    configure(monkeypatch)
    assert actions._validate_payload("wazuh.disable_account", {"username": "lab-user"}) == ["lab-user"]
    with pytest.raises(actions.ResponseIntegrationError, match="ACCOUNT_DISABLE_AGENT_IDS"):
        actions.preflight_live_response("wazuh.disable_account", "001", "CONFIRM DISABLE_ACCOUNT 001")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_ACCOUNT_DISABLE_AGENT_IDS", "001")
    actions.preflight_live_response("wazuh.disable_account", "001", "CONFIRM DISABLE_ACCOUNT 001")
    with pytest.raises(actions.ResponseIntegrationError, match="unsupported"):
        actions._validate_payload("wazuh.disable_account", {"username": "lab;user"})
    with pytest.raises(actions.ResponseIntegrationError, match="valid IPv4"):
        actions._validate_payload("wazuh.block_ip", {"ip_address": "not-an-ip"})


def test_http_is_only_allowed_for_localhost_lab(monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_API_URL", "http://wazuh-manager.internal:55000")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_ALLOW_HTTP", "true")
    with pytest.raises(actions.ResponseIntegrationError, match="HTTPS"):
        actions._base_url()
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_API_URL", "http://127.0.0.1:55000")
    assert actions._base_url() == "http://127.0.0.1:55000"

def test_block_ip_rejects_acknowledgement_for_different_agent(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(actions, "_token", lambda: "fake-jwt")
    monkeypatch.setattr(actions, "_request", lambda *args, **kwargs: (
        200, {"error": 0, "data": {"affected_items": ["002"], "failed_items": []}}
    ))
    with pytest.raises(actions.ResponseIntegrationError, match="mismatched"):
        actions.execute_wazuh_response(
            "wazuh.block_ip", "001", {"ip_address": "203.0.113.9"},
            confirmation="CONFIRM BLOCK_IP 001", reason="Authorized disposable lab exercise",
        )

def test_disable_account_rejects_root_and_option_like_usernames():
    with pytest.raises(actions.ResponseIntegrationError, match="invalid or protected"):
        actions._validate_payload("wazuh.disable_account", {"username": "root"})
    with pytest.raises(actions.ResponseIntegrationError, match="invalid or protected"):
        actions._validate_payload("wazuh.disable_account", {"username": "-option"})
