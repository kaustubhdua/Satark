from __future__ import annotations

import pytest

import integrations.response_actions as actions


def configure(monkeypatch):
    monkeypatch.setenv("SATARK_ENABLE_LIVE_RESPONSE", "true")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_API_URL", "https://wazuh-manager.example.test:55000")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_USERNAME", "lab-user")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_MANAGER_PASSWORD", "lab-password")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS", "001,002")
    monkeypatch.setenv(
        "FIRSTLIGHT_WAZUH_PROTECTED_IPS",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
    )
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_RESPONSE_TTL_VERIFIED", "true")
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_RESPONSE_TTL_SECONDS", "300")


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


def test_block_ip_sends_only_fixed_command_to_one_allowlisted_linux_agent(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(actions, "_token", lambda: "fake-jwt")
    captured = {}

    def fake_request(url, **kwargs):
        if url.endswith("/manager/info"):
            return 200, {"data": {"affected_items": [{"version": "v4.14.10"}]}}
        if "/agents?" in url:
            return 200, {"data": {"affected_items": [{"id": "001", "status": "active", "os": {"platform": "linux", "name": "Ubuntu"}}]}}
        captured["url"] = url
        captured.update(kwargs)
        return 200, {"error": 0, "data": {"affected_items": ["001"], "failed_items": []}}

    monkeypatch.setattr(actions, "_request", fake_request)
    result = actions.execute_wazuh_response(
        "wazuh.block_ip", "001", {"ip_address": "8.8.8.8"},
        confirmation="CONFIRM BLOCK_IP 001", reason="Authorized disposable lab exercise",
    )
    assert result.provider == "Wazuh Active Response"
    assert result.status == "submitted"
    assert "/active-response?agents_list=001" in captured["url"]
    assert "wait_for_complete" not in captured["url"]
    assert captured["method"] == "PUT"
    assert captured["headers"]["Authorization"] == "Bearer fake-jwt"
    assert captured["body"] == {"command": "firewall-drop", "arguments": ["8.8.8.8"], "custom": False}


def test_live_response_controls_are_hidden_when_feature_flag_is_off(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv("SATARK_ENABLE_LIVE_RESPONSE", "false")
    assert actions.available_response_actions() == []


def test_live_response_is_hidden_until_ttl_verification(monkeypatch):
    configure(monkeypatch)
    monkeypatch.delenv("FIRSTLIGHT_WAZUH_RESPONSE_TTL_VERIFIED")
    assert actions.available_response_actions() == []
    with pytest.raises(actions.ResponseIntegrationError, match="automatic timeout and reversal"):
        actions.preflight_live_response("wazuh.block_ip", "001", "CONFIRM BLOCK_IP 001")


def test_response_ttl_must_be_between_60_and_900_seconds(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_RESPONSE_TTL_SECONDS", "30")
    with pytest.raises(actions.ResponseIntegrationError, match="between 60 and 900"):
        actions.preflight_live_response("wazuh.block_ip", "001", "CONFIRM BLOCK_IP 001")


def test_block_ip_rejects_protected_and_non_global_addresses(monkeypatch):
    configure(monkeypatch)
    with pytest.raises(actions.ResponseIntegrationError, match="protected infrastructure"):
        actions._validate_payload("wazuh.block_ip", {"ip_address": "10.1.2.3"})
    with pytest.raises(actions.ResponseIntegrationError, match="globally routable"):
        actions._validate_payload("wazuh.block_ip", {"ip_address": "203.0.113.9"})
    with pytest.raises(actions.ResponseIntegrationError, match="valid IPv4"):
        actions._validate_payload("wazuh.block_ip", {"ip_address": "not-an-ip"})


def test_account_disable_is_not_exposed_until_reversible_ttl_exists(monkeypatch):
    configure(monkeypatch)
    assert "wazuh.disable_account" not in actions.available_response_actions()
    with pytest.raises(actions.ResponseIntegrationError, match="account disable is not supported"):
        actions.preflight_live_response("wazuh.disable_account", "001", "CONFIRM DISABLE_ACCOUNT 001")


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

    def fake_request(url, **kwargs):
        if url.endswith("/manager/info"):
            return 200, {"data": {"affected_items": [{"version": "v4.14.10"}]}}
        if "/agents?" in url:
            return 200, {"data": {"affected_items": [{"id": "002", "status": "active", "os": {"platform": "linux"}}]}}
        raise AssertionError("Active Response must not run for a mismatched agent")

    monkeypatch.setattr(actions, "_request", fake_request)
    with pytest.raises(actions.ResponseIntegrationError, match="missing, mismatched, or not active"):
        actions.execute_wazuh_response(
            "wazuh.block_ip", "001", {"ip_address": "8.8.8.8"},
            confirmation="CONFIRM BLOCK_IP 001", reason="Authorized disposable lab exercise",
        )


def test_manager_version_gate_rejects_wazuh_5_before_submission(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(actions, "_token", lambda: "fake-jwt")
    calls = []

    def fake_request(url, **kwargs):
        calls.append(url)
        return 200, {"data": {"affected_items": [{"version": "v5.0.0"}]}}

    monkeypatch.setattr(actions, "_request", fake_request)
    with pytest.raises(actions.ResponseIntegrationError, match="requires a verified Wazuh Manager 4.14.x"):
        actions.execute_wazuh_response(
            "wazuh.block_ip", "001", {"ip_address": "8.8.8.8"},
            confirmation="CONFIRM BLOCK_IP 001", reason="Authorized disposable lab exercise",
        )
    assert calls == ["https://wazuh-manager.example.test:55000/manager/info"]


def test_block_ip_rejects_unsupported_agent_os(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(actions, "_token", lambda: "fake-jwt")

    def fake_request(url, **kwargs):
        if url.endswith("/manager/info"):
            return 200, {"data": {"affected_items": [{"version": "v4.14.10"}]}}
        if "/agents?" in url:
            return 200, {"data": {"affected_items": [{"id": "001", "status": "active", "os": {"platform": "windows", "name": "Microsoft Windows 11"}}]}}
        raise AssertionError("Active Response must not run for an unsupported OS")

    monkeypatch.setattr(actions, "_request", fake_request)
    with pytest.raises(actions.ResponseIntegrationError, match="restricted to verified Linux"):
        actions.execute_wazuh_response(
            "wazuh.block_ip", "001", {"ip_address": "8.8.8.8"},
            confirmation="CONFIRM BLOCK_IP 001", reason="Authorized disposable lab exercise",
        )
