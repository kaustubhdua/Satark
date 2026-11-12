from __future__ import annotations

import json

import scripts.firstlight_live_response as cli


def test_wazuh_response_cli_is_preview_only(capsys, monkeypatch):
    monkeypatch.setenv("FIRSTLIGHT_WAZUH_PROTECTED_IPS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8")
    code = cli.main([
        "--action", "block-ip",
        "--agent-id", "001",
        "--ip-address", "8.8.8.8",
        "--reason", "case FL-1",
    ])
    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["provider"] == "Wazuh Active Response"
    assert output["action"] == "wazuh.block_ip"
    assert output["agent_id"] == "001"
    assert output["ip_address"] == "8.8.8.8"
    assert output["live_execution"] is False
    assert "third executor" in output["execution_route"]


def test_wazuh_response_cli_rejects_invalid_agent_and_payload(capsys):
    assert cli.main([
        "--action", "block-ip", "--agent-id", "not-an-agent",
        "--ip-address", "203.0.113.9", "--reason", "case FL-1",
    ]) == 2
    assert "agent ID must be numeric" in capsys.readouterr().err

    assert cli.main([
        "--action", "block-ip", "--agent-id", "001",
        "--ip-address", "not-an-ip", "--reason", "case FL-1",
    ]) == 2
    assert "valid IPv4" in capsys.readouterr().err


def test_disable_account_preview_is_rejected_until_supported(capsys):
    code = cli.main([
        "--action", "disable-account", "--agent-id", "001",
        "--username", "lab-user", "--reason", "case FL-2",
    ])
    assert code == 2
    assert "not allowlisted" in capsys.readouterr().err
