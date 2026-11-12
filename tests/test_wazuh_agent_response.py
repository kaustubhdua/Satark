from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from integrations.wazuh_agent import satark_response_state as state


class FakeIptables:
    def __init__(self):
        self.rules: set[str] = set()
        self.calls: list[list[str]] = []

    def run(self, command, **kwargs):
        args = list(command[1:])
        self.calls.append(args)
        if args[0] == "-C":
            key = " ".join(args[2:])
            return subprocess.CompletedProcess(command, 0 if key in self.rules else 1, "", "")
        if args[0] == "-I":
            key = " ".join(args[3:])
            self.rules.add(key)
            return subprocess.CompletedProcess(command, 0, "", "")
        if args[0] == "-D":
            key = " ".join(args[2:])
            self.rules.discard(key)
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"Unexpected iptables operation: {args}")


@pytest.fixture
def firewall(monkeypatch, tmp_path):
    fake = FakeIptables()
    monkeypatch.setenv("SATARK_RESPONSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(state.shutil, "which", lambda _name: "/usr/sbin/iptables")
    monkeypatch.setattr(state.subprocess, "run", fake.run)
    return fake, tmp_path / "state" / "blocks.json"


def test_add_block_persists_expiry_and_watchdog_reverses_it(firewall):
    fake, state_file = firewall
    result = state.add_block("8.8.8.8", "60", now=1000)
    assert result == {"status": "blocked", "ip_address": "8.8.8.8", "expires_at": 1060}
    assert state_file.exists()
    assert json.loads(state_file.read_text()) == {"8.8.8.8": 1060.0}
    assert state.expire_due(now=1059) == []
    assert state.expire_due(now=1061) == ["8.8.8.8"]
    assert json.loads(state_file.read_text()) == {}
    assert any(call[0] == "-D" for call in fake.calls)


def test_repeated_block_extends_expiry_without_duplicate_rule(firewall):
    fake, state_file = firewall
    state.add_block("8.8.8.8", "60", now=1000)
    result = state.add_block("8.8.8.8", "120", now=1010)
    assert result["status"] == "extended"
    assert result["expires_at"] == 1130
    assert len([call for call in fake.calls if call[0] == "-I"]) == 1


def test_orphaned_satark_rule_fails_closed_without_duplicate_insert(firewall):
    fake, state_file = firewall
    fake.rules.add(" ".join(state._owned_rule("8.8.8.8")))
    with pytest.raises(state.ResponseStateError, match="ownership record"):
        state.add_block("8.8.8.8", "60", now=1000)
    assert not state_file.exists()
    assert len([call for call in fake.calls if call[0] == "-I"]) == 0


def test_preexisting_unowned_firewall_rule_is_never_removed(firewall):
    fake, state_file = firewall
    fake.rules.add("-s 8.8.8.8 -j DROP")
    result = state.add_block("8.8.8.8", "60", now=1000)
    assert result["status"] == "already_blocked_unowned"
    assert not state_file.exists()
    assert state.expire_due(now=2000) == []
    assert not any(call[0] == "-D" for call in fake.calls)


@pytest.mark.parametrize("value", ["203.0.113.9", "10.0.0.1", "127.0.0.1", "not-an-ip"])
def test_rejects_non_global_or_invalid_ip(value, firewall):
    with pytest.raises(state.ResponseStateError):
        state.add_block(value, "60", now=1000)


@pytest.mark.parametrize("value", ["0", "59", "901", "forever"])
def test_rejects_out_of_range_ttl(value, firewall):
    with pytest.raises(state.ResponseStateError):
        state.add_block("8.8.8.8", value, now=1000)


def test_manual_delete_only_removes_satark_owned_rule(firewall):
    fake, state_file = firewall
    state.add_block("8.8.8.8", "300", now=1000)
    # An operator may add an independent rule for the same address after
    # SATARK's action. Reversal must remove only the tagged SATARK rule.
    fake.rules.add("-s 8.8.8.8 -j DROP")
    result = state.remove_block("8.8.8.8")
    assert result["status"] == "removed"
    assert json.loads(state_file.read_text()) == {}
    assert "-s 8.8.8.8 -j DROP" in fake.rules
    assert not any(rule.startswith("-s 8.8.8.8 -m comment") for rule in fake.rules)
    assert any(call[0] == "-D" for call in fake.calls)


def test_corrupt_state_fails_closed(firewall):
    _fake, state_file = firewall
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{not-json")
    with pytest.raises(state.ResponseStateError, match="unreadable"):
        state.expire_due(now=5000)


def test_watchdog_service_keeps_required_runtime_lock_and_minimal_capabilities():
    service = (
        Path(__file__).resolve().parents[1]
        / "integrations/wazuh_agent/satark-response-watchdog.service"
    ).read_text(encoding="utf-8")
    assert "ProtectSystem=strict" in service
    assert "ReadWritePaths=/var/lib/satark-response /run" in service
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in service
    assert "AmbientCapabilities=CAP_NET_ADMIN" in service
    assert "NoNewPrivileges=true" in service
    assert "Restart=always" in service
