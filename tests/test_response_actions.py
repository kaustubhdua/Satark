from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from integrations.response_actions import (
    ResponseIntegrationError,
    _validate_payload,
    live_response_enabled,
    preflight_live_response,
)


class WazuhResponseGuardrailTests(unittest.TestCase):
    def configure(self):
        return patch.dict(os.environ, {
            "SATARK_ENABLE_LIVE_RESPONSE": "true",
            "FIRSTLIGHT_WAZUH_MANAGER_API_URL": "https://wazuh-manager.example.test:55000",
            "FIRSTLIGHT_WAZUH_MANAGER_USERNAME": "lab-user",
            "FIRSTLIGHT_WAZUH_MANAGER_PASSWORD": "lab-password",
            "FIRSTLIGHT_WAZUH_RESPONSE_AGENT_IDS": "001",
            "FIRSTLIGHT_WAZUH_PROTECTED_IPS": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
            "FIRSTLIGHT_WAZUH_RESPONSE_TTL_VERIFIED": "true",
            "FIRSTLIGHT_WAZUH_RESPONSE_TTL_SECONDS": "300",
        }, clear=True)

    def test_live_actions_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ResponseIntegrationError, "disabled"):
                preflight_live_response("wazuh.block_ip", "001", "CONFIRM BLOCK_IP 001")

    def test_exact_confirmation_required(self):
        with self.configure():
            with self.assertRaisesRegex(ResponseIntegrationError, "Explicit confirmation"):
                preflight_live_response("wazuh.block_ip", "001", "yes")

    def test_confirmation_is_target_bound(self):
        with self.configure():
            with self.assertRaisesRegex(ResponseIntegrationError, "Explicit confirmation"):
                preflight_live_response("wazuh.block_ip", "001", "CONFIRM BLOCK_IP 002")

    def test_live_capability_flag(self):
        with patch.dict(os.environ, {"SATARK_ENABLE_LIVE_RESPONSE": "true"}):
            self.assertTrue(live_response_enabled())
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(live_response_enabled())

    def test_invalid_ip_fails_before_authentication(self):
        with self.assertRaisesRegex(ResponseIntegrationError, "valid IPv4"):
            _validate_payload("wazuh.block_ip", {"ip_address": "not-an-ip"})

    def test_protected_account_fails_before_authentication(self):
        with self.assertRaisesRegex(ResponseIntegrationError, "not allowlisted"):
            _validate_payload("wazuh.disable_account", {"username": "root"})


if __name__ == "__main__":
    unittest.main()
