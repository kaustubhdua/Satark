import unittest

from scripts.satark_track1_acceptance_preflight import validate


class AcceptancePreflightTests(unittest.TestCase):
    def test_missing_tenant_config_lists_variable_names_only(self):
        errors = validate("tenant", {})
        self.assertTrue(errors)
        self.assertIn("SATARK_TEST_POSTGRES_URL", errors[0])
        self.assertNotIn("postgres-password", " ".join(errors))

    def test_tenant_requires_isolated_postgres_and_distinct_identities(self):
        env = {
            "SATARK_TEST_POSTGRES_URL": "postgresql+psycopg://satark:secret@localhost:5432/satark_test",
            "SATARK_TEST_USER_A_EMAIL": "a@example.test",
            "SATARK_TEST_USER_A_PASSWORD": "not-logged",
            "SATARK_TEST_TENANT_A_ID": "11111111-1111-4111-8111-111111111111",
            "SATARK_TEST_USER_B_EMAIL": "b@example.test",
            "SATARK_TEST_USER_B_PASSWORD": "not-logged",
            "SATARK_TEST_TENANT_B_ID": "22222222-2222-4222-8222-222222222222",
            "SATARK_TEST_VIEWER_EMAIL": "viewer@example.test",
            "SATARK_TEST_VIEWER_PASSWORD": "not-logged",
            "SATARK_TEST_VIEWER_TENANT_ID": "33333333-3333-4333-8333-333333333333",
            "SATARK_DATABASE_URL": "postgresql+psycopg://satark:secret@localhost:5432/satark_prod",
        }
        self.assertEqual(validate("tenant", env), [])
        env["SATARK_DATABASE_URL"] = env["SATARK_TEST_POSTGRES_URL"]
        self.assertTrue(any("isolated database" in e for e in validate("tenant", env)))
        env["SATARK_TEST_TENANT_B_ID"] = env["SATARK_TEST_TENANT_A_ID"]
        self.assertTrue(any("must be distinct" in e for e in validate("tenant", env)))

    def test_wazuh_write_confirmation_and_target_binding_are_mandatory(self):
        env = {
            "FIRSTLIGHT_WAZUH_INDEXER_URL": "https://wazuh.example.test",
            "FIRSTLIGHT_WAZUH_INDEXER_USERNAME": "readonly",
            "FIRSTLIGHT_WAZUH_INDEXER_PASSWORD": "not-logged",
            "FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS": "004,005",
            "FIRSTLIGHT_WAZUH_INITIAL_SINCE": "2026-10-20T07:00:00Z",
            "FIRSTLIGHT_WAZUH_TENANT_ID": "tenant-a",
            "FIRSTLIGHT_WAZUH_CASE_ID": "case-a",
            "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_TENANT_ID": "tenant-b",
            "FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_CASE_ID": "case-a",
            "FIRSTLIGHT_WAZUH_ACCEPTANCE_ALLOW_WRITES": "I_AUTHORIZE_WRITES_TO_THIS_TEST_CASE",
        }
        errors = validate("wazuh", env)
        self.assertTrue(any("must exactly match" in e for e in errors))
        env["FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_TENANT_ID"] = "tenant-a"
        self.assertEqual(validate("wazuh", env), [])

    def test_response_preflight_does_not_enable_live_response(self):
        env = {
            "FIRSTLIGHT_RESPONSE_ACCEPTANCE_ENABLED": "true",
            "FIRSTLIGHT_RESPONSE_ACCEPTANCE_TENANT_ID": "tenant-a",
            "FIRSTLIGHT_RESPONSE_ACCEPTANCE_CASE_ID": "case-a",
        }
        self.assertTrue(any("intentionally disabled" in e for e in validate("response", env)))
        env["FIRSTLIGHT_RESPONSE_ACCEPTANCE_ENABLED"] = "false"
        self.assertEqual(validate("response", env), [])

    def test_production_requires_self_hosted_https_api_and_postgres(self):
        env = {
            "SATARK_API_INTERNAL_URL": "https://satark-api.example.test",
            "SATARK_DATABASE_URL": "postgresql+psycopg://satark:secret@db.example.test:5432/satark",
        }
        self.assertEqual(validate("production", env), [])
        env["SATARK_API_INTERNAL_URL"] = "http://public.example.test"
        self.assertTrue(any("HTTPS" in e for e in validate("production", env)))


if __name__ == "__main__":
    unittest.main()
