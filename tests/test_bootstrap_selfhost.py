import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("bootstrap_selfhost", ROOT / "scripts" / "bootstrap_selfhost.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def parse(text):
    return dict(line.split("=", 1) for line in text.splitlines() if re.match(r"^[A-Z][A-Z0-9_]*=", line))


class BootstrapSelfhostTests(unittest.TestCase):
    def setUp(self):
        self.text, self.todo = bootstrap.build((ROOT / "deploy" / "production.env.example").read_text(), "security.example.org", "ops@example.org")
        self.env = parse(self.text)

    def test_generated_secrets_are_strong_and_distinct(self):
        tokens = [self.env[k] for k in ("FIRSTLIGHT_API_TOKEN", "FIRSTLIGHT_WAZUH_SYNC_TOKEN", "REDIS_REST_TOKEN")]
        self.assertEqual(len(set(tokens)), 3)
        for token in tokens:
            self.assertRegex(token, r"^[0-9a-f]{64}$")
        self.assertGreaterEqual(len(self.env["POSTGRES_PASSWORD"]), 40)
        self.assertEqual(len(self.env["SATARK_MFA_ENCRYPTION_KEY"]), 44)

    def test_database_urls_embed_the_matching_encoded_passwords(self):
        from urllib.parse import quote
        self.assertIn(quote(self.env["SATARK_RUNTIME_DB_PASSWORD"], safe=""), self.env["SATARK_DATABASE_URL"])
        self.assertIn(quote(self.env["SATARK_BACKUP_DB_PASSWORD"], safe=""), self.env["SATARK_BACKUP_DATABASE_URL"])

    def test_no_generated_placeholder_is_left_and_operator_items_are_reported(self):
        for key in ("POSTGRES_PASSWORD", "SATARK_MFA_ENCRYPTION_KEY", "FIRSTLIGHT_API_TOKEN", "REDIS_REST_TOKEN"):
            self.assertNotIn("REPLACE", self.env[key])
        self.assertIn("SATARK_SMTP_PASSWORD", self.todo)
        self.assertIn("FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", self.todo)
        self.assertEqual(self.env["SATARK_DOMAIN"], "security.example.org")

    def test_every_compose_variable_is_in_the_template(self):
        compose = (ROOT / "docker-compose.production.yml").read_text()
        template_keys = set(self.env)
        needed = {m for m in re.findall(r"\$\{([A-Z][A-Z0-9_]*)(?::\?|\})", compose)}
        self.assertEqual(sorted(needed - template_keys), [])


if __name__ == "__main__":
    unittest.main()
