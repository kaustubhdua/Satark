"""Regression checks for the local-only Compose topology."""

from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class LocalComposeTests(unittest.TestCase):
    def test_services_are_separate_and_ollama_is_not_host_published(self):
        config = yaml.safe_load((ROOT / "docker-compose.local.yml").read_text(encoding="utf-8"))
        self.assertEqual(set(config["services"]), {"web", "streamlit", "ollama"})
        self.assertEqual(config["services"]["web"]["build"]["context"], "./web")
        self.assertEqual(config["services"]["streamlit"]["build"]["dockerfile"], "Dockerfile.streamlit")
        self.assertEqual(config["services"]["web"]["ports"], ["127.0.0.1:3000:3000"])
        self.assertEqual(config["services"]["streamlit"]["ports"], ["127.0.0.1:8501:8501"])
        self.assertNotIn("ports", config["services"]["ollama"])
        self.assertEqual(config["services"]["web"]["depends_on"]["ollama"]["condition"], "service_healthy")
        self.assertEqual(config["services"]["streamlit"]["depends_on"]["ollama"]["condition"], "service_healthy")

    def test_app_containers_keep_basic_hardening(self):
        config = yaml.safe_load((ROOT / "docker-compose.local.yml").read_text(encoding="utf-8"))
        for name in ("web", "streamlit"):
            service = config["services"][name]
            self.assertIn("ALL", service["cap_drop"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertTrue(any(str(item).startswith("/tmp:") for item in service["tmpfs"]))


if __name__ == "__main__":
    unittest.main()
