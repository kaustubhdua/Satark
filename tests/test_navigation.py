"""Tests for local Ollama endpoint configuration in the Streamlit UI."""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ui import navigation


class ConfiguredOllamaEndpointTests(unittest.TestCase):
    def test_environment_variable_is_trimmed(self):
        with patch.dict(os.environ, {"OLLAMA_BASE_URL": " http://ollama:11434/ "}):
            self.assertEqual(navigation.configured_ollama_base_url(), "http://ollama:11434")

    def test_default_endpoint_is_localhost(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(navigation.configured_ollama_base_url(), "http://127.0.0.1:11434")


if __name__ == "__main__":
    unittest.main()
