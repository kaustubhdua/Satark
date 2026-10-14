"""Tests for the self-hosted Ollama compatibility client."""

import json
import unittest
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ai_provider import (
    LocalOllamaClient,
    TEXT_MODEL_PREFERENCES,
    VISION_MODEL_PREFERENCES,
    choose_model,
    discover_models,
    get_client,
)


class ProviderHelperTests(unittest.TestCase):
    def test_preferences_are_non_empty_and_local(self):
        self.assertTrue(TEXT_MODEL_PREFERENCES)
        self.assertTrue(VISION_MODEL_PREFERENCES)
        self.assertNotIn("groq", " ".join(TEXT_MODEL_PREFERENCES + VISION_MODEL_PREFERENCES).lower())

    def test_choose_model_prefers_first_available_preference(self):
        self.assertEqual(
            choose_model({TEXT_MODEL_PREFERENCES[1], TEXT_MODEL_PREFERENCES[0]}, TEXT_MODEL_PREFERENCES),
            TEXT_MODEL_PREFERENCES[0],
        )

    def test_choose_model_uses_local_default_when_discovery_is_empty(self):
        self.assertEqual(choose_model(set(), TEXT_MODEL_PREFERENCES), TEXT_MODEL_PREFERENCES[0])

    def test_choose_model_returns_none_when_no_preference_is_available(self):
        self.assertIsNone(choose_model({"unrelated-model"}, ["supported-model"]))

    def test_get_client_never_requires_an_api_key(self):
        self.assertIsInstance(get_client(""), LocalOllamaClient)
        self.assertIsInstance(get_client(None), LocalOllamaClient)


    def test_public_ollama_endpoint_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "localhost or a private-network"):
            LocalOllamaClient(base_url="https://api.example.com")

    def test_private_network_ollama_endpoint_is_allowed(self):
        client = LocalOllamaClient(base_url="http://192.168.1.40:11434")
        self.assertEqual(client.base_url, "http://192.168.1.40:11434")

    @patch("ai_provider.urlopen")
    def test_discover_models_reads_local_ollama_tags(self, urlopen):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({"models": [{"name": "qwen2.5:3b"}, {"name": "qwen2.5vl:3b"}]}).encode()
        urlopen.return_value = response
        client = LocalOllamaClient(base_url="http://127.0.0.1:11434")
        self.assertEqual(discover_models(client), {"qwen2.5:3b", "qwen2.5vl:3b"})
        self.assertIn("/api/tags", urlopen.call_args.args[0].full_url)

    @patch("ai_provider.urlopen")
    def test_chat_completion_translates_json_schema_request_to_local_ollama(self, urlopen):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({"message": {"content": "{\"risk_score\":12}"}}).encode()
        urlopen.return_value = response
        client = LocalOllamaClient(base_url="http://127.0.0.1:11434")
        result = client.chat.completions.create(
            model="qwen2.5:3b",
            temperature=0,
            max_tokens=200,
            response_format={"type": "json_object"},
            messages=[{"role": "user", "content": "Analyze only the supplied text."}],
        )
        self.assertEqual(result.choices[0].message.content, '{"risk_score":12}')
        payload = json.loads(urlopen.call_args.args[0].data.decode())
        self.assertEqual(payload["model"], "qwen2.5:3b")
        self.assertEqual(payload["format"], "json")
        self.assertFalse(payload["stream"])

    def test_multimodal_message_converts_data_url_to_base64_image(self):
        data_url = "data:image/jpeg;base64,aGVsbG8="
        messages = LocalOllamaClient._message_parts([{
            "role": "user",
            "content": [
                {"type": "text", "text": "Inspect this"},
                {"type": "image_url", "image_url": {"url": data_url}},
            ],
        }])
        self.assertEqual(messages[0]["content"], "Inspect this")
        self.assertEqual(messages[0]["images"], ["aGVsbG8="])

    def test_model_discovery_fails_closed_when_local_service_is_unavailable(self):
        client = Mock()
        client.models.list.side_effect = RuntimeError("unavailable")
        self.assertEqual(discover_models(client), set())


if __name__ == "__main__":
    unittest.main()
