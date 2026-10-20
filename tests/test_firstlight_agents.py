from __future__ import annotations

import json
import os
import time
import unittest
from unittest.mock import patch

from firstlight_agents import AgentFinding, AgentResult, _parse_json, _run_one, _safe_details, run_independent_agents
from ai_provider import LocalOllamaClient


class FirstlightAgentContractTests(unittest.TestCase):
    def test_disabled_by_default_and_explicit_about_mode(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FIRSTLIGHT_MODEL_AGENTS_ENABLED", None)
            result = run_independent_agents([])
        self.assertFalse(result["enabled"])
        self.assertEqual(result["mode"], "deterministic_only")

    def test_invalid_agent_json_is_rejected(self):
        for value in ("", "not json", "[]", "x" * 12001):
            with self.subTest(value=value[:20]):
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    _parse_json(value)

    def test_agent_schema_rejects_unknown_fields_and_bad_confidence(self):
        with self.assertRaises(Exception):
            AgentFinding.model_validate({
                "title": "Unsupported conclusion", "severity": "high",
                "rationale": "There is not enough supporting evidence.",
                "evidence_ids": ["EV-1"], "confidence": 1.2, "tool_call": "delete",
            })

    def test_agent_result_schema_requires_allowlisted_agent_and_status(self):
        with self.assertRaises(Exception):
            AgentResult.model_validate({
                "agent_id": "arbitrary-agent", "status": "ok", "summary": "x",
                "findings": [], "limitations": [],
            })

    def test_agent_details_are_allowlisted_and_bounded(self):
        details = _safe_details({
            "rule_id": "5710",
            "agent_name": "lab-host",
            "command": "must not be passed to the model",
            "data": {"srcip": "192.0.2.10", "password": "never include"},
        })
        self.assertEqual(details["rule_id"], "5710")
        self.assertEqual(details["agent_name"], "lab-host")
        self.assertNotIn("command", details)
        self.assertNotIn("password", details.get("data", {}))
        self.assertEqual(details["data"]["srcip"], "192.0.2.10")

    def test_agent_evidence_bound_is_enforced_before_provider_calls(self):
        with patch.dict(os.environ, {"FIRSTLIGHT_MODEL_AGENTS_ENABLED": "true"}):
            with self.assertRaises(ValueError):
                run_independent_agents([{"id": str(i)} for i in range(501)])

    def test_provider_malformed_json_returns_invalid_output(self):
        response = type("Response", (), {"choices": [
            type("Choice", (), {"message": type("Message", (), {"content": "not-json"})()})()
        ]})()
        client = type("Client", (), {"chat": type("Chat", (), {
            "completions": type("Completions", (), {
                "create": lambda *args, **kwargs: response
            })()
        })()})()
        with patch("ai_provider.LocalOllamaClient", return_value=client):
            result = _run_one("timeline_analyst", "test-model", [{"id": "EV-1"}], {"EV-1"})
        self.assertEqual(result.status, "invalid_output")
        self.assertEqual(result.findings, [])

    def test_unknown_evidence_references_are_discarded(self):
        payload = {
            "agent_id": "timeline_analyst", "status": "ok", "summary": "Sequence needs review.",
            "findings": [{
                "title": "Unsupported relationship", "severity": "review",
                "rationale": "The record does not support this conclusion.",
                "evidence_ids": ["MADE-UP-ID"], "confidence": 0.2,
            }],
            "limitations": [],
        }
        response = type("Response", (), {"choices": [
            type("Choice", (), {"message": type("Message", (), {"content": json.dumps(payload)})()})()
        ]})()
        client = type("Client", (), {"chat": type("Chat", (), {
            "completions": type("Completions", (), {
                "create": lambda *args, **kwargs: response
            })()
        })()})()
        with patch("ai_provider.LocalOllamaClient", return_value=client):
            result = _run_one("timeline_analyst", "test-model", [{"id": "EV-1"}], {"EV-1"})
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.findings, [])

    def test_deadline_returns_timeout_for_pending_agents(self):
        def slow_agent(*args, **kwargs):
            time.sleep(0.05)
            raise RuntimeError("simulated provider timeout")

        with patch.dict(os.environ, {"FIRSTLIGHT_MODEL_AGENTS_ENABLED": "true"}), \
             patch("firstlight_agents._run_one", side_effect=slow_agent), \
             patch("firstlight_agents.wait", side_effect=lambda futures, timeout: (set(), set(futures))):
            result = run_independent_agents([{"id": "EV-1"}])
        self.assertEqual(result["mode"], "independent_local_model_agents")
        self.assertEqual({agent["status"] for agent in result["agents"]}, {"timeout"})


class OllamaStructuredOutputTests(unittest.TestCase):
    def test_native_client_passes_json_schema_to_ollama_format(self):
        client = LocalOllamaClient(base_url="http://localhost:11434", timeout=1)
        schema = {"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"]}
        captured = {}
        def fake_request(path, payload=None, timeout=None):
            captured["path"] = path
            captured["payload"] = payload
            return {"message":{"content":'{"summary":"ok"}'}}
        with patch.object(client, "_request_json", side_effect=fake_request):
            client.chat.completions.create(
                model="test-model", messages=[{"role":"user","content":"test"}],
                response_format={"type":"json_schema","json_schema":{"name":"test","schema":schema}},
            )
        self.assertEqual(captured["path"], "/api/chat")
        self.assertEqual(captured["payload"]["format"], schema)


if __name__ == "__main__":
    unittest.main()
