from __future__ import annotations

import json
import os
import time
import unittest
from unittest.mock import patch

from firstlight_agents import AgentFinding, AgentResult, _parse_json, _run_one, run_independent_agents


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


if __name__ == "__main__":
    unittest.main()
