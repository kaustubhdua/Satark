from __future__ import annotations

import json

from fastapi.testclient import TestClient

from service import app as service_app
from service.engine import analyze_text

client = TestClient(service_app.app)


def test_empty_and_extra_fields_are_rejected():
    assert client.post("/analyze", json={"text": " "}).status_code == 422
    assert client.post("/analyze", json={"text": "hello", "admin": True}).status_code == 422


def test_url_urgency_signals_are_explainable_and_non_verdict():
    response = client.post(
        "/analyze",
        json={"text": "Urgent! verify your account at http://example.invalid/login", "case_id": "demo"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "needs_review"
    assert payload["signals"]
    assert payload["case_id"] == "demo"
    assert "not a verdict" in payload["disclaimer"].lower()
    assert all(signal["evidence_excerpt"] for signal in payload["signals"])


def test_benign_text_does_not_get_declared_safe():
    response = client.post("/analyze", json={"text": "Meeting starts at 10 AM."})
    assert response.status_code == 200
    assert response.json()["verdict"] == "insufficient_evidence"
    assert "safe" not in response.json()["summary"].lower()


def test_non_global_ip_is_not_emitted_as_public_indicator():
    signals = analyze_text("Try 127.0.0.1 and 192.168.1.1")
    assert not any(signal.category == "ip" for signal in signals)


def test_global_ip_is_only_context_not_a_malicious_verdict():
    signals = analyze_text("Observed source 8.8.8.8")
    assert any(signal.category == "ip" for signal in signals)
    assert all("not" not in signal.description.lower() or "malicious" not in signal.description.lower() for signal in signals)


def test_health_never_claims_production_ready():
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["production_ready"] is False
    assert response.headers["cache-control"] == "no-store"


def test_invalid_ollama_output_falls_back_to_deterministic(monkeypatch):
    async def fake_summary(text, signals):
        return None, "invalid_output"

    monkeypatch.setattr(service_app, "_model_summary", fake_summary)
    response = client.post("/analyze", json={"text": "Urgent verify your account"})
    assert response.status_code == 200
    assert response.json()["ai_status"] == "invalid_output"
    assert response.json()["signals"]


def test_url_fragment_is_bounded():
    signals = analyze_text("http://" + "a" * 5000 + ".invalid")
    assert len(signals) <= 50
