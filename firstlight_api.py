"""Shared FIRSTLIGHT investigation API.

This service wraps the repository's canonical Python engine so web and
Streamlit workflows can use the same evidence verification and investigation
rules. It performs no live collection or real response actions.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from firstlight_engine import investigate_case, sha256_record
from firstlight_agents import run_independent_agents
from firstlight_wazuh import WazuhConfigurationError, WazuhConnectorError, fetch_configured_alerts

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE = 500
app = FastAPI(title="FIRSTLIGHT Investigation API", version="1.0.0", docs_url=None, redoc_url=None)


class EvidenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(min_length=1, max_length=100)
    time: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=160)
    kind: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=4096)
    details: dict[str, Any] = Field(default_factory=dict)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("details", mode="before")
    @classmethod
    def validate_details(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("details must be a JSON object")
        try:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
            raise ValueError("details must be bounded JSON data") from exc
        if len(encoded) > 16 * 1024:
            raise ValueError("details exceed the 16 KiB limit")
        return value

    @field_validator("time")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        from datetime import datetime
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("time must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("time must include an explicit timezone")
        return value


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    case_id: str = Field(min_length=1, max_length=128)
    title: str = Field(default="FIRSTLIGHT investigation", min_length=1, max_length=240)
    evidence: list[EvidenceInput] = Field(max_length=MAX_EVIDENCE)


def _authorize(authorization: str | None) -> None:
    expected = os.getenv("FIRSTLIGHT_API_TOKEN", "")
    # Fail closed: an absent secret must never silently turn the investigation
    # endpoint into a public API. Local/demo deployments need an explicit token too.
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="FIRSTLIGHT API token is not configured or is invalid")
    supplied = authorization or ""
    if not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:], expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.middleware("http")
async def bounded_request(request: Request, call_next):
    length = request.headers.get("content-length")
    if length is not None:
        try:
            declared = int(length)
            if declared < 0:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if declared > MAX_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body is too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


def _ollama_readiness() -> dict[str, Any]:
    enabled = os.getenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", "").lower() in {"1", "true", "yes"}
    configured = os.getenv("FIRSTLIGHT_OLLAMA_MODEL", "qwen2.5:3b").strip() or "qwen2.5:3b"
    if not enabled:
        return {"status": "disabled", "model_available": False, "configured_model": configured}
    started = time.monotonic()
    try:
        from ai_provider import LocalOllamaClient
        client = LocalOllamaClient(timeout=5)
        listing = client.models.list()
        installed = {
            str(getattr(item, "id", ""))
            for item in getattr(listing, "data", [])
            if getattr(item, "id", None)
        }
        actual = next((name for name in installed if name == configured or name == configured + ":latest"), None)
        return {
            "status": "ready" if actual else "model_missing",
            "model_available": actual is not None,
            "configured_model": configured,
            "installed_model": actual,
            "latency_ms": max(0, round((time.monotonic() - started) * 1000)),
        }
    except Exception:
        # Never return endpoint URLs, model server errors, or configuration
        # values through the health endpoint. Deterministic analysis remains usable.
        return {
            "status": "unavailable",
            "model_available": False,
            "configured_model": configured,
            "latency_ms": max(0, round((time.monotonic() - started) * 1000)),
        }


@app.get("/health")
async def health():
    model_agents_enabled = os.getenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", "").lower() in {"1", "true", "yes"}
    readiness = _ollama_readiness()
    # Keep internal diagnostics useful without disclosing configured/installed
    # model names or timing details through the public health endpoint.
    public_ollama = {
        "status": readiness.get("status", "unavailable"),
        "model_available": readiness.get("model_available") is True,
    }
    return {
        "status": "ok",
        "engine": "firstlight_engine.investigate_case",
        "model_agents_enabled": model_agents_enabled,
        "ollama": public_ollama,
        "production_ready": False,
    }


@app.get("/api/v1/integrations/wazuh/alerts")
async def get_wazuh_alerts(authorization: str | None = Header(default=None), limit: int = 100, since: str | None = None, tenant_id: str = ""):
    """Read one bounded page of Wazuh alerts; this endpoint does not persist events."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    expected = os.getenv("FIRSTLIGHT_WAZUH_SYNC_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="Wazuh connector is not enabled or token configuration is invalid")
    supplied = authorization or ""
    if not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:], expected):
        raise HTTPException(status_code=401, detail="Unauthorized")
    configured_tenant = os.getenv("FIRSTLIGHT_WAZUH_TENANT_ID", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", configured_tenant):
        raise HTTPException(status_code=503, detail="Wazuh connector tenant is not configured")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", tenant_id, re.IGNORECASE):
        raise HTTPException(status_code=400, detail="A valid tenant_id is required")
    if not hmac.compare_digest(tenant_id.lower(), configured_tenant):
        raise HTTPException(status_code=403, detail="Wazuh source is not configured for this tenant")
    try:
        events = fetch_configured_alerts(limit=limit, since=since, order="desc")
    except WazuhConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except WazuhConnectorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"source": "wazuh-indexer", "mode": "read_only_fetch", "persisted": False, "count": len(events), "events": events,
            "limitations": ["One bounded page only; no durable checkpoint or persistence.", "Requires a dedicated read-only Wazuh Indexer account.", "Source digest alone does not prove authenticity."]}

@app.post("/api/v1/cases/investigate")
async def run_investigation(
    request: Request,
    authorization: str | None = Header(default=None),
):
    _authorize(authorization)

    # Read the actual stream incrementally. Content-Length is only an early
    # rejection hint; chunked requests must be subject to the same hard limit.
    chunks: list[bytes] = []
    total_bytes = 0
    try:
        async for chunk in request.stream():
            total_bytes += len(chunk)
            if total_bytes > MAX_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body is too large"})
            chunks.append(chunk)
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Could not read request body"})

    try:
        payload = InvestigationRequest.model_validate_json(b"".join(chunks))
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": exc.errors(include_input=False, include_context=False)})
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON request body"})

    ids = [item.id for item in payload.evidence]
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=422, detail="Evidence IDs must be unique within a case")

    envelopes: list[dict[str, Any]] = []
    integrity = []
    for item in payload.evidence:
        # This representation is also used by the browser when hashing evidence.
        record = {
            "event_id": item.id,
            "timestamp": item.time,
            "source": item.source,
            "kind": item.kind,
            "summary": item.summary,
            "details": item.details,
        }
        actual = sha256_record(record)
        valid = hmac.compare_digest(actual, item.digest)
        integrity.append({
            "evidence_id": item.id,
            "valid": valid,
            "status": "VERIFIED" if valid else "HASH MISMATCH — POSSIBLE TAMPERING",
            "expected_sha256": item.digest,
            "actual_sha256": actual,
        })
        # Keep a mismatched submitted digest intact so the engine also marks it
        # untrusted; never silently reseal a record that failed verification.
        envelopes.append({
            "evidence_id": item.id,
            "record": record,
            "sha256": item.digest,
            "collected_at": "",
            "integrity_status": "verified" if valid else "mismatch",
        })

    result = investigate_case({"case_id": payload.case_id, "title": payload.title}, envelopes)
    try:
        agent_analysis = run_independent_agents([
            {"id": item.id, "time": item.time, "source": item.source, "kind": item.kind,
             "summary": item.summary, "details": item.details, "integrity": "verified" if check["valid"] else "mismatch"}
            for item, check in zip(payload.evidence, integrity)
        ])
    except Exception:
        # Model failures never replace or suppress deterministic investigation output.
        agent_analysis = {
            "enabled": os.getenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", "").lower() in {"1", "true", "yes"},
            "mode": "agent_error",
            "agents": [],
            "limitations": ["Agent orchestration failed; deterministic findings remain authoritative."],
        }
    return {
        "schema_version": "1.1",
        "case_id": payload.case_id,
        "integrity": integrity,
        "integrity_summary": {
            "total": len(integrity),
            "verified": sum(1 for item in integrity if item["valid"]),
            "mismatched": sum(1 for item in integrity if not item["valid"]),
        },
        "investigation": result,
        "agent_analysis": agent_analysis,
        "limitations": [
            "Only client-supplied bounded event summaries and structured details were reviewed; no live endpoint collection occurred.",
            "Browser-computed hashes detect changes relative to the submitted digest but do not prove source authenticity or establish an independently protected chain of custody.",
            ("Optional local model agents are advisory; deterministic findings remain authoritative." if agent_analysis.get("enabled") else "Independent LLM agents were not enabled for this run."),
            "Response proposals are simulation-only.",
        ],
    }
