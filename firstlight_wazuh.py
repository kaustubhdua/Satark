"""Read-only connector for alerts indexed by Wazuh.

The connector talks to the Wazuh Indexer/OpenSearch REST API, not to an
arbitrary URL supplied by a caller. Credentials and the endpoint are supplied
only by server-side environment variables. It never executes response actions.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PAGE_SIZE = 500
MAX_DETAILS_BYTES = 16 * 1024
DEFAULT_INDEX = "wazuh-alerts-*"
_INDEX_PATTERN = re.compile(r"^[A-Za-z0-9._,*-]{1,180}$")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_url(request: Request, timeout: float):
    return build_opener(_NoRedirectHandler()).open(request, timeout=timeout)


class WazuhConfigurationError(ValueError):
    """Raised when required connector configuration is missing or unsafe."""


class WazuhConnectorError(RuntimeError):
    """Raised when the configured Wazuh Indexer cannot return valid alerts."""


@dataclass(frozen=True)
class WazuhIndexerConfig:
    base_url: str
    username: str
    password: str
    index_pattern: str = DEFAULT_INDEX
    timeout_seconds: float = 8.0
    allow_http: bool = False
    allowed_agent_ids: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "WazuhIndexerConfig":
        base_url = os.getenv("FIRSTLIGHT_WAZUH_INDEXER_URL", "").strip().rstrip("/")
        username = os.getenv("FIRSTLIGHT_WAZUH_INDEXER_USERNAME", "")
        password = os.getenv("FIRSTLIGHT_WAZUH_INDEXER_PASSWORD", "")
        index_pattern = os.getenv("FIRSTLIGHT_WAZUH_INDEX_PATTERN", DEFAULT_INDEX)
        agent_ids = tuple(sorted({item.strip() for item in os.getenv("FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS", "").split(",") if item.strip()}))
        allow_http = os.getenv("FIRSTLIGHT_WAZUH_ALLOW_HTTP", "").lower() in {"1", "true", "yes"}
        try:
            timeout = float(os.getenv("FIRSTLIGHT_WAZUH_TIMEOUT_SECONDS", "8"))
        except ValueError as exc:
            raise WazuhConfigurationError("Wazuh timeout must be a number") from exc
        if not base_url or not username or not password:
            raise WazuhConfigurationError("Wazuh Indexer URL and credentials are required")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in ({"https", "http"} if allow_http else {"https"})
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise WazuhConfigurationError(
                "Wazuh Indexer URL must be an HTTPS origin/path without embedded credentials, query, or fragment"
            )
        if not _INDEX_PATTERN.fullmatch(index_pattern) or index_pattern in {".", ".."}:
            raise WazuhConfigurationError("Wazuh index pattern contains unsupported characters")
        if not agent_ids or len(agent_ids) > 100 or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", item) for item in agent_ids):
            raise WazuhConfigurationError("FIRSTLIGHT_WAZUH_ALLOWED_AGENT_IDS must list 1–100 valid authorized Wazuh agent IDs")
        if not 1 <= timeout <= 30:
            raise WazuhConfigurationError("Wazuh timeout must be between 1 and 30 seconds")
        return cls(base_url, username, password, index_pattern, timeout, allow_http, agent_ids)


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("alert is missing a usable timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("alert timestamp is not ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("alert timestamp must include a timezone")
    parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bounded_mapping(value: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    if len(encoded) <= MAX_DETAILS_BYTES:
        return value
    return {
        "truncated": True,
        "original_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def normalize_alert(hit: dict[str, Any], *, include_source_snapshot: bool = False) -> dict[str, Any]:
    """Convert one OpenSearch hit into a bounded canonical FIRSTLIGHT event."""
    if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
        raise ValueError("Wazuh alert hit is malformed")
    source = hit["_source"]
    raw_timestamp = source.get("@timestamp") or source.get("timestamp")
    alert_time = _timestamp(raw_timestamp)
    try:
        source_snapshot_bytes = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise ValueError("alert source cannot be canonically serialized") from exc
    source_digest = hashlib.sha256(source_snapshot_bytes).hexdigest()
    rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
    agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
    manager = source.get("manager") if isinstance(source.get("manager"), dict) else {}
    data = source.get("data") if isinstance(source.get("data"), dict) else {}
    doc_id = hit.get("_id")
    index = hit.get("_index")
    if not isinstance(doc_id, str) or not doc_id or not isinstance(index, str) or not index:
        raise ValueError("Wazuh alert is missing its index document identity")

    identity = f"{index}:{doc_id}"
    event_id = "wazuh-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    description = rule.get("description")
    full_log = source.get("full_log")
    summary = description if isinstance(description, str) and description.strip() else full_log
    if not isinstance(summary, str) or not summary.strip():
        summary = "Wazuh alert (no description supplied)"
    summary = summary[:4096]

    details = {
        "provider": "wazuh-indexer",
        "index": index[:180],
        "document_id": doc_id[:256],
        "rule_id": str(rule.get("id", ""))[:100],
        "rule_level": rule.get("level"),
        "rule_groups": [str(group)[:120] for group in rule.get("groups", [])[:30] if isinstance(group, (str, int))] if isinstance(rule.get("groups"), list) else [],
        "agent_id": str(agent.get("id", ""))[:100],
        "agent_name": str(agent.get("name", ""))[:180],
        "manager_name": str(manager.get("name", ""))[:180],
        "location": str(source.get("location", ""))[:256],
        "decoder_name": str((source.get("decoder") or {}).get("name", ""))[:100]
            if isinstance(source.get("decoder"), dict) else "",
        "data": _bounded_mapping(data),
        "source_record_sha256": source_digest,
    }
    normalized = {
        "event_id": event_id,
        "timestamp": alert_time,
        "source": "wazuh",
        "kind": "security_alert",
        "summary": summary,
        "details": details,
        "provenance": {
            "provider": "wazuh-indexer",
            "index": index[:180],
            "document_id": doc_id[:256],
            "source_timestamp": alert_time,
            "source_timestamp_raw": str(raw_timestamp)[:100],
            "ingested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_record_sha256": details["source_record_sha256"],
            "source_snapshot_bytes": len(source_snapshot_bytes),
        },
    }
    if include_source_snapshot:
        normalized["source_snapshot_json"] = source_snapshot_bytes.decode("utf-8")
    return normalized


class WazuhIndexerClient:
    """Small bounded OpenSearch client using Wazuh Indexer basic authentication."""

    def __init__(self, config: WazuhIndexerConfig):
        self.config = config

    def fetch_alerts(self, *, limit: int = 100, since: str | None = None, until: str | None = None, offset: int = 0, order: str = "asc", include_source_snapshot: bool = False) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset + limit > 10_000:
            raise ValueError("offset plus limit must stay within the 10,000-result indexer window")
        if order not in {"asc", "desc"}:
            raise ValueError("order must be asc or desc")
        range_filter: dict[str, Any] = {}
        if since is not None:
            range_filter["gte"] = _timestamp(since)
        if until is not None:
            range_filter["lte"] = _timestamp(until)
        filters: list[dict[str, Any]] = [{"terms": {"agent.id": list(self.config.allowed_agent_ids)}}]
        if range_filter:
            filters.append({"range": {"@timestamp": range_filter}})
        query: dict[str, Any] = {"bool": {"filter": filters}}
        payload = {
            "from": offset,
            "size": limit,
            "track_total_hits": False,
            "query": query,
            "sort": [{"@timestamp": {"order": order, "unmapped_type": "date"}}],
            "_source": True,
        }
        url = f"{self.config.base_url}/{self.config.index_pattern}/_search"
        token = base64.b64encode(
            f"{self.config.username}:{self.config.password}".encode("utf-8")
        ).decode("ascii")
        request = Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": f"Basic {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with _open_url(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise WazuhConnectorError("Wazuh response exceeded the configured byte limit")
        except HTTPError as exc:
            if exc.code in (401, 403):
                raise WazuhConnectorError("Wazuh Indexer rejected the configured credentials or permissions") from exc
            raise WazuhConnectorError(f"Wazuh Indexer returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise WazuhConnectorError("Wazuh Indexer is unreachable or the TLS connection failed") from exc
        try:
            response_data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WazuhConnectorError("Wazuh Indexer returned invalid JSON") from exc
        hits = response_data.get("hits", {}).get("hits", []) if isinstance(response_data, dict) else None
        if not isinstance(hits, list):
            raise WazuhConnectorError("Wazuh Indexer response did not contain a hits list")
        normalized = []
        for hit in hits[:limit]:
            try:
                normalized.append(normalize_alert(hit, include_source_snapshot=include_source_snapshot))
            except (TypeError, ValueError):
                # Fail the page closed rather than silently dropping a malformed record.
                raise WazuhConnectorError("A Wazuh alert was malformed; page was not returned")
        return normalized


def fetch_configured_alerts(*, limit: int = 100, since: str | None = None, until: str | None = None, offset: int = 0, order: str = "asc") -> list[dict[str, Any]]:
    """Fetch one bounded page from the configured Wazuh Indexer."""
    return WazuhIndexerClient(WazuhIndexerConfig.from_env()).fetch_alerts(limit=limit, since=since, until=until, offset=offset, order=order)
