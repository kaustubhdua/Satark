"""Persistent Wazuh-to-Supabase ingestion worker for FIRSTLIGHT.

Run this on a persistent, private host, not inside a Vercel request. The worker
uses a Supabase service-role credential only on that host and validates the
configured actor's tenant membership before it writes evidence. It performs no
live response actions.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from firstlight_wazuh import (
    MAX_PAGE_SIZE,
    WazuhConnectorError,
    WazuhIndexerClient,
    WazuhIndexerConfig,
)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_url(request: Request, timeout: float):
    return build_opener(_NoRedirectHandler()).open(request, timeout=timeout)


class WorkerConfigurationError(ValueError):
    pass


class SupabaseRestError(RuntimeError):
    pass


def _retry_delay(base_seconds: int, attempt: int, maximum: int = 900) -> int:
    """Bounded exponential retry delay; attempt numbers are one-based."""
    if not 1 <= base_seconds <= 3600 or attempt < 1 or maximum < 1:
        raise ValueError("retry delay inputs are out of range")
    return min(maximum, base_seconds * (2 ** min(attempt - 1, 20)))


def _safe_error_code(exc: BaseException) -> str:
    """Return a bounded diagnostic category without logging exception payloads."""
    if isinstance(exc, WorkerConfigurationError):
        return "configuration_error"
    if isinstance(exc, WazuhConnectorError):
        return "wazuh_connector_error"
    if isinstance(exc, SupabaseRestError):
        return "supabase_request_error"
    if isinstance(exc, (TimeoutError, URLError)):
        return "network_timeout_or_unavailable"
    if isinstance(exc, HTTPError):
        return "http_error"
    return "worker_error"


def _uuid_env(name: str) -> str:
    value = os.getenv(name, "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value):
        raise WorkerConfigurationError(f"{name} must be a UUID")
    return value


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise WorkerConfigurationError(f"{name} must be an ISO-8601 timestamp with timezone") from exc
    if parsed.tzinfo is None:
        raise WorkerConfigurationError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class SupabaseServiceRest:
    """Small REST client; credentials never leave this persistent worker."""

    def __init__(self, base_url: str, service_role_key: str, timeout: float = 8.0):
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".supabase.co"):
            raise WorkerConfigurationError("SUPABASE_URL must be an HTTPS Supabase project URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise WorkerConfigurationError("SUPABASE_URL must not embed credentials, query, or fragment")
        if not service_role_key or len(service_role_key) < 32:
            raise WorkerConfigurationError("SUPABASE_SERVICE_ROLE_KEY is missing or too short")
        self.base_url = f"https://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "")
        self.key = service_role_key
        self.timeout = timeout

    def upload_source_snapshot(self, *, tenant_id: str, case_id: str, digest: str, snapshot: str) -> str:
        raw = snapshot.encode("utf-8")
        if len(raw) > 4 * 1024 * 1024:
            raise SupabaseRestError("Wazuh source snapshot exceeds the satark-evidence bucket's 4 MiB object limit")
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SupabaseRestError("Wazuh source snapshot digest did not match its provenance digest")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SupabaseRestError("Wazuh source snapshot digest is malformed")
        path = f"{tenant_id}/{case_id}/wazuh/{digest}.json"
        url = self.base_url + "/storage/v1/object/satark-evidence/" + quote(path, safe="/")
        request = Request(
            url, data=raw,
            headers={
                "apikey": self.key,
                "Authorization": "Bearer " + self.key,
                "Content-Type": "application/json",
                "x-upsert": "true",
            },
            method="POST",
        )
        try:
            with _open_url(request, timeout=self.timeout) as response:
                body = response.read(64 * 1024 + 1)
                if len(body) > 64 * 1024:
                    raise SupabaseRestError("Supabase Storage response exceeded the allowed byte limit")
        except HTTPError as exc:
            if exc.code in (401, 403):
                raise SupabaseRestError("Supabase Storage rejected the worker credential or object policy") from exc
            raise SupabaseRestError(f"Supabase Storage returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SupabaseRestError("Supabase Storage is unreachable or the TLS connection failed") from exc
        return path

    def verify_source_snapshot(self, *, tenant_id: str, case_id: str, path: str, digest: str) -> bool:
        """Fetch a tenant/case-bound private source object and verify its exact bytes."""
        expected_path = f"{tenant_id}/{case_id}/wazuh/{digest}.json"
        if path != expected_path or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SupabaseRestError("Source snapshot path or digest is invalid")
        url = self.base_url + "/storage/v1/object/satark-evidence/" + quote(path, safe="/")
        request = Request(url, headers={
            "apikey": self.key,
            "Authorization": "Bearer " + self.key,
            "Accept": "application/json",
        }, method="GET")
        try:
            with _open_url(request, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise SupabaseRestError("Source snapshot exceeded the private bucket limit")
        except HTTPError as exc:
            if exc.code in (401, 403, 404):
                raise SupabaseRestError("Source snapshot could not be read with the worker's scoped path") from exc
            raise SupabaseRestError(f"Supabase Storage returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SupabaseRestError("Supabase Storage is unreachable or the TLS connection failed") from exc
        actual = hashlib.sha256(raw).hexdigest()
        return hmac.compare_digest(actual, digest)

    def request(self, method: str, table: str, *, query: dict[str, str] | None = None,
                body: dict[str, Any] | None = None, prefer: str | None = None) -> Any:
        suffix = "/rest/v1/" + table
        if query:
            suffix += "?" + urlencode(query)
        payload = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {
            "apikey": self.key,
            "Authorization": "Bearer " + self.key,
            "Accept": "application/json",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if prefer:
            headers["Prefer"] = prefer
        request = Request(self.base_url + suffix, data=payload, headers=headers, method=method)
        try:
            with _open_url(request, timeout=self.timeout) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise SupabaseRestError("Supabase response exceeded the allowed byte limit")
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))
        except HTTPError as exc:
            if exc.code in (401, 403):
                raise SupabaseRestError("Supabase rejected the service credential or table permissions") from exc
            raise SupabaseRestError(f"Supabase REST returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SupabaseRestError("Supabase REST is unreachable or the TLS connection failed") from exc


class WazuhSupabaseWorker:
    def __init__(self, *, rest: SupabaseServiceRest | Any, wazuh: Any,
                 tenant_id: str, case_id: str, actor_id: str,
                 page_size: int = 100, overlap_seconds: int = 300,
                 initial_since: str | None = None):
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise WorkerConfigurationError(f"page size must be between 1 and {MAX_PAGE_SIZE}")
        if not 0 <= overlap_seconds <= 3600:
            raise WorkerConfigurationError("overlap must be between 0 and 3600 seconds")
        self.rest = rest
        self.wazuh = wazuh
        self.tenant_id = tenant_id
        self.case_id = case_id
        self.actor_id = actor_id
        self.page_size = page_size
        self.overlap = timedelta(seconds=overlap_seconds)
        self.initial_since = _parse_timestamp(initial_since, "FIRSTLIGHT_WAZUH_INITIAL_SINCE") if initial_since else None
        agent_scope = hashlib.sha256(",".join(wazuh.config.allowed_agent_ids).encode("utf-8")).hexdigest()[:12]
        self.source_key = "wazuh-indexer:" + wazuh.config.index_pattern + ":" + agent_scope
        self._validate_target()

    def _validate_target(self) -> None:
        cases = self.rest.request("GET", "satark_cases", query={
            "select": "id,tenant_id", "id": "eq." + self.case_id,
            "tenant_id": "eq." + self.tenant_id, "limit": "1",
        })
        if not isinstance(cases, list) or not cases or cases[0].get("id") != self.case_id:
            raise WorkerConfigurationError("Configured target case does not belong to the configured tenant")
        memberships = self.rest.request("GET", "satark_memberships", query={
            "select": "tenant_id,user_id,role", "tenant_id": "eq." + self.tenant_id,
            "user_id": "eq." + self.actor_id, "role": "in.(owner,responder,analyst)", "limit": "1",
        })
        if not isinstance(memberships, list) or not memberships:
            raise WorkerConfigurationError("Configured actor must be an owner, responder, or analyst in the target tenant")

    def _load_checkpoint(self) -> datetime:
        rows = self.rest.request("GET", "satark_ingestion_checkpoints", query={
            "select": "last_event_timestamp",
            "tenant_id": "eq." + self.tenant_id,
            "case_id": "eq." + self.case_id,
            "source_key": "eq." + self.source_key,
            "limit": "1",
        })
        if isinstance(rows, list) and rows:
            return _parse_timestamp(str(rows[0]["last_event_timestamp"]), "checkpoint")
        if self.initial_since is None:
            raise WorkerConfigurationError(
                "No checkpoint exists; set FIRSTLIGHT_WAZUH_INITIAL_SINCE to an explicit ISO-8601 timestamp before first run"
            )
        return self.initial_since

    def _event_record(self, event: dict[str, Any], source_object_path: str) -> dict[str, Any]:
        provenance = event.get("provenance") if isinstance(event.get("provenance"), dict) else {}
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        metadata = {
            "provider": "wazuh-indexer",
            "index": str(provenance.get("index", details.get("index", "")))[:180],
            "document_id": str(provenance.get("document_id", details.get("document_id", "")))[:256],
            "rule_id": str(details.get("rule_id", ""))[:100],
            "rule_level": details.get("rule_level"),
            "rule_groups": details.get("rule_groups", []) if isinstance(details.get("rule_groups"), list) else [],
            "agent_id": str(details.get("agent_id", ""))[:100],
            "agent_name": str(details.get("agent_name", ""))[:180],
            "manager_name": str(details.get("manager_name", ""))[:180],
            "location": str(details.get("location", ""))[:256],
            "decoder_name": str(details.get("decoder_name", ""))[:100],
            "data": details.get("data", {}) if isinstance(details.get("data"), dict) else {},
            "source_record_sha256": str(provenance.get("source_record_sha256", "")),
        }
        event_id = str(event.get("event_id", ""))[:100]
        event_time = str(event.get("timestamp", ""))
        event_kind = str(event.get("kind", "security_alert"))[:100]
        summary = str(event.get("summary", ""))[:8192]
        browser_record = {
            "event_id": event_id,
            "timestamp": event_time,
            "source": "Wazuh",
            "kind": event_kind,
            "summary": summary,
            "details": details,
        }
        browser_digest = hashlib.sha256(
            json.dumps(browser_record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        ).hexdigest()
        metadata["source_provider"] = "wazuh-indexer"
        metadata["source_details"] = details
        metadata["source_index"] = metadata["index"]
        metadata["source_document_id"] = metadata["document_id"]
        metadata["source_timestamp_raw"] = str(provenance.get("source_timestamp_raw", event.get("timestamp", "")))[:100]
        metadata["source_object_path"] = source_object_path
        metadata["source_snapshot_preserved"] = True
        metadata["source_snapshot_bytes"] = int(provenance.get("source_snapshot_bytes", 0))
        metadata["local_evidence_id"] = event_id
        metadata["browser_record_sha256"] = browser_digest
        metadata["browser_event_timestamp"] = event_time
        metadata["persisted_by_worker"] = True
        metadata["source"] = "FIRSTLIGHT event record"
        metadata["record_hash_version"] = 2
        return {
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "source_label": "Wazuh",
            "event_kind": event_kind,
            "observed_at": _parse_timestamp(event_time, "event timestamp").isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "summary": summary,
            "metadata": metadata,
            "created_by": self.actor_id,
        }

    def _save_event(self, event: dict[str, Any]) -> None:
        provenance = event.get("provenance") if isinstance(event.get("provenance"), dict) else {}
        snapshot = event.get("source_snapshot_json")
        source_hash = str(provenance.get("source_record_sha256", ""))
        if not isinstance(snapshot, str) or not snapshot:
            raise SupabaseRestError("Wazuh source snapshot was not returned; refusing digest-only evidence persistence")
        source_path = self.rest.upload_source_snapshot(
            tenant_id=self.tenant_id, case_id=self.case_id, digest=source_hash, snapshot=snapshot,
        )
        record = self._event_record(event, source_path)
        if not record["summary"]:
            raise SupabaseRestError("Wazuh event had no usable summary")
        source_hash = str(event.get("provenance", {}).get("source_record_sha256", ""))
        if len(source_hash) != 64 or any(ch not in "0123456789abcdef" for ch in source_hash):
            raise SupabaseRestError("Wazuh event did not contain a valid source-record digest")
        body = {**record, "source_sha256": source_hash, "record_sha256": _canonical_hash(record)}
        self.rest.request(
            "POST", "satark_evidence",
            query={"on_conflict": "case_id,record_sha256"},
            body=body,
            prefer="resolution=ignore-duplicates,return=minimal",
        )

    def _save_checkpoint(self, cursor: datetime, count: int, *, status: str = "ok", error: str | None = None) -> None:
        now = _iso_utc(datetime.now(timezone.utc))
        body = {
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "source_key": self.source_key,
            "last_event_timestamp": _iso_utc(cursor),
            "last_batch_count": count,
            "last_status": status,
            "last_error": error[:1000] if error else None,
            "updated_at": now,
        }
        if status == "ok":
            body["last_success_at"] = now
        self.rest.request(
            "POST", "satark_ingestion_checkpoints",
            query={"on_conflict": "tenant_id,case_id,source_key"},
            body=body,
            prefer="resolution=merge-duplicates,return=minimal",
        )

    def run_once(self) -> dict[str, Any]:
        cursor = self._load_checkpoint()
        since = _iso_utc(cursor - self.overlap)
        until_dt = datetime.now(timezone.utc)
        until = _iso_utc(until_dt)
        offset = 0
        count = 0
        latest = cursor
        try:
            while True:
                page = self.wazuh.fetch_alerts(
                    limit=self.page_size, since=since, until=until, offset=offset, include_source_snapshot=True,
                )
                for event in page:
                    self._save_event(event)
                    event_time = _parse_timestamp(str(event["timestamp"]), "event timestamp")
                    if event_time > latest:
                        latest = event_time
                count += len(page)
                if len(page) < self.page_size:
                    break
                offset += len(page)
                if offset + self.page_size > 10_000:
                    raise WazuhConnectorError(
                        "The time window contains at least 10,000 alerts; reduce the polling interval or backfill window"
                    )
            # A checkpoint advances only after every page was persisted successfully.
            self._save_checkpoint(latest, count)
            return {"status": "ok", "fetched": count, "cursor": _iso_utc(latest)}
        except Exception as exc:
            # Leave the cursor unchanged; all event writes are duplicate-safe on retry.
            try:
                self._save_checkpoint(cursor, count, status="error", error=_safe_error_code(exc))
            except Exception:
                pass
            raise

    @classmethod
    def from_env(cls) -> "WazuhSupabaseWorker":
        supabase_url = os.getenv("SUPABASE_URL", "").strip()
        service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
        tenant_id = _uuid_env("FIRSTLIGHT_WAZUH_TENANT_ID")
        case_id = _uuid_env("FIRSTLIGHT_WAZUH_CASE_ID")
        actor_id = _uuid_env("FIRSTLIGHT_WAZUH_ACTOR_ID")
        initial_since = os.getenv("FIRSTLIGHT_WAZUH_INITIAL_SINCE", "").strip() or None
        try:
            page_size = int(os.getenv("FIRSTLIGHT_WAZUH_PAGE_SIZE", "100"))
            overlap = int(os.getenv("FIRSTLIGHT_WAZUH_OVERLAP_SECONDS", "300"))
            timeout = float(os.getenv("FIRSTLIGHT_SUPABASE_TIMEOUT_SECONDS", "8"))
        except ValueError as exc:
            raise WorkerConfigurationError("Worker numeric configuration is invalid") from exc
        rest = SupabaseServiceRest(supabase_url, service_key, timeout=timeout)
        wazuh_config = WazuhIndexerConfig.from_env()
        wazuh = WazuhIndexerClient(wazuh_config)
        return cls(
            rest=rest, wazuh=wazuh, tenant_id=tenant_id, case_id=case_id,
            actor_id=actor_id, page_size=page_size, overlap_seconds=overlap,
            initial_since=initial_since,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="FIRSTLIGHT Wazuh-to-Supabase read-only ingestion worker")
    parser.add_argument("--once", action="store_true", help="run one poll and exit")
    args = parser.parse_args()
    interval = int(os.getenv("FIRSTLIGHT_WAZUH_POLL_SECONDS", "60"))
    if not 15 <= interval <= 3600:
        raise SystemExit("FIRSTLIGHT_WAZUH_POLL_SECONDS must be between 15 and 3600")
    worker = WazuhSupabaseWorker.from_env()
    failures = 0
    while True:
        try:
            result = worker.run_once()
            failures = 0
            print(json.dumps({"component": "firstlight-wazuh-worker", **result}, separators=(",", ":")))
            delay = interval
        except Exception as exc:
            failures += 1
            delay = _retry_delay(interval, failures)
            print(json.dumps({"component": "firstlight-wazuh-worker", "status": "error", "error_code": _safe_error_code(exc), "retry_in_seconds": delay}, separators=(",", ":")))
            if args.once:
                raise SystemExit(1) from exc
        if args.once:
            return
        time.sleep(delay)


if __name__ == "__main__":
    main()
