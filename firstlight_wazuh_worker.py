"""Self-hosted Wazuh-to-SATARK ingestion worker.

Reads from a configured Wazuh Indexer and writes tenant-scoped evidence,
private source snapshots, audit events, and checkpoints to SATARK's database.
No hosted database, storage, or identity provider is required.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from firstlight_wazuh import MAX_PAGE_SIZE, WazuhConnectorError, WazuhIndexerClient, WazuhIndexerConfig
from satark_backend import (
    Case, Evidence, IngestionCheckpoint, Membership, SessionLocal, Tenant, audit, set_rls_user_context, utcnow,
)

MAX_SOURCE_BYTES = 4 * 1024 * 1024


class WorkerConfigurationError(ValueError):
    pass


def _retry_delay(base_seconds: int, attempt: int, maximum: int = 900) -> int:
    if not 1 <= base_seconds <= 3600 or attempt < 1 or maximum < 1:
        raise ValueError("retry delay inputs are out of range")
    return min(maximum, base_seconds * (2 ** min(attempt - 1, 20)))


def _safe_error_code(exc: BaseException) -> str:
    if isinstance(exc, WorkerConfigurationError):
        return "configuration_error"
    if isinstance(exc, WazuhConnectorError):
        return "wazuh_connector_error"
    if isinstance(exc, (TimeoutError, OSError)):
        return "network_timeout_or_unavailable"
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
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class WazuhSatarkWorker:
    def __init__(self, *, wazuh: Any, tenant_id: str, case_id: str, actor_id: str,
                 page_size: int = 100, overlap_seconds: int = 300,
                 initial_since: str | None = None, evidence_dir: str | None = None):
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise WorkerConfigurationError(f"page size must be between 1 and {MAX_PAGE_SIZE}")
        if not 0 <= overlap_seconds <= 3600:
            raise WorkerConfigurationError("overlap must be between 0 and 3600 seconds")
        self.wazuh = wazuh
        self.tenant_id = tenant_id
        self.case_id = case_id
        self.actor_id = actor_id
        self.page_size = page_size
        self.overlap = timedelta(seconds=overlap_seconds)
        self.initial_since = _parse_timestamp(initial_since, "FIRSTLIGHT_WAZUH_INITIAL_SINCE") if initial_since else None
        self.evidence_dir = Path(evidence_dir or os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence")).resolve()
        agent_scope = hashlib.sha256(",".join(wazuh.config.allowed_agent_ids).encode("utf-8")).hexdigest()[:12]
        self.source_key = "wazuh-indexer:" + wazuh.config.index_pattern + ":" + agent_scope
        self._validate_target()

    def _validate_target(self) -> None:
        db = SessionLocal()
        set_rls_user_context(db, self.actor_id)
        try:
            case = db.scalar(select(Case).where(Case.id == self.case_id, Case.tenant_id == self.tenant_id))
            membership = db.scalar(select(Membership).where(
                Membership.tenant_id == self.tenant_id, Membership.user_id == self.actor_id,
            ))
            if not case:
                raise WorkerConfigurationError("Configured target case does not belong to the configured tenant")
            if not membership or membership.role not in {"owner", "responder", "analyst"}:
                raise WorkerConfigurationError("Configured actor must be an owner, responder, or analyst in the target tenant")
        finally:
            db.close()

    def _load_checkpoint(self) -> datetime:
        db = SessionLocal()
        set_rls_user_context(db, self.actor_id)
        try:
            membership = db.scalar(select(Membership).where(
                Membership.tenant_id == self.tenant_id, Membership.user_id == self.actor_id,
            ).with_for_update())
            case = db.scalar(select(Case).where(Case.id == self.case_id, Case.tenant_id == self.tenant_id))
            if not case or not membership or membership.role not in {"owner", "responder", "analyst"}:
                raise WorkerConfigurationError("Target case or actor membership is no longer authorized")
            row = db.scalar(select(IngestionCheckpoint).where(
                IngestionCheckpoint.tenant_id == self.tenant_id,
                IngestionCheckpoint.case_id == self.case_id,
                IngestionCheckpoint.source_key == self.source_key,
            ))
            if row:
                value = row.last_event_timestamp
                if value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
                return value.astimezone(timezone.utc)
            if self.initial_since is None:
                raise WorkerConfigurationError(
                    "No checkpoint exists; set FIRSTLIGHT_WAZUH_INITIAL_SINCE to an explicit ISO-8601 timestamp before first run"
                )
            return self.initial_since
        finally:
            db.close()

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
            "event_id": event_id, "timestamp": event_time, "source": "Wazuh",
            "kind": event_kind, "summary": summary, "details": details,
        }
        metadata.update({
            "source_provider": "wazuh-indexer",
            "source_details": details,
            "source_index": metadata["index"],
            "source_document_id": metadata["document_id"],
            "source_timestamp_raw": str(provenance.get("source_timestamp_raw", event.get("timestamp", "")))[:100],
            "source_object_path": source_object_path,
            "source_snapshot_preserved": True,
            "source_snapshot_bytes": int(provenance.get("source_snapshot_bytes", 0)),
            "local_evidence_id": event_id,
            "browser_record_sha256": _canonical_hash(browser_record),
            "browser_event_timestamp": event_time,
            "persisted_by_worker": True,
            "source": "FIRSTLIGHT event record",
            "record_hash_version": 2,
        })
        return {
            "tenant_id": self.tenant_id, "case_id": self.case_id,
            "source_label": "Wazuh", "event_kind": event_kind,
            "observed_at": _parse_timestamp(event_time, "event timestamp"),
            "summary": summary, "metadata": metadata,
        }

    def _persist_source_snapshot(self, digest: str, snapshot: str) -> tuple[str, int, bool]:
        raw = snapshot.encode("utf-8")
        if not raw or len(raw) > MAX_SOURCE_BYTES:
            raise WorkerConfigurationError("Wazuh source snapshot exceeds the 4 MiB evidence limit")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not hashlib.sha256(raw).hexdigest() == digest:
            raise WorkerConfigurationError("Wazuh source snapshot digest is invalid")
        relative = f"{self.tenant_id}/{self.case_id}/wazuh/{digest}.json"
        destination = (self.evidence_dir / relative).resolve()
        if self.evidence_dir not in destination.parents:
            raise WorkerConfigurationError("Evidence object path escaped the private storage root")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            existing = destination.read_bytes()
            if not hashlib.sha256(existing).hexdigest() == digest:
                raise WorkerConfigurationError("Existing Wazuh source snapshot failed integrity verification")
            return relative, len(existing), False
        temporary = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".part")
        try:
            with temporary.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return relative, len(raw), True

    def _save_event(self, event: dict[str, Any]) -> bool:
        provenance = event.get("provenance") if isinstance(event.get("provenance"), dict) else {}
        snapshot = event.get("source_snapshot_json")
        source_hash = str(provenance.get("source_record_sha256", ""))
        if not isinstance(snapshot, str) or not snapshot:
            raise WorkerConfigurationError("Wazuh source snapshot was not returned; refusing digest-only evidence persistence")
        record = self._event_record(event, "")
        if not record["summary"]:
            raise WorkerConfigurationError("Wazuh event had no usable summary")
        relative, byte_count, created_object = self._persist_source_snapshot(source_hash, snapshot)
        record["metadata"]["source_object_path"] = relative
        db = SessionLocal()
        set_rls_user_context(db, self.actor_id)
        try:
            case = db.scalar(select(Case).where(Case.id == self.case_id, Case.tenant_id == self.tenant_id).with_for_update())
            membership = db.scalar(select(Membership).where(
                Membership.tenant_id == self.tenant_id, Membership.user_id == self.actor_id,
            ).with_for_update())
            if not case or not membership or membership.role not in {"owner", "responder", "analyst"}:
                raise WorkerConfigurationError("Target case or actor membership is no longer authorized")
            existing = db.scalar(select(Evidence).where(
                Evidence.tenant_id == self.tenant_id,
                Evidence.case_id == self.case_id,
                Evidence.source_sha256 == source_hash,
            ))
            if existing:
                return False
            row = Evidence(
                tenant_id=self.tenant_id, case_id=self.case_id, object_key=str((self.evidence_dir / relative).resolve()),
                source_label="Wazuh", event_kind=record["event_kind"], observed_at=record["observed_at"],
                summary=record["summary"], source_sha256=source_hash, size_bytes=byte_count,
                content_type="application/json", original_filename="wazuh-source.json",
                metadata_json=record["metadata"], created_by=self.actor_id,
            )
            db.add(row)
            db.flush()
            audit(db, self.tenant_id, self.actor_id, "wazuh.evidence.ingested", {
                "case_id": self.case_id, "evidence_id": row.id, "source_sha256": source_hash,
                "source_document_id": record["metadata"]["source_document_id"],
            })
            db.commit()
            return True
        except IntegrityError:
            db.rollback()
            existing = db.scalar(select(Evidence).where(
                Evidence.tenant_id == self.tenant_id, Evidence.case_id == self.case_id,
                Evidence.source_sha256 == source_hash,
            ))
            if existing:
                return False
            if created_object:
                (self.evidence_dir / relative).resolve().unlink(missing_ok=True)
            raise
        except Exception:
            db.rollback()
            if created_object:
                (self.evidence_dir / relative).resolve().unlink(missing_ok=True)
            raise
        finally:
            db.close()

    def _save_checkpoint(self, cursor: datetime, count: int, *, status: str = "ok", error: str | None = None) -> None:
        db = SessionLocal()
        set_rls_user_context(db, self.actor_id)
        try:
            row = db.scalar(select(IngestionCheckpoint).where(
                IngestionCheckpoint.tenant_id == self.tenant_id,
                IngestionCheckpoint.case_id == self.case_id,
                IngestionCheckpoint.source_key == self.source_key,
            ).with_for_update())
            now = utcnow()
            if row is None:
                row = IngestionCheckpoint(
                    tenant_id=self.tenant_id, case_id=self.case_id, source_key=self.source_key,
                    last_event_timestamp=cursor, last_batch_count=count, last_status=status,
                    last_error=error, last_success_at=now if status == "ok" else None, updated_at=now,
                )
                db.add(row)
            else:
                row.last_event_timestamp = cursor
                row.last_batch_count = count
                row.last_status = status
                row.last_error = error
                if status == "ok":
                    row.last_success_at = now
                row.updated_at = now
            db.commit()
        finally:
            db.close()

    def run_once(self) -> dict[str, Any]:
        self._validate_target()
        cursor = self._load_checkpoint()
        since = _iso_utc(cursor - self.overlap)
        until_dt = datetime.now(timezone.utc)
        until = _iso_utc(until_dt)
        offset = 0
        fetched_count = 0
        persisted_count = 0
        try:
            while True:
                self._validate_target()
                page = self.wazuh.fetch_alerts(
                    limit=self.page_size, since=since, until=until, offset=offset, include_source_snapshot=True,
                )
                self._validate_target()
                fetched_count += len(page)
                for event in page:
                    if self._save_event(event):
                        persisted_count += 1
                if len(page) < self.page_size:
                    break
                offset += len(page)
                if offset + self.page_size > 10_000:
                    raise WazuhConnectorError(
                        "The time window contains at least 10,000 alerts; reduce the polling interval or backfill window"
                    )
            self._validate_target()
            self._save_checkpoint(until_dt, fetched_count)
            return {"status": "ok", "fetched": fetched_count, "persisted": persisted_count, "cursor": until}
        except Exception as exc:
            try:
                self._validate_target()
                self._save_checkpoint(cursor, fetched_count, status="error", error=_safe_error_code(exc))
            except Exception:
                pass
            raise

    @classmethod
    def from_env(cls) -> "WazuhSatarkWorker":
        tenant_id = _uuid_env("FIRSTLIGHT_WAZUH_TENANT_ID")
        case_id = _uuid_env("FIRSTLIGHT_WAZUH_CASE_ID")
        actor_id = _uuid_env("FIRSTLIGHT_WAZUH_ACTOR_ID")
        initial_since = os.getenv("FIRSTLIGHT_WAZUH_INITIAL_SINCE", "").strip() or None
        try:
            page_size = int(os.getenv("FIRSTLIGHT_WAZUH_PAGE_SIZE", "100"))
            overlap = int(os.getenv("FIRSTLIGHT_WAZUH_OVERLAP_SECONDS", "300"))
        except ValueError as exc:
            raise WorkerConfigurationError("Worker numeric configuration is invalid") from exc
        wazuh_config = WazuhIndexerConfig.from_env()
        return cls(
            wazuh=WazuhIndexerClient(wazuh_config), tenant_id=tenant_id, case_id=case_id,
            actor_id=actor_id, page_size=page_size, overlap_seconds=overlap,
            initial_since=initial_since,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="FIRSTLIGHT Wazuh-to-SATARK private ingestion worker")
    parser.add_argument("--once", action="store_true", help="run one poll and exit")
    args = parser.parse_args()
    interval = int(os.getenv("FIRSTLIGHT_WAZUH_POLL_SECONDS", "60"))
    if not 15 <= interval <= 3600:
        raise SystemExit("FIRSTLIGHT_WAZUH_POLL_SECONDS must be between 15 and 3600")
    worker = WazuhSatarkWorker.from_env()
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
            print(json.dumps({"component": "firstlight-wazuh-worker", "status": "error",
                "error_code": _safe_error_code(exc), "retry_in_seconds": delay}, separators=(",", ":")))
            if args.once:
                raise SystemExit(1) from exc
        if args.once:
            return
        time.sleep(delay)


if __name__ == "__main__":
    main()
