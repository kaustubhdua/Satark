"""Explicitly opted-in live acceptance probe for the self-hosted Wazuh worker.

This test writes real Wazuh evidence and checkpoints to the configured SATARK
test case. It refuses to run without explicit write authorization and matching
tenant/case confirmation. Never use it against a production tenant.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from sqlalchemy import select

from firstlight_wazuh_worker import WazuhSatarkWorker, _parse_timestamp, _safe_error_code
from satark_backend import Evidence, IngestionCheckpoint, SessionLocal


WRITE_CONFIRMATION = "I_AUTHORIZE_WRITES_TO_THIS_TEST_CASE"


def validate_worker_acceptance(
    run_result: dict[str, Any],
    checkpoint_rows: Any,
    evidence_rows: Any,
    verified_snapshot_count: int,
) -> dict[str, Any]:
    if not isinstance(run_result, dict) or run_result.get("status") != "ok":
        raise ValueError("worker poll did not return status=ok")
    fetched, cursor = run_result.get("fetched"), run_result.get("cursor")
    if not isinstance(fetched, int) or isinstance(fetched, bool) or fetched < 1:
        raise ValueError("no real Wazuh events were fetched; acceptance cannot pass")
    if not isinstance(cursor, str) or not cursor:
        raise ValueError("worker did not return its checkpoint cursor")
    if not isinstance(checkpoint_rows, list) or not checkpoint_rows:
        raise ValueError("durable ingestion checkpoint is missing")
    checkpoint = checkpoint_rows[0]
    if not isinstance(checkpoint, dict) or checkpoint.get("last_status") != "ok":
        raise ValueError("durable ingestion checkpoint is not marked successful")
    if _parse_timestamp(str(checkpoint.get("last_event_timestamp", "")), "stored checkpoint") != _parse_timestamp(cursor, "worker cursor"):
        raise ValueError("durable checkpoint does not match the completed poll cursor")
    if not isinstance(evidence_rows, list) or not evidence_rows:
        raise ValueError("no durable Wazuh evidence rows were found for the configured case")
    if not isinstance(verified_snapshot_count, int) or verified_snapshot_count < 1:
        raise ValueError("no preserved source snapshots were re-read and verified")
    return {
        "result": "PASS",
        "component": "firstlight-wazuh-worker",
        "mode": "live_persistent_ingestion",
        "fetched_events": fetched,
        "checkpoint_status": "ok",
        "checkpoint_cursor": cursor,
        "durable_evidence_rows_examined": len(evidence_rows),
        "source_snapshot_objects_re_read_and_digest_verified": verified_snapshot_count,
        "response_actions_executed": False,
        "limitations": [
            "This proves a successful poll, a matching durable checkpoint, and byte-level verification of sampled preserved source objects.",
            "It does not independently prove Wazuh source authenticity, tenant isolation against privileged database operators, response execution, or production readiness.",
        ],
    }


def main() -> int:
    if os.getenv("FIRSTLIGHT_WAZUH_ACCEPTANCE_ALLOW_WRITES", "") != WRITE_CONFIRMATION:
        print("Refusing to run: explicit write authorization is required for an isolated test case.", file=sys.stderr)
        return 2
    try:
        worker = WazuhSatarkWorker.from_env()
        tenant_confirmation = os.getenv("FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_TENANT_ID", "").strip().lower()
        case_confirmation = os.getenv("FIRSTLIGHT_WAZUH_ACCEPTANCE_CONFIRM_CASE_ID", "").strip().lower()
        if tenant_confirmation != worker.tenant_id or case_confirmation != worker.case_id:
            print("Refusing to run: confirmation tenant/case IDs must exactly match the worker target.", file=sys.stderr)
            return 2

        result = worker.run_once()
        db = SessionLocal()
        try:
            checkpoint = db.scalar(select(IngestionCheckpoint).where(
                IngestionCheckpoint.tenant_id == worker.tenant_id,
                IngestionCheckpoint.case_id == worker.case_id,
                IngestionCheckpoint.source_key == worker.source_key,
            ))
            evidence = db.scalars(select(Evidence).where(
                Evidence.tenant_id == worker.tenant_id,
                Evidence.case_id == worker.case_id,
                Evidence.source_label == "Wazuh",
            ).order_by(Evidence.observed_at.desc()).limit(10)).all()
            checkpoint_rows = [{
                "last_status": checkpoint.last_status,
                "last_event_timestamp": checkpoint.last_event_timestamp.isoformat(),
            }] if checkpoint else []
            evidence_rows = [{
                "id": row.id, "source_sha256": row.source_sha256,
                "object_key": row.object_key, "metadata": row.metadata_json,
            } for row in evidence]
            verified = 0
            root = worker.evidence_dir.resolve()
            for row in evidence:
                path = __import__("pathlib").Path(row.object_key).resolve()
                if root not in path.parents or not path.is_file():
                    raise ValueError("a preserved source object is outside the private evidence root or missing")
                raw = path.read_bytes()
                if len(raw) > 4 * 1024 * 1024 or __import__("hashlib").sha256(raw).hexdigest() != row.source_sha256:
                    raise ValueError("a preserved source object failed byte-level digest verification")
                verified += 1
        finally:
            db.close()
        report = validate_worker_acceptance(result, checkpoint_rows, evidence_rows, verified)
        report["tenant_id"] = worker.tenant_id
        report["case_id"] = worker.case_id
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({
            "result": "FAIL", "component": "firstlight-wazuh-worker",
            "error_code": _safe_error_code(exc), "exception_type": type(exc).__name__,
            "response_actions_executed": False,
        }), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
