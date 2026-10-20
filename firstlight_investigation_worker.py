"""Durable FIRSTLIGHT investigation-job worker.

Runs on a private persistent host. Jobs are atomically leased in Postgres;
deterministic investigation output is persisted before the job is marked complete.
No response actions are executed here. Ollama is intentionally not required for
the deterministic job path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from typing import Any

from firstlight_engine import investigate_case, sha256_record
from firstlight_wazuh_worker import SupabaseRestError, SupabaseServiceRest, WorkerConfigurationError


MAX_CASE_EVIDENCE = 500
MAX_RESULT_BYTES = 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class InvestigationJobWorker:
    def __init__(self, rest: Any, lease_seconds: int = 120):
        if not 15 <= lease_seconds <= 600:
            raise ValueError("lease_seconds must be between 15 and 600")
        self.rest = rest
        self.lease_seconds = lease_seconds

    def _finish(self, job_id: str, status: str, *, result: dict[str, Any] | None = None,
                result_sha256: str | None = None, error_code: str | None = None) -> Any:
        body = {
            "p_job_id": job_id,
            "p_status": status,
            "p_result": result,
            "p_result_sha256": result_sha256,
            "p_error_code": error_code,
        }
        return self.rest.request("POST", "rpc/satark_finish_investigation_job", body=body)

    def run_once(self) -> dict[str, Any]:
        claimed = self.rest.request(
            "POST", "rpc/satark_claim_investigation_job",
            body={"p_lease_seconds": self.lease_seconds},
        )
        if isinstance(claimed, dict):
            jobs = [claimed]
        elif isinstance(claimed, list):
            jobs = claimed
        else:
            jobs = []
        if not jobs:
            return {"status": "idle"}
        job = jobs[0]
        job_id = str(job.get("id", ""))
        try:
            result = self._investigate(job)
            encoded = _canonical(result)
            if len(encoded) > MAX_RESULT_BYTES:
                raise ValueError("result_too_large")
            digest = hashlib.sha256(encoded).hexdigest()
            self._finish(job_id, "succeeded", result=result, result_sha256=digest)
            return {"status": "succeeded", "job_id": job_id, "result_sha256": digest}
        except Exception as exc:
            # Store only a stable error code, never exception strings that may
            # contain URLs, credentials, event content, or database responses.
            code = str(exc) if str(exc) in {
                "case_not_found", "requester_not_member", "evidence_limit_exceeded",
                "case_title_invalid", "result_too_large", "evidence_shape_invalid",
            } else "investigation_failed"
            try:
                attempts = int(job.get("attempts", 1))
                max_attempts = int(job.get("max_attempts", 3))
                next_status = "queued" if attempts < max_attempts else "failed"
                self._finish(job_id, next_status, error_code=code)
            except Exception:
                # A failed completion write leaves the lease to expire and be
                # reclaimed; the next attempt is idempotent by job ID.
                pass
            return {"status": "failed", "job_id": job_id, "error_code": code}

    def _investigate(self, job: dict[str, Any]) -> dict[str, Any]:
        job_id = str(job.get("id", ""))
        tenant_id = str(job.get("tenant_id", ""))
        case_id = str(job.get("case_id", ""))
        requester = str(job.get("requested_by", ""))
        if not all((job_id, tenant_id, case_id, requester)):
            raise ValueError("case_not_found")
        cases = self.rest.request("GET", "satark_cases", query={
            "select": "id,tenant_id,title,status,severity,metadata",
            "id": "eq." + case_id, "tenant_id": "eq." + tenant_id, "limit": "1",
        }) or []
        if not cases:
            raise ValueError("case_not_found")
        memberships = self.rest.request("GET", "satark_memberships", query={
            "select": "tenant_id,user_id,role",
            "tenant_id": "eq." + tenant_id, "user_id": "eq." + requester,
            "role": "in.(owner,responder,analyst)", "limit": "1",
        }) or []
        if not memberships:
            raise ValueError("requester_not_member")
        rows = self.rest.request("GET", "satark_evidence", query={
            "select": "id,tenant_id,case_id,source_label,event_kind,observed_at,summary,source_sha256,record_sha256,metadata,created_at",
            "tenant_id": "eq." + tenant_id, "case_id": "eq." + case_id,
            "order": "observed_at.asc", "limit": str(MAX_CASE_EVIDENCE + 1),
        }) or []
        if len(rows) > MAX_CASE_EVIDENCE:
            raise ValueError("evidence_limit_exceeded")
        envelopes: list[dict[str, Any]] = []
        source_records: list[dict[str, Any]] = []
        for row in rows:
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            details = metadata.get("source_details") if isinstance(metadata.get("source_details"), dict) else {}
            event_id = str(metadata.get("local_evidence_id") or row.get("id") or "")
            observed_at = row.get("observed_at")
            if not event_id or not isinstance(observed_at, str) or not observed_at:
                raise ValueError("evidence_shape_invalid")
            record = {
                "event_id": event_id,
                "timestamp": observed_at,
                "source": str(row.get("source_label") or "unknown")[:160],
                "kind": str(row.get("event_kind") or "observation")[:100],
                "summary": str(row.get("summary") or "")[:4096],
                "details": details,
            }
            # Recompute from the exact normalized record passed to the engine.
            # This validates the worker's deterministic envelope; it is not
            # represented as independent proof that the original source was true.
            normalized_digest = sha256_record(record)
            envelopes.append({
                "evidence_id": event_id,
                "record": record,
                "sha256": normalized_digest,
                "collected_at": str(row.get("created_at") or ""),
                "integrity_status": "verified",
            })
            source_records.append({
                "id": str(row.get("id")),
                "event_id": event_id,
                "stored_record_sha256": row.get("record_sha256"),
                "source_sha256": row.get("source_sha256"),
                "normalized_sha256": normalized_digest,
            })
        case = cases[0]
        investigation = investigate_case(
            {"case_id": case_id, "title": str(case.get("title") or "FIRSTLIGHT case")},
            envelopes,
        )
        result = {
            "schema_version": "1.0",
            "job_id": job_id,
            "tenant_id": tenant_id,
            "case_id": case_id,
            "run_version": str(job.get("run_version") or "1.0"),
            "status": "completed",
            "evidence_count": len(envelopes),
            "evidence_provenance": source_records,
            "investigation": investigation,
            "limitations": [
                "Deterministic rules are triage aids, not proof of compromise.",
                "Normalized-record hashes do not independently prove source authenticity or collector identity.",
                "Only persisted case evidence was evaluated; missing telemetry is an evidence gap, not proof of absence.",
                "This worker performs no live response actions.",
            ],
        }
        self._persist_findings(job, result, investigation)
        self._persist_report(job, result)
        return result

    def _persist_findings(self, job: dict[str, Any], result: dict[str, Any], investigation: Any) -> None:
        if not isinstance(investigation, dict):
            return
        findings = investigation.get("findings", [])
        if not isinstance(findings, list):
            return
        for index, finding in enumerate(findings[:100]):
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or finding.get("name") or "FIRSTLIGHT finding")[:240]
            severity = str(finding.get("severity") or "review").lower()
            if severity not in {"info", "low", "medium", "high", "critical", "review", "unknown"}:
                severity = "review"
            refs = finding.get("evidence_ids", finding.get("evidence_refs", []))
            if not isinstance(refs, list):
                refs = []
            safe_refs = [str(ref)[:100] for ref in refs[:50] if isinstance(ref, (str, int))]
            detail = str(finding.get("rationale") or finding.get("detail") or finding.get("description") or "")[:8192]
            key = ("fljob-" + str(job.get("id", ""))[:36] + "-" + str(index))[:160]
            body = {
                "tenant_id": job["tenant_id"], "case_id": job["case_id"],
                "finding_key": key, "title": title, "severity": severity,
                "detail": detail or "Deterministic finding; see persisted job result for full context.",
                "evidence_refs": safe_refs, "source": "FIRSTLIGHT deterministic job",
                "confidence": finding.get("confidence") if isinstance(finding.get("confidence"), (int, float)) else None,
                "created_by": job["requested_by"],
            }
            self.rest.request("POST", "satark_findings", query={"on_conflict": "case_id,finding_key"}, body=body, prefer="resolution=ignore-duplicates,return=minimal")

    def _persist_report(self, job: dict[str, Any], result: dict[str, Any]) -> None:
        snapshot = result
        digest = _digest(snapshot)
        body = {
            "tenant_id": job["tenant_id"], "case_id": job["case_id"],
            "title": "FIRSTLIGHT investigation " + str(job.get("id", ""))[:8],
            "report_version": 1, "snapshot": snapshot, "snapshot_sha256": digest,
            "created_by": job["requested_by"],
        }
        # A report insert failure fails the job; retrying uses the same content
        # digest and the unique constraint prevents duplicate snapshots.
        try:
            self.rest.request("POST", "satark_reports", query={"on_conflict": "case_id,snapshot_sha256"}, body=body, prefer="resolution=ignore-duplicates,return=minimal")
        except SupabaseRestError as exc:
            if "HTTP 409" not in str(exc):
                raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="claim and process at most one job")
    parser.add_argument("--poll-seconds", type=int, default=int(os.getenv("FIRSTLIGHT_JOB_POLL_SECONDS", "5")))
    parser.add_argument("--lease-seconds", type=int, default=int(os.getenv("FIRSTLIGHT_JOB_LEASE_SECONDS", "120")))
    args = parser.parse_args()
    if not 1 <= args.poll_seconds <= 60:
        parser.error("--poll-seconds must be between 1 and 60")
    rest = SupabaseServiceRest(
        os.getenv("SUPABASE_URL", ""),
        os.getenv("SUPABASE_SERVICE_ROLE_KEY", ""),
    )
    worker = InvestigationJobWorker(rest, lease_seconds=args.lease_seconds)
    while True:
        outcome = worker.run_once()
        print(json.dumps(outcome, separators=(",", ":")), flush=True)
        if args.once:
            return 0 if outcome["status"] in {"idle", "succeeded"} else 1
        if outcome["status"] == "idle":
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
