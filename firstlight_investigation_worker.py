"""Durable FIRSTLIGHT investigation-job worker.

Runs on a private persistent host. Jobs are atomically leased in Postgres;
deterministic investigation output is persisted before the job is marked complete.
No response actions are executed here. Ollama is intentionally not required for
the deterministic job path.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
from typing import Any

from firstlight_engine import investigate_case, sha256_record
from firstlight_wazuh_worker import SupabaseRestError, SupabaseServiceRest, WorkerConfigurationError, _retry_delay, _safe_error_code


MAX_CASE_EVIDENCE = 500
MAX_RESULT_BYTES = 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded_details(value: Any, max_bytes: int = 8192) -> tuple[dict[str, Any], bool]:
    """Keep useful primitive evidence fields bounded before engine/output expansion."""
    if not isinstance(value, dict):
        return {}, value not in ({}, None)
    safe: dict[str, Any] = {}
    truncated = False
    for key in sorted(value)[:40]:
        item = value[key]
        name = str(key)[:80]
        if isinstance(item, str):
            safe[name] = item[:512]
            truncated = truncated or len(item) > 512
        elif isinstance(item, bool) or isinstance(item, int):
            safe[name] = item
        elif isinstance(item, float):
            import math
            if math.isfinite(item):
                safe[name] = item
            else:
                truncated = True
        elif isinstance(item, list):
            entries = []
            for entry in item[:20]:
                if isinstance(entry, str):
                    entries.append(entry[:128])
                    truncated = truncated or len(entry) > 128
                elif isinstance(entry, (bool, int)):
                    entries.append(entry)
                elif isinstance(entry, float):
                    import math
                    if math.isfinite(entry):
                        entries.append(entry)
                else:
                    truncated = True
            safe[name] = entries
            truncated = truncated or len(item) > 20
        elif isinstance(item, dict):
            nested: dict[str, Any] = {}
            for child_key in sorted(item)[:30]:
                child = item[child_key]
                child_name = str(child_key)[:80]
                if isinstance(child, str):
                    nested[child_name] = child[:256]
                    truncated = truncated or len(child) > 256
                elif isinstance(child, (bool, int)):
                    nested[child_name] = child
                elif isinstance(child, float):
                    import math
                    if math.isfinite(child):
                        nested[child_name] = child
                    else:
                        truncated = True
                elif isinstance(child, list):
                    nested[child_name] = [x[:128] if isinstance(x, str) else x for x in child[:20]
                                          if isinstance(x, (str, int, bool))]
                    truncated = True
                else:
                    truncated = True
            safe[name] = nested
            truncated = truncated or len(item) > 30
        else:
            truncated = True
    truncated = truncated or len(value) > 40
    while safe and len(_canonical(safe)) > max_bytes:
        safe.pop(next(reversed(safe)))
        truncated = True
    if len(_canonical(safe)) > max_bytes:
        return {}, True
    return safe, truncated


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
            "select": "id,tenant_id,case_id,source_label,event_kind,observed_at,summary,source_sha256,record_sha256,metadata,created_by,created_at",
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
            browser_timestamp = str(metadata.get("browser_event_timestamp") or observed_at)
            original_record = {
                "event_id": event_id,
                "timestamp": browser_timestamp,
                "source": str(row.get("source_label") or "unknown")[:160],
                "kind": str(row.get("event_kind") or "observation")[:100],
                "summary": str(row.get("summary") or "")[:4096],
                "details": details,
            }
            original_digest = sha256_record(original_record)
            expected_browser_digest = str(metadata.get("browser_record_sha256") or "")
            browser_digest_valid = bool(
                len(expected_browser_digest) == 64
                and hmac.compare_digest(original_digest, expected_browser_digest)
            )
            bounded_details, details_truncated = _bounded_details(details)
            record = {**original_record, "details": bounded_details}
            normalized_digest = sha256_record(record)

            # Version-2 database envelopes use sorted-key canonical JSON. Legacy
            # rows are not falsely labelled corrupt merely because they predate it.
            stored_envelope_valid: bool | None = None
            if metadata.get("record_hash_version") == 2:
                from datetime import datetime, timezone
                try:
                    parsed_time = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
                    if parsed_time.tzinfo is None:
                        raise ValueError("naive timestamp")
                    canonical_time = parsed_time.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    stored_record = {
                        "tenant_id": tenant_id,
                        "case_id": case_id,
                        "source_label": str(row.get("source_label") or ""),
                        "event_kind": str(row.get("event_kind") or ""),
                        "observed_at": canonical_time,
                        "summary": str(row.get("summary") or ""),
                        "metadata": metadata,
                        "created_by": str(row.get("created_by") or ""),
                    }
                    actual_envelope_digest = _digest(stored_record)
                    stored_envelope_valid = hmac.compare_digest(actual_envelope_digest, str(row.get("record_sha256") or ""))
                except (TypeError, ValueError, OverflowError):
                    stored_envelope_valid = False

            source_snapshot_status = "not_applicable"
            if metadata.get("persisted_by_worker") is True:
                source_path = str(metadata.get("source_object_path") or "")
                source_digest = str(row.get("source_sha256") or "")
                verifier = getattr(self.rest, "verify_source_snapshot", None)
                if callable(verifier):
                    try:
                        source_snapshot_status = "verified" if verifier(
                            tenant_id=tenant_id, case_id=case_id, path=source_path, digest=source_digest,
                        ) else "mismatch"
                    except Exception:
                        source_snapshot_status = "unavailable"
                else:
                    source_snapshot_status = "unverified"

            integrity_ok = browser_digest_valid and stored_envelope_valid is not False
            if source_snapshot_status == "mismatch":
                integrity_ok = False
            # If a source object cannot be fetched right now, retain a valid
            # normalized event but explicitly disclose that source verification
            # is unavailable. Never claim the raw source object was verified.
            envelopes.append({
                "evidence_id": event_id,
                "record": record,
                "sha256": normalized_digest if integrity_ok else "",
                "collected_at": str(row.get("created_at") or ""),
                "integrity_status": "verified" if integrity_ok else "mismatch",
            })
            source_records.append({
                "id": str(row.get("id")),
                "event_id": event_id,
                "stored_record_sha256": row.get("record_sha256"),
                "stored_record_hash_status": (
                    "verified" if stored_envelope_valid is True
                    else "mismatch" if stored_envelope_valid is False
                    else "legacy_not_recomputed"
                ),
                "browser_record_sha256": expected_browser_digest or None,
                "browser_record_hash_status": "verified" if browser_digest_valid else "mismatch_or_missing",
                "source_sha256": row.get("source_sha256"),
                "source_snapshot_status": source_snapshot_status,
                "normalized_sha256": normalized_digest,
                "details_truncated": details_truncated,
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
        for source_record in source_records:
            if source_record.get("source_snapshot_status") in {"mismatch", "unavailable", "unverified"}:
                investigation.setdefault("gaps", []).append(
                    "Source snapshot verification is " + str(source_record["source_snapshot_status"]) +
                    " for evidence " + str(source_record.get("event_id", "unknown")) + "."
                )
            if source_record.get("details_truncated"):
                investigation.setdefault("gaps", []).append(
                    "Some evidence fields were bounded before deterministic analysis for evidence " +
                    str(source_record.get("event_id", "unknown")) + "."
                )
            if source_record.get("browser_record_hash_status") != "verified":
                investigation.setdefault("gaps", []).append(
                    "Normalized evidence digest is missing or mismatched for evidence " +
                    str(source_record.get("event_id", "unknown")) + "."
                )
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
            detail = str(finding.get("explanation") or finding.get("rationale") or finding.get("detail") or finding.get("description") or "")[:8192]
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
    failures = 0
    while True:
        try:
            outcome = worker.run_once()
            if outcome["status"] in {"idle", "succeeded"}:
                failures = 0
                delay = args.poll_seconds
            else:
                failures += 1
                delay = _retry_delay(args.poll_seconds, failures, maximum=60)
            print(json.dumps(outcome, separators=(",", ":")), flush=True)
            if args.once:
                return 0 if outcome["status"] in {"idle", "succeeded"} else 1
        except Exception as exc:
            failures += 1
            delay = _retry_delay(args.poll_seconds, failures, maximum=60)
            print(json.dumps({"status":"error","error_code":_safe_error_code(exc),"retry_in_seconds":delay}, separators=(",", ":")), flush=True)
            if args.once:
                return 1
        time.sleep(delay)


if __name__ == "__main__":
    raise SystemExit(main())
