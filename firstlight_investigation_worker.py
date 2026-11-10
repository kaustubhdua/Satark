"""Self-hosted durable FIRSTLIGHT investigation worker.

Claims SATARK jobs from the same SQLAlchemy database used by the API.
No Supabase REST, Storage, service-role credential, or hosted auth dependency.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import timedelta, timezone

from sqlalchemy import or_, select

from firstlight_engine import investigate_case, sha256_record
from firstlight_agents import run_independent_agents
from satark_backend import (
    Case, Evidence, Finding, InvestigationJob, Report, SessionLocal, audit, set_rls_user_context, set_rls_worker_context, utcnow,
)

MAX_EVIDENCE = 500
MAX_TOTAL_EVIDENCE_BYTES = 32 * 1024 * 1024
MAX_RESULT_BYTES = 1024 * 1024


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


class InvestigationJobWorker:
    def __init__(self, lease_seconds: int = 120):
        if not 15 <= lease_seconds <= 600:
            raise ValueError("lease_seconds must be between 15 and 600")
        self.lease_seconds = lease_seconds

    def claim(self):
        db = SessionLocal()
        set_rls_worker_context(db)
        try:
            now = utcnow()
            query = (select(InvestigationJob)
                .where(or_(InvestigationJob.status == "queued",
                    (InvestigationJob.status == "running") & (InvestigationJob.lease_until < now)))
                .order_by(InvestigationJob.created_at.asc())
                .limit(1)
                .with_for_update(skip_locked=True))
            job = db.scalar(query)
            if not job:
                return None
            if job.attempts >= job.max_attempts:
                job.status = "failed"
                job.error_code = "retry_limit_reached"
                job.updated_at = now
                db.commit()
                return None
            job.status = "running"
            job.attempts += 1
            job.lease_until = now + timedelta(seconds=self.lease_seconds)
            job.updated_at = now
            db.commit()
            return job.id
        finally:
            db.close()

    def run_once(self):
        job_id = self.claim()
        if not job_id:
            return {"status": "idle"}
        db = SessionLocal()
        set_rls_worker_context(db)
        try:
            job = db.get(InvestigationJob, job_id)
            if not job or job.status != "running":
                return {"status": "lost_lease", "job_id": job_id}
            set_rls_user_context(db, job.requested_by)
            case = db.scalar(select(Case).where(Case.id == job.case_id, Case.tenant_id == job.tenant_id))
            if not case:
                raise ValueError("case_not_found")
            evidence = db.scalars(select(Evidence).where(
                Evidence.tenant_id == job.tenant_id, Evidence.case_id == job.case_id
            ).order_by(Evidence.observed_at.asc()).limit(MAX_EVIDENCE + 1)).all()
            if len(evidence) > MAX_EVIDENCE:
                raise ValueError("evidence_limit_exceeded")
            envelopes = []
            integrity = []
            total_evidence_bytes = 0
            root = os.path.realpath(os.getenv("SATARK_EVIDENCE_DIR", "./data/evidence"))
            for item in evidence:
                path = os.path.realpath(item.object_key)
                if not path.startswith(root + os.sep) or not os.path.isfile(path):
                    raise ValueError("evidence_object_missing")
                with open(path, "rb") as handle:
                    raw = handle.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise ValueError("evidence_object_too_large")
                total_evidence_bytes += len(raw)
                if total_evidence_bytes > MAX_TOTAL_EVIDENCE_BYTES:
                    raise ValueError("case_evidence_bytes_exceeded")
                actual = hashlib.sha256(raw).hexdigest()
                valid = actual == item.source_sha256
                integrity.append({"evidence_id": item.id, "valid": valid,
                    "status": "VERIFIED" if valid else "HASH MISMATCH"})
                details = {}
                if item.content_type == "application/json":
                    try:
                        parsed = json.loads(raw.decode("utf-8"))
                        details = item.metadata_json if isinstance(item.metadata_json, dict) and item.metadata_json else (parsed if isinstance(parsed, dict) else {})
                    except (ValueError, UnicodeDecodeError):
                        details = {}
                observed_at = item.observed_at
                created_at = item.created_at
                if observed_at.tzinfo is None:
                    observed_at = observed_at.replace(tzinfo=timezone.utc)
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                record = {"event_id": item.id, "timestamp": observed_at.isoformat(),
                    "source": item.source_label, "kind": item.event_kind, "summary": item.summary,
                    "details": details}
                envelopes.append({"evidence_id": item.id, "record": record,
                    "sha256": sha256_record(record) if valid else "0" * 64,
                    "collected_at": created_at.isoformat(),
                    "integrity_status": "verified" if valid else "mismatch"})
            result = investigate_case({"case_id": case.id, "title": case.title}, envelopes)
            agent_events = [{
                "id": item["record"]["event_id"],
                "time": item["record"]["timestamp"],
                "source": item["record"]["source"],
                "kind": item["record"]["kind"],
                "summary": item["record"]["summary"],
                "details": item["record"]["details"],
                "integrity": item["integrity_status"],
            } for item in envelopes]
            try:
                agent_analysis = run_independent_agents(agent_events)
            except Exception:
                # Optional local model failures never suppress deterministic results.
                agent_analysis = {
                    "enabled": os.getenv("FIRSTLIGHT_MODEL_AGENTS_ENABLED", "").lower() in {"1", "true", "yes"},
                    "mode": "agent_error", "agents": [],
                    "limitations": ["Local model agents failed; deterministic findings remain authoritative."],
                }
            payload = {"schema_version": "1.1", "case_id": case.id, "integrity": integrity,
                "integrity_summary": {"total": len(integrity),
                    "verified": sum(1 for x in integrity if x["valid"]),
                    "mismatched": sum(1 for x in integrity if not x["valid"])},
                "investigation": result, "agent_analysis": agent_analysis,
                "limitations": ["Only evidence already stored in this SATARK case was analyzed.",
                    "Stored-byte digest checks do not prove original source authenticity.",
                    "Optional local model analysis is advisory; deterministic findings remain authoritative.",
                    "No live response action was executed."]}
            encoded = canonical(payload)
            if len(encoded) > MAX_RESULT_BYTES:
                raise ValueError("result_too_large")
            digest = hashlib.sha256(encoded).hexdigest()
            report = Report(tenant_id=job.tenant_id, case_id=job.case_id,
                title="FIRSTLIGHT investigation", snapshot=payload, snapshot_sha256=digest,
                report_version=1, created_by=job.requested_by)
            for index, finding in enumerate(result.get("findings", [])):
                if not isinstance(finding, dict):
                    continue
                refs = finding.get("evidence_ids", [])
                refs = [value for value in refs if isinstance(value, str) and value in {item.id for item in evidence}]
                db.add(Finding(
                    tenant_id=job.tenant_id, case_id=job.case_id,
                    finding_key=str(finding.get("finding_id") or f"finding-{index}")[:160],
                    title=str(finding.get("title") or "Untitled finding")[:240],
                    severity=str(finding.get("severity") or "unknown")[:16],
                    detail=str(finding.get("explanation") or "")[:8192],
                    evidence_refs=refs, source="FIRSTLIGHT deterministic rules",
                    confidence=None, created_by=job.requested_by,
                ))
            db.add(report)
            db.flush()
            job.status = "succeeded"
            job.result = payload
            job.result_sha256 = digest
            job.error_code = None
            job.lease_until = None
            job.updated_at = utcnow()
            audit(db, job.tenant_id, job.requested_by, "investigation.completed",
                {"job_id": job.id, "report_id": report.id, "result_sha256": digest})
            db.commit()
            return {"status": "succeeded", "job_id": job.id, "result_sha256": digest}
        except Exception as exc:
            db.rollback()
            job = db.get(InvestigationJob, job_id)
            if job:
                code = str(exc) if str(exc) in {
                    "case_not_found", "evidence_limit_exceeded", "evidence_object_missing",
                    "evidence_object_too_large", "case_evidence_bytes_exceeded", "result_too_large",
                } else "investigation_failed"
                job.error_code = code
                job.status = "queued" if job.attempts < job.max_attempts else "failed"
                job.lease_until = None
                job.updated_at = utcnow()
                db.commit()
            return {"status": "failed", "job_id": job_id, "error_code": code}
        finally:
            db.close()


def main():
    poll = max(1, min(60, int(os.getenv("FIRSTLIGHT_JOB_POLL_SECONDS", "5"))))
    worker = InvestigationJobWorker(int(os.getenv("FIRSTLIGHT_JOB_LEASE_SECONDS", "120")))
    while True:
        result = worker.run_once()
        if result["status"] == "idle":
            time.sleep(poll)


if __name__ == "__main__":
    main()
