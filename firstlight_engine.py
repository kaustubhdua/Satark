"""FIRSTLIGHT incident-response core for SATARK.

Synthetic-first incident workflow with deterministic evidence integrity,
evidence-linked findings, a hash-chained audit trail, and approval-gated
response simulation. No real endpoint or network actions are performed.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
import uuid
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_record(record: dict[str, Any]) -> str:
    """Hash a record's canonical JSON representation."""
    return hashlib.sha256(_canonical(record)).hexdigest()


def _event(event_id: str, timestamp: str, source: str, kind: str, summary: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": source,
        "kind": kind,
        "summary": summary,
        "details": details,
    }


def create_demo_case() -> dict[str, Any]:
    """Return a repeatable, fictional account-compromise scenario."""
    start = datetime(2026, 10, 10, 9, 15, tzinfo=timezone.utc)
    raw_events = [
        ("EV-001", 0, "identity", "authentication", "Successful login from a new source", {"account": "analyst@example.test", "source_ip": "198.51.100.24", "result": "success", "novel_source": True}),
        ("EV-002", 4, "endpoint", "process", "Unusual script interpreter launched", {"host": "WS-DEMO-04", "process": "powershell.exe", "parent": "outlook.exe", "rule": "unusual_parent_child"}),
        ("EV-003", 7, "network", "connection", "Endpoint connected to a suspicious test domain", {"host": "WS-DEMO-04", "destination": "updates-example.invalid", "port": 443, "disposition": "simulated"}),
        ("EV-004", 11, "filesystem", "file", "A staged archive was created in a temporary directory", {"host": "WS-DEMO-04", "path": "C:/Temp/collection-demo.zip", "execution": "not performed"}),
        ("EV-005", 15, "identity", "session", "A second session token was issued", {"account": "analyst@example.test", "session": "SESSION-DEMO-2", "source_ip": "198.51.100.24"}),
    ]
    records = []
    for event_id, minutes, source, kind, summary, details in raw_events:
        timestamp = (start + timedelta(minutes=minutes)).isoformat()
        records.append(_event(event_id, timestamp, source, kind, summary, details))
    return {
        "case_id": "FL-DEMO-2026-001",
        "title": "Possible account compromise and endpoint staging",
        "scenario": "Synthetic training incident. All identities, hosts and indicators are fictional.",
        "status": "investigating",
        "severity": "high",
        "created_at": start.isoformat(),
        "events": records,
    }


def seal_evidence(event: dict[str, Any]) -> dict[str, Any]:
    record = deepcopy(event)
    return {
        "evidence_id": record["event_id"],
        "record": record,
        "sha256": sha256_record(record),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "integrity_status": "verified",
    }


def verify_evidence(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {
            "evidence_id": "unknown",
            "expected_sha256": "",
            "actual_sha256": "",
            "valid": False,
            "status": "HASH MISMATCH — POSSIBLE TAMPERING",
        }
    record = item.get("record", {})
    try:
        actual = sha256_record(record)
    except (TypeError, ValueError, RecursionError, UnicodeError, OverflowError):
        actual = ""
    expected = str(item.get("sha256", ""))
    evidence_id = item.get("evidence_id", "unknown")
    # The envelope ID is used to join findings and timeline entries. Bind it
    # to the hashed record's event_id so an attacker cannot swap the displayed
    # reference while keeping an otherwise valid record hash.
    record_id = record.get("event_id") if isinstance(record, dict) else None
    id_matches = bool(record_id) and evidence_id == record_id
    valid = bool(expected) and bool(actual) and actual == expected and id_matches
    return {
        "evidence_id": evidence_id,
        "expected_sha256": expected,
        "actual_sha256": actual,
        "valid": valid,
        "status": "VERIFIED" if valid else "HASH MISMATCH — POSSIBLE TAMPERING",
    }


def _timeline_sort_key(value: Any) -> datetime:
    """Sort ISO timestamps by instant, treating naive values as UTC."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return datetime.max.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def make_audit_entry(action: str, actor: str, payload: dict[str, Any], previous_hash: str) -> dict[str, Any]:
    entry = {
        "audit_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "payload": deepcopy(payload),
        "previous_hash": previous_hash,
    }
    entry["entry_hash"] = sha256_record(entry)
    return entry


def verify_audit_chain(entries: list[dict[str, Any]]) -> bool:
    """Return False for malformed or non-canonicalizable audit data."""
    if not isinstance(entries, list):
        return False
    previous = "GENESIS"
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("previous_hash") != previous:
            return False
        without_hash = {key: value for key, value in entry.items() if key != "entry_hash"}
        try:
            actual_hash = sha256_record(without_hash)
        except (TypeError, ValueError, RecursionError, UnicodeError, OverflowError):
            return False
        entry_hash = entry.get("entry_hash")
        if not isinstance(entry_hash, str) or actual_hash != entry_hash:
            return False
        previous = entry_hash
    return True


def append_audit(entries: list[dict[str, Any]], action: str, actor: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    previous = entries[-1]["entry_hash"] if entries else "GENESIS"
    return entries + [make_audit_entry(action, actor, payload, previous)]


def investigate_case(case: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic agent workflow; every finding cites evidence IDs."""
    evidence = [item for item in evidence if isinstance(item, dict)]
    by_id = {
        str(item.get("evidence_id")): item
        for item in evidence
        if item.get("evidence_id") is not None
    }
    valid_ids = [
        str(item.get("evidence_id"))
        for item in evidence
        if item.get("evidence_id") is not None and verify_evidence(item)["valid"]
    ]
    findings = []

    def finding(fid: str, title: str, explanation: str, severity: str, refs: list[str], confidence: str) -> None:
        valid_refs = [ref for ref in refs if ref in valid_ids]
        findings.append({
            "finding_id": fid,
            "title": title,
            "explanation": explanation,
            "severity": severity,
            "evidence_ids": valid_refs,
            "evidence_available": bool(valid_refs),
            "confidence": confidence if valid_refs else "low",
            "state": "supported" if valid_refs else "unverified",
        })

    finding("F-001", "Unfamiliar successful login", "The synthetic identity event marks the source as novel. This is an investigation lead, not proof that the login was malicious.", "high", ["EV-001"], "medium")
    finding("F-002", "Unusual process ancestry", "A script interpreter is recorded with an email client as its parent. Correlate with endpoint telemetry before concluding execution intent.", "high", ["EV-002"], "medium")
    finding("F-003", "Network activity after suspicious process", "A test-domain connection follows the process event in the supplied timeline. The relationship is temporal correlation, not proof of causation.", "medium", ["EV-002", "EV-003"], "medium")
    finding("F-004", "Possible data staging", "A temporary archive is recorded. Its contents and transfer status are not established by this artifact alone.", "medium", ["EV-004"], "low")
    finding("F-005", "Follow-on identity session", "A second session appears after the unfamiliar login. Confirm session provenance and revoke only through an authorized response workflow.", "medium", ["EV-001", "EV-005"], "medium")

    timeline = []
    for item in evidence:
        checked = verify_evidence(item)
        record = item.get("record", {})
        record = record if isinstance(record, dict) else {}
        timeline.append({
            "timestamp": record.get("timestamp", ""),
            "event_id": item.get("evidence_id", ""),
            "summary": record.get("summary", "Unknown event"),
            "source": record.get("source", "unknown"),
            "integrity": checked["status"],
            "evidence_ids": [item.get("evidence_id", "")] if checked["valid"] else [],
        })
    timeline.sort(key=lambda event: _timeline_sort_key(event["timestamp"]))

    return {
        "case_id": case["case_id"],
        "orchestrator": {"status": "completed", "strategy": "Preserve → detect → correlate → verify → propose response"},
        "agents": [
            {"name": "Evidence Agent", "status": "completed", "summary": f"Reviewed {len(evidence)} evidence records; {len(valid_ids)} passed integrity verification."},
            {"name": "Detection Agent", "status": "completed", "summary": "Applied deterministic checks to synthetic identity, process, network and file events."},
            {"name": "Correlation Agent", "status": "completed", "summary": "Ordered events by source timestamps and linked temporally related activity."},
            {"name": "Verification Agent", "status": "completed", "summary": "Attached evidence IDs to findings and labelled inference and unknowns explicitly."},
        ],
        "findings": findings,
        "timeline": timeline,
        "gaps": [
            "No memory image or live process snapshot is included in this synthetic case.",
            "The archive contents and any successful exfiltration are not established.",
            "Network destination reputation is simulated and has not been queried externally.",
        ],
        "response_proposals": [
            {"action_id": "ACT-001", "title": "Isolate simulated endpoint WS-DEMO-04", "impact": "Would contain the demo host in the simulator; no real device is affected.", "risk": "high", "status": "pending"},
            {"action_id": "ACT-002", "title": "Revoke simulated account sessions", "impact": "Would invalidate demo sessions only; verify identity and business impact first.", "risk": "high", "status": "pending"},
            {"action_id": "ACT-003", "title": "Preserve endpoint and identity logs", "impact": "Retain additional artifacts before containment where feasible.", "risk": "low", "status": "pending"},
        ],
    }


def apply_simulated_response(proposals: list[dict[str, Any]], action_id: str, approved: bool, approver: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Enforce explicit approval and simulate, never execute real response actions."""
    if not isinstance(proposals, list):
        raise ValueError("Response proposals must be a list.")
    updated = deepcopy(proposals)
    target = next(
        (
            item for item in updated
            if isinstance(item, dict) and item.get("action_id") == action_id
        ),
        None,
    )
    if target is None:
        raise ValueError("Unknown response action.")
    # Require the actual boolean True. Truthy strings/integers from untrusted
    # callers must never cross the simulated approval gate.
    safe_approver = str(approver or "unknown")[:128]
    if approved is not True:
        target["status"] = "rejected"
        return updated, {
            "action_id": action_id,
            "status": "rejected",
            "approver": safe_approver,
            "simulated": True,
        }
    target["status"] = "approved_simulated"
    return updated, {
        "action_id": action_id,
        "status": "simulated_success",
        "approver": safe_approver,
        "simulated": True,
        "message": "No real host, account, network or process was changed.",
    }
