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

from firstlight_rules import RULE_VERSION, rule_metadata


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
    """Seal one well-formed event with a stable identity."""
    if not isinstance(event, dict):
        raise ValueError("Evidence event must be an object.")
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError("Evidence event must include a non-empty event_id.")
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
    # Bind the envelope ID to the hashed record so references cannot be swapped.
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


def prioritize_evidence(evidence: list[dict[str, Any]], now: datetime | None = None) -> list[dict[str, Any]]:
    """Rank evidence for triage using transparent, deterministic heuristics.

    Scores are workflow hints, not calibrated risk probabilities. An integrity
    mismatch raises review urgency but never makes the record trustworthy.
    """
    if not isinstance(evidence, list):
        raise ValueError("Evidence must be a list.")
    current = now or datetime.now(timezone.utc)
    if not isinstance(current, datetime):
        raise ValueError("now must be a datetime when supplied.")
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)

    volatility_terms = {
        "memory": 35, "process": 30, "connection": 28, "session": 26,
        "authentication": 24, "login": 24, "network": 22, "identity": 20,
        "registry": 15, "file": 12, "log": 12,
    }
    relevance_terms = (
        "suspicious", "unusual", "novel", "powershell", "mfa",
        "forwarding", "archive", "lookalike", "credential", "failed",
        "unexpected", "malicious",
    )
    priorities = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        record = item.get("record", {})
        if not isinstance(record, dict):
            record = {}
        evidence_id = str(item.get("evidence_id", "unknown"))
        kind = str(record.get("kind", "")).lower()
        source = str(record.get("source", "")).lower()
        summary = str(record.get("summary", "")).lower()
        details = record.get("details", {}) if isinstance(record.get("details"), dict) else {}
        searchable = " ".join((kind, source, summary, str(details.get("rule_id", "")), " ".join(str(group) for group in details.get("rule_groups", []) if isinstance(group, (str, int)))))
        integrity = verify_evidence(item)
        reasons = []

        volatility_matches = [(term, points) for term, points in volatility_terms.items()
                              if term in kind or term in source]
        volatility_score = max((points for _, points in volatility_matches), default=8)
        reasons.append(
            f"Volatility: {max((term for term, points in volatility_matches if points == volatility_score), default='general artifact')} "
            f"(+{volatility_score})"
        )

        relevance_score = 20 if any(term in searchable for term in relevance_terms) else 8
        source_level = details.get("rule_level")
        if details.get("provider") == "wazuh-indexer" and isinstance(source_level, (int, str)) and not isinstance(source_level, bool):
            try:
                parsed_level = int(source_level)
            except (TypeError, ValueError):
                parsed_level = -1
            if 0 <= parsed_level <= 16:
                relevance_score = max(relevance_score, 25 if parsed_level >= 12 else 20 if parsed_level >= 10 else 15 if parsed_level >= 7 else 8)
                reasons.append(f"Wazuh source rule level {parsed_level} (vendor severity context, not a probability)")
        reasons.append(f"Investigation relevance heuristic (+{relevance_score})")

        if integrity["valid"]:
            integrity_score = 10
            reasons.append("Stored digest matches (+10)")
            next_step = "Preserve the source snapshot and corroborate with independent logs."
        else:
            integrity_score = 25
            reasons.append("Integrity mismatch or malformed baseline (+25 review urgency)")
            next_step = "Quarantine from trusted conclusions; compare with a protected baseline and re-collect if possible."

        recency_score = 0
        timestamp = record.get("timestamp")
        try:
            observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            age_minutes = (current - observed.astimezone(timezone.utc)).total_seconds() / 60
            if 0 <= age_minutes <= 15:
                recency_score = 15
            elif 0 <= age_minutes <= 60:
                recency_score = 12
            elif 0 <= age_minutes <= 360:
                recency_score = 8
            elif 0 <= age_minutes <= 1440:
                recency_score = 4
            if recency_score:
                reasons.append(f"Recent source timestamp (+{recency_score})")
        except (TypeError, ValueError, OverflowError):
            pass

        score = min(100, volatility_score + relevance_score + integrity_score + recency_score)
        level = "critical" if score >= 75 else "high" if score >= 55 else "medium" if score >= 35 else "low"
        priorities.append({
            "evidence_id": evidence_id,
            "priority": level,
            "priority_score": score,
            "integrity": integrity["status"],
            "reasons": reasons,
            "recommended_next_step": next_step,
        })

    return sorted(priorities, key=lambda row: (-row["priority_score"], row["evidence_id"]))


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
    """Append only to a valid audit chain; never silently extend corrupted history."""
    if not isinstance(entries, list):
        raise ValueError("Audit entries must be a list.")
    if not verify_audit_chain(entries):
        raise ValueError("Cannot append to an invalid audit chain.")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("Audit action must be a non-empty string.")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("Audit actor must be a non-empty string.")
    if not isinstance(payload, dict):
        raise ValueError("Audit payload must be an object.")
    previous = entries[-1]["entry_hash"] if entries else "GENESIS"
    try:
        entry = make_audit_entry(action, actor, payload, previous)
    except (TypeError, ValueError, RecursionError, UnicodeError, OverflowError) as exc:
        raise ValueError("Audit payload cannot be canonically serialized.") from exc
    return entries + [entry]


def investigate_case(case: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic agent workflow; every finding cites evidence IDs."""
    if not isinstance(case, dict):
        raise ValueError("Case must be an object.")
    case_id = case.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("Case must include a non-empty case_id.")
    if not isinstance(evidence, list):
        raise ValueError("Evidence must be a list.")
    evidence = [item for item in evidence if isinstance(item, dict)]
    valid_ids = [
        str(item.get("evidence_id"))
        for item in evidence
        if item.get("evidence_id") is not None and verify_evidence(item)["valid"]
    ]
    valid_id_set = set(valid_ids)
    findings = []

    def finding(fid: str, title: str, explanation: str, severity: str, refs: list[str], confidence: str) -> None:
        valid_refs = list(dict.fromkeys(ref for ref in refs if ref in valid_id_set))
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

    # Derive findings from the supplied records rather than assuming demo IDs.
    # These are explainable triage heuristics, not proof of malicious activity.
    valid_records = {
        str(item.get("evidence_id")): item.get("record", {})
        for item in evidence
        if item.get("evidence_id") is not None and verify_evidence(item)["valid"]
        and isinstance(item.get("record"), dict)
    }
    next_finding = 1

    def add_rule_finding(title: str, explanation: str, severity: str, refs: list[str], confidence: str) -> None:
        nonlocal next_finding
        finding(f"F-{next_finding:03d}", title, explanation, severity, refs, confidence)
        findings[-1].update(rule_metadata(title))
        next_finding += 1

    records = [(eid, record) for eid, record in valid_records.items()]
    for evidence_id, record in records:
        kind = str(record.get("kind", "")).lower()
        source = str(record.get("source", "")).lower()
        summary = str(record.get("summary", "")).lower()
        details = record.get("details", {})
        details = details if isinstance(details, dict) else {}
        groups = details.get("rule_groups", [])
        groups_text = " ".join(str(group).lower() for group in groups if isinstance(group, (str, int))) if isinstance(groups, list) else ""
        searchable = " ".join((kind, source, summary, str(details.get("rule", "")).lower(), str(details.get("rule_id", "")).lower(), groups_text))
        success = str(details.get("result", "")).lower() in {"success", "successful", "succeeded"}

        raw_wazuh_level = details.get("rule_level")
        if details.get("provider") == "wazuh-indexer" and isinstance(raw_wazuh_level, (int, str)) and not isinstance(raw_wazuh_level, bool):
            try:
                wazuh_level = int(raw_wazuh_level)
            except (TypeError, ValueError):
                wazuh_level = -1
            if 7 <= wazuh_level <= 16:
                severity = "critical" if wazuh_level >= 12 else "high" if wazuh_level >= 10 else "medium"
                add_rule_finding(
                    "Wazuh source detection alert",
                    f"The Wazuh Indexer record carries source rule level {wazuh_level}. This preserves the source detector's severity context; it is not an independently calibrated probability or proof of compromise. Corroborate the underlying event and host context.",
                    severity, [evidence_id], "medium" if wazuh_level >= 10 else "low",
                )

        if (kind in {"authentication", "login", "sign_in"} or "login" in searchable or "sign-in" in searchable) and (
            details.get("novel_source") is True
            or any(term in searchable for term in ("new source", "new browser", "new device", "new location", "unfamiliar"))
        ) and (success or "successful" in searchable):
            add_rule_finding(
                "Unfamiliar successful login",
                "The source record describes a successful login in a new or unfamiliar context. This is an investigation lead, not proof of account compromise.",
                "high", [evidence_id], "medium",
            )

        if any(term in searchable for term in ("forwarding rule", "mailbox rule", "inbox forwarding", "mail forwarding")):
            add_rule_finding(
                "Mailbox forwarding or rule change",
                "The supplied record describes a mailbox forwarding or rule change. Verify the rule owner, destination, and authorization independently.",
                "high", [evidence_id], "medium",
            )

        if any(term in searchable for term in ("mfa", "multi-factor", "authentication settings", "authentication method changed")):
            add_rule_finding(
                "Authentication setting changed",
                "The supplied record describes an authentication-setting change. Verify whether it was authorized and whether recovery methods were affected.",
                "high", [evidence_id], "medium",
            )

        if kind in {"message", "email", "mail"} and any(term in searchable for term in ("lookalike", "urgent", "password", "otp", "credential")):
            add_rule_finding(
                "Social-engineering indicators",
                "The message summary includes urgency, lookalike-domain, or credential-request language. Verify sender and destination independently; wording alone is not proof of phishing.",
                "medium", [evidence_id], "low",
            )

        if kind == "process" and any(term in searchable for term in ("suspicious attachment", "suspicious process", "attachment path")):
            add_rule_finding(
                "Potentially suspicious endpoint activity",
                "The supplied summary describes a potentially suspicious process or attachment path. This workflow does not inspect the actual process or file.",
                "medium", [evidence_id], "low",
            )

        parent = str(details.get("parent", "")).lower()
        process = str(details.get("process", "")).lower()
        unusual_parent = any(term in parent for term in ("outlook", "winword", "excel", "browser", "email"))
        script_process = any(term in process for term in ("powershell", "wscript", "cscript", "cmd.exe", "bash", "python"))
        if kind == "process" and (details.get("rule") == "unusual_parent_child" or (unusual_parent and script_process)):
            add_rule_finding(
                "Unusual process ancestry",
                "The source records a script-capable process with a potentially unusual parent or rule match. Correlate with endpoint telemetry before inferring intent.",
                "high", [evidence_id], "medium",
            )

        destination = str(details.get("destination", "")).lower()
        if kind in {"connection", "network"} and (
            "suspicious" in searchable or details.get("disposition") == "suspicious"
            or destination.endswith(".invalid")
        ):
            related = [evidence_id]
            host = details.get("host")
            current_time = _timeline_sort_key(record.get("timestamp"))
            prior_processes = [
                (eid, other) for eid, other in records
                if eid != evidence_id
                and str(other.get("kind", "")).lower() == "process"
                and isinstance(other.get("details"), dict)
                and (not host or other["details"].get("host") == host)
                and _timeline_sort_key(other.get("timestamp")) <= current_time
            ]
            prior_processes.sort(key=lambda pair: _timeline_sort_key(pair[1].get("timestamp")))
            if prior_processes:
                related.insert(0, prior_processes[-1][0])
            add_rule_finding(
                "Potentially suspicious network activity",
                "The record contains a suspicious-destination signal. Any link to earlier process activity is temporal correlation, not proof of causation; verify destination context independently.",
                "medium", related, "low" if len(related) == 1 else "medium",
            )

        path = str(details.get("path", "")).lower()
        if kind in {"file", "filesystem"} and (
            any(term in path for term in (".zip", ".7z", ".rar", ".tar", ".gz"))
            or any(term in searchable for term in ("archive", "staging", "staged"))
            or "temp" in path
        ):
            add_rule_finding(
                "Possible data staging",
                "A file or archive-like artifact may indicate staging. The artifact alone does not establish its contents, purpose, or transfer.",
                "medium", [evidence_id], "low",
            )

        if kind == "session" or "session" in searchable:
            account = details.get("account")
            current_time = _timeline_sort_key(record.get("timestamp"))
            prior_auth = [
                (eid, other) for eid, other in records
                if eid != evidence_id
                and str(other.get("kind", "")).lower() in {"authentication", "login"}
                and isinstance(other.get("details"), dict)
                and (not account or other["details"].get("account") == account)
                and _timeline_sort_key(other.get("timestamp")) <= current_time
            ]
            prior_auth.sort(key=lambda pair: _timeline_sort_key(pair[1].get("timestamp")))
            if prior_auth:
                add_rule_finding(
                    "Follow-on identity session",
                    "A session record follows an authentication event for the same account or an unspecified account. Confirm session provenance before taking action.",
                    "medium", [prior_auth[-1][0], evidence_id], "medium",
                )

    if not findings:
        # Make the absence of a matching heuristic explicit rather than
        # implying the case is safe or inventing a positive finding.
        findings.append({
            "finding_id": "F-001",
            "title": "No rule matched — analyst review required",
            "explanation": "The supplied evidence did not match the current deterministic triage rules. This is not a safety clearance; review the source records and add case-specific checks as needed.",
            "severity": "info",
            "evidence_ids": [],
            "evidence_available": False,
            "confidence": "low",
            "state": "unverified",
            "rule_id": "FL-GENERIC-000",
            "rule_version": RULE_VERSION,
            "rule_source": "FIRSTLIGHT",
            "attack_techniques": [],
            "logic_type": "no_rule_match",
            "rule_limitations": ["No detection rule matched; this is not a clearance that the system or case is safe."],
        })

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

    # Keep limitations tied to the supplied case, not to the demo scenario.
    valid_kinds = {str(record.get("kind", "")).lower() for _, record in records}
    gaps = ["Only supplied artifacts were reviewed; no live endpoint or identity collection was performed."]
    if not ({"memory", "process_snapshot"} & valid_kinds):
        gaps.append("No memory image or live process snapshot is included in the supplied evidence.")
    has_archive = any(
        str(record.get("kind", "")).lower() in {"file", "filesystem"}
        and any(term in str(record.get("summary", "")).lower() for term in ("archive", "staging", "staged"))
        for _, record in records
    )
    if has_archive:
        gaps.append("Archive contents and any successful transfer are not established by these records.")
    if any(str(record.get("kind", "")).lower() in {"connection", "network"} for _, record in records):
        gaps.append("Network destination reputation was not independently verified by this workflow.")

    evidence_priorities = prioritize_evidence(evidence)
    response_proposals = [
        {"action_id": "ACT-001", "title": f"Preserve evidence for case {case_id}", "impact": "Would mark evidence-preservation as approved in the simulator only; no files are changed.", "risk": "low", "status": "pending"},
        {"action_id": "ACT-002", "title": "Review and contain affected assets", "impact": "Analyst must identify and confirm an exact target before any real response; this prototype only records a simulated decision.", "risk": "high", "status": "pending"},
        {"action_id": "ACT-003", "title": "Review identity sessions and access", "impact": "Analyst must verify the account and business impact; this prototype does not revoke real sessions.", "risk": "high", "status": "pending"},
    ]
    matched_findings = [
        item for item in findings
        if item.get("title") != "No rule matched — analyst review required"
    ]
    referenced_ids = sorted({
        evidence_id
        for item in findings
        for evidence_id in item.get("evidence_ids", [])
    })
    agent_trace = [
        {
            "agent_id": "evidence_integrity",
            "name": "Evidence Integrity Agent",
            "mode": "deterministic",
            "status": "completed",
            "inputs": len(evidence),
            "outputs": len(valid_ids),
            "evidence_ids": list(valid_ids),
            "summary": f"Checked {len(evidence)} supplied records; {len(valid_ids)} matched their sealed hash and identity.",
        },
        {
            "agent_id": "evidence_triage",
            "name": "Evidence Triage Agent",
            "mode": "deterministic",
            "status": "completed",
            "inputs": len(evidence),
            "outputs": len(evidence_priorities),
            "evidence_ids": [item["evidence_id"] for item in evidence_priorities],
            "summary": "Ranked supplied records using transparent volatility, relevance, recency and integrity heuristics; scores are not probabilities.",
        },
        {
            "agent_id": "detection_correlation",
            "name": "Detection & Correlation Agent",
            "mode": "deterministic",
            "status": "completed",
            "inputs": len(valid_records),
            "outputs": len(matched_findings),
            "evidence_ids": referenced_ids,
            "summary": f"Produced {len(matched_findings)} rule-backed investigation lead(s) from integrity-verified records; temporal links do not prove causation.",
        },
        {
            "agent_id": "timeline_reconstruction",
            "name": "Timeline Reconstruction Agent",
            "mode": "deterministic",
            "status": "completed",
            "inputs": len(evidence),
            "outputs": len(timeline),
            "evidence_ids": [item["event_id"] for item in timeline if item.get("evidence_ids")],
            "summary": f"Ordered {len(timeline)} supplied events by source timestamp; records with invalid integrity remain visible but untrusted.",
        },
        {
            "agent_id": "verification",
            "name": "Verification & Gap Agent",
            "mode": "deterministic",
            "status": "completed",
            "inputs": len(findings),
            "outputs": sum(bool(item.get("evidence_ids")) for item in findings),
            "evidence_ids": referenced_ids,
            "summary": f"Checked evidence references and recorded {len(gaps)} explicit evidence gap(s); unsupported claims remain unverified.",
        },
        {
            "agent_id": "response_planning",
            "name": "Response Planning Agent",
            "mode": "deterministic",
            "status": "completed",
            "inputs": len(findings),
            "outputs": len(response_proposals),
            "evidence_ids": referenced_ids,
            "summary": "Prepared reviewable proposals only. Approval records a simulation and never executes a real response action.",
        },
    ]
    return {
        "schema_version": "1.1",
        "case_id": case_id,
        "orchestrator": {
            "status": "completed",
            "mode": "bounded_deterministic",
            "strategy": "Preserve → triage → detect/correlate → reconstruct → verify → propose response",
            "agent_count": len(agent_trace),
            "model_agents_enabled": False,
            "note": "Named stages are deterministic workflow agents in this prototype, not independent LLM agents.",
        },
        "agents": agent_trace,
        "agent_trace": agent_trace,
        "findings": findings,
        "evidence_priorities": evidence_priorities,
        "timeline": timeline,
        "gaps": gaps,
        "response_proposals": response_proposals,
    }


def apply_simulated_response(proposals: list[dict[str, Any]], action_id: str, approved: bool, approver: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Enforce explicit approval and simulate, never execute real response actions."""
    if not isinstance(proposals, list):
        raise ValueError("Response proposals must be a list.")
    updated = deepcopy(proposals)
    target = next(
        (item for item in updated if isinstance(item, dict) and item.get("action_id") == action_id),
        None,
    )
    if target is None:
        raise ValueError("Unknown response action.")
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
