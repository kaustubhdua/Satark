"""Reproducible, offline Track 1 demonstration for FIRSTLIGHT.

Run from the repository root:
    python scripts/firstlight_track1_demo.py
    python scripts/firstlight_track1_demo.py --output artifacts/firstlight-demo-report.json

This script is a deterministic test fixture, not a production workflow.
All inputs are fictional. It performs no response action and must never be
used as operational evidence or loaded into a deployed workspace.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

# Make direct execution from scripts/ work without requiring an installed package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firstlight_engine import (  # noqa: E402
    append_audit,
    investigate_case,
    seal_evidence,
    verify_audit_chain,
    verify_evidence,
)
from firstlight_ingest import detect_event_patterns, ingest_event_artifact  # noqa: E402


def synthetic_events() -> list[dict[str, Any]]:
    """Return a deterministic fictional account/endpoint activity sequence."""
    return [
        {
            "event_id": "DEMO-AUTH-001",
            "timestamp": "2026-10-20T09:00:00Z",
            "source": "identity",
            "kind": "authentication",
            "summary": "Successful login from an unfamiliar source",
            "details": {"account": "analyst@example.test", "result": "success", "novel_source": True, "source_ip": "198.51.100.24"},
        },
        {
            "event_id": "DEMO-ENDPOINT-001",
            "timestamp": "2026-10-20T09:03:00Z",
            "source": "endpoint",
            "kind": "process",
            "summary": "Script interpreter launched by mail client",
            "details": {"host": "WS-DEMO-01", "process": "powershell.exe", "parent": "outlook.exe"},
        },
        {
            "event_id": "DEMO-NETWORK-001",
            "timestamp": "2026-10-20T09:05:00Z",
            "source": "network",
            "kind": "connection",
            "summary": "Connection to an untrusted training indicator",
            "details": {"host": "WS-DEMO-01", "destination": "training-indicator.invalid", "port": 443},
        },
        {
            "event_id": "DEMO-FILE-001",
            "timestamp": "2026-10-20T09:07:00Z",
            "source": "filesystem",
            "kind": "file",
            "summary": "Archive staged in a temporary directory",
            "details": {"host": "WS-DEMO-01", "path": "C:/Temp/training-archive.zip"},
        },
        {
            "event_id": "DEMO-SESSION-001",
            "timestamp": "2026-10-20T09:08:00Z",
            "source": "identity",
            "kind": "session",
            "summary": "A follow-on identity session was issued",
            "details": {"account": "analyst@example.test", "session": "SESSION-TRAINING-01"},
        },
    ]


def run_demo() -> dict[str, Any]:
    """Run ingestion → detection → evidence sealing → investigation → approval."""
    payload = json.dumps({"events": synthetic_events()}, sort_keys=True).encode("utf-8")
    ingested = ingest_event_artifact(payload, "firstlight-track1-demo.json")
    detections = detect_event_patterns(ingested["events"])
    evidence = [seal_evidence(event) for event in ingested["events"]]
    case = {
        "case_id": "FL-TRACK1-DEMO-001",
        "title": "Synthetic account and endpoint investigation",
        "scenario": "Fictional training data; no live collection was performed.",
        "status": "investigating",
    }
    investigation = investigate_case(case, evidence)

    audit: list[dict[str, Any]] = []
    audit = append_audit(audit, "artifact_ingested", "demo-runner", {
        "case_id": case["case_id"],
        "artifact_sha256": ingested["artifact_sha256"],
        "record_count": ingested["record_count"],
    })
    audit = append_audit(audit, "investigation_completed", "demo-runner", {
        "case_id": case["case_id"],
        "finding_count": len(investigation["findings"]),
        "verified_evidence_count": sum(verify_evidence(item)["valid"] for item in evidence),
    })
    report = {
        "report_schema": "firstlight-track1-demo/v1",
        "case": case,
        "input": {
            "filename": ingested["filename"],
            "sha256": ingested["artifact_sha256"],
            "records_ingested": ingested["record_count"],
            "records_rejected": ingested["rejected_count"],
            "warnings": ingested["warnings"],
        },
        "detection": {
            "mode": "deterministic",
            "finding_count": len(detections),
            "findings": detections,
        },
        "investigation": investigation,
        "evidence_integrity": {
            "checked": len(evidence),
            "valid": sum(verify_evidence(item)["valid"] for item in evidence),
            "invalid_ids": [item["evidence_id"] for item in evidence if not verify_evidence(item)["valid"]],
        },
        "audit": {
            "entries": audit,
            "valid_hash_chain": verify_audit_chain(audit),
        },
        "limitations": [
            "All events and indicators are fictional.",
            "No live endpoint, identity, network, or SIEM data was collected.",
            "Deterministic matches are investigation leads, not proof of compromise.",
            "No response action changed a real system.",
        ],
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional path to write the JSON report.")
    args = parser.parse_args()
    report = run_demo()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(json.dumps({
        "case_id": report["case"]["case_id"],
        "records_ingested": report["input"]["records_ingested"],
        "detections": report["detection"]["finding_count"],
        "investigation_findings": len(report["investigation"]["findings"]),
        "evidence_integrity": report["evidence_integrity"],
        "audit_chain_valid": report["audit"]["valid_hash_chain"],
        "report_path": str(args.output) if args.output else None,
        "fixture_only": True,
    }, indent=2))
    if args.output:
        print(f"Full report written to {args.output}")
    return 0 if report["audit"]["valid_hash_chain"] and report["evidence_integrity"]["valid"] == report["evidence_integrity"]["checked"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
