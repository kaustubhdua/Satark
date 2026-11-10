"""Versioned, metadata-only evidence reports for local File Guard scans."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re

_REPORT_SCHEMA = "satark.file-guard.evidence/v1"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def build_evidence_report(scan_result, *, scanned_at=None, snapshot=None):
    """Return a deterministic, hash-sealed report without retaining file bytes.

    The report digest detects accidental/tampered edits after export; it is not
    a digital signature and does not prove who collected the evidence.
    """
    record = scan_result.to_dict() if hasattr(scan_result, "to_dict") else dict(scan_result)
    digest = str(record.get("sha256", "")).lower()
    if not _SHA256.fullmatch(digest):
        raise ValueError("Evidence report requires a valid SHA-256 digest.")

    timestamp = scanned_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError("A non-empty ISO-8601 scan timestamp is required.")

    intel = record.get("intelligence_match") or {}
    report = {
        "report_schema": _REPORT_SCHEMA,
        "scanned_at": timestamp,
        "file": {
            "filename": str(record.get("filename", "unnamed"))[:255],
            "size_bytes": max(0, int(record.get("size_bytes", 0))),
            "sha256": digest,
            "detected_type": str(record.get("detected_type", "unknown"))[:100],
            "extension": str(record.get("extension", ""))[:32],
        },
        "assessment": {
            "verdict": str(record.get("verdict", "unknown"))[:80],
            "risk_level": str(record.get("risk_level", "unknown"))[:24],
            "score": max(0, min(100, int(record.get("score", 0)))),
            "interpretation": (
                "No known threat detected by enabled local checks; this is not proof of safety."
                if record.get("verdict") == "No known threat detected"
                else "Review the listed evidence. This result is limited to enabled local checks."
            ),
        },
        "evidence": {
            "signals": record.get("signals", [])[:100],
            "intelligence_match": {
                "matched": bool(intel),
                "label": str(intel.get("label", ""))[:24],
                "family": str(intel.get("family", ""))[:120],
                "source": str(intel.get("source", ""))[:160],
                "dataset_date": str(intel.get("dataset_date", ""))[:40],
                "file_type": str(intel.get("file_type", ""))[:40],
            },
            "yara": {
                "available": bool(record.get("yara_available", False)),
                "matches": [str(item)[:120] for item in record.get("yara_matches", [])[:32]],
                "error": str(record.get("yara_error") or "")[:80],
            },
            "agent_trace": record.get("agent_trace", [])[:32],
        },
        "processing": {
            "raw_bytes_processed_for_hash_and_signatures": True,
            "semantic_content_extracted": False,
            "ocr_performed": False,
            "file_executed": False,
            "network_used": False,
            "original_file_modified": False,
        },
        "snapshot": snapshot if isinstance(snapshot, dict) else {},
        "limitations": [
            "Exact SHA-256 matching only identifies byte-identical records in the imported historical snapshot.",
            "Unknown or unmatched files are not thereby proven safe.",
            "A report digest is not a digital signature or independent chain-of-custody proof.",
        ],
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    report["report_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return report


def verify_evidence_report(report):
    """Verify the report's canonical digest without trusting the embedded value."""
    if not isinstance(report, dict):
        return False
    supplied = report.get("report_sha256")
    if not isinstance(supplied, str) or not _SHA256.fullmatch(supplied):
        return False
    unsigned = {key: value for key, value in report.items() if key != "report_sha256"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return hashlib.compare_digest(supplied, expected) if hasattr(hashlib, "compare_digest") else supplied == expected
