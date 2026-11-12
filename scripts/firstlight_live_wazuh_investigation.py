"""Investigate real, allowlisted Wazuh Indexer alerts with FIRSTLIGHT.

This command reads only the configured Wazuh Indexer and never performs response
actions. It is deliberately separate from the fictional offline demo.
Run from the repository root:
    python scripts/firstlight_live_wazuh_investigation.py --since 2026-10-20T00:00:00Z --until 2026-10-20T23:59:59Z
Credentials and agent allowlists must be configured in the server environment.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firstlight_engine import investigate_case, seal_evidence, verify_evidence  # noqa: E402
from firstlight_wazuh import fetch_configured_alerts  # noqa: E402


def _iso_utc(value: str, field: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"{field} must be ISO-8601 with a timezone") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_live_report(
    alerts: list[dict[str, Any]],
    *,
    since: str,
    until: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Analyze actual normalized Wazuh records; never manufacture events."""
    if not isinstance(alerts, list):
        raise ValueError("Wazuh alerts must be a list")
    if not alerts:
        raise ValueError("Wazuh returned no alerts for the requested window; no incident report was created")
    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("source") != "wazuh" or not isinstance(alert.get("provenance"), dict):
            raise ValueError("Live investigation accepts only provenance-bearing Wazuh Indexer events")
        if alert["provenance"].get("provider") != "wazuh-indexer":
            raise ValueError("Alert provenance is not from the configured Wazuh Indexer")
    sealed = [seal_evidence(alert) for alert in alerts]
    integrity = [verify_evidence(item) for item in sealed]
    if not all(item["valid"] for item in integrity):
        raise ValueError("Evidence sealing verification failed; investigation aborted")
    source_fingerprint = hashlib.sha256(
        json.dumps(
            sorted(item["provenance"]["source_record_sha256"] for item in alerts),
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    case_id = "FL-WAZUH-" + source_fingerprint[:16].upper()
    created_at = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    case = {
        "case_id": case_id,
        "title": "Wazuh Indexer alert investigation",
        "scenario": "Investigation of real alerts fetched from the configured Wazuh Indexer. Findings are rule-backed leads, not proof of compromise.",
        "status": "investigating",
        "created_at": created_at,
        "source": "wazuh-indexer",
        "query_window": {"since": since, "until": until},
        "source_fingerprint_sha256": source_fingerprint,
        "source_alert_count": len(alerts),
    }
    investigation = investigate_case(case, sealed)
    return {
        "report_schema": "firstlight-live-wazuh-investigation/v1",
        "generated_at": created_at,
        "collection": {
            "mode": "live_configured_wazuh_indexer",
            "provider": "wazuh-indexer",
            "query_window": {"since": since, "until": until},
            "alerts_returned": len(alerts),
            "evidence_sealed": len(sealed),
            "evidence_integrity_valid": sum(item["valid"] for item in integrity),
            "source_fingerprint_sha256": source_fingerprint,
            "source_records": [
                {
                    "event_id": alert["event_id"],
                    "index": alert["provenance"]["index"],
                    "document_id": alert["provenance"]["document_id"],
                    "source_timestamp": alert["provenance"]["source_timestamp"],
                    "source_record_sha256": alert["provenance"]["source_record_sha256"],
                }
                for alert in alerts
            ],
        },
        "case": case,
        "investigation": investigation,
        "response": {
            "mode": "not_configured",
            "live_action_executed": False,
            "reason": "This investigation report does not create response proposals. Endpoint actions are available only through the separate guarded live-response workflow.",
            "proposals": [],
        },
        "limitations": [
            "Only alerts returned by the configured Wazuh Indexer and allowlisted agent IDs were examined.",
            "A Wazuh rule alert is an investigation signal, not independently verified proof of compromise.",
            "No live endpoint collection, threat-intelligence lookup, or response action was executed.",
            "The report is written to the selected local output path and is not an immutable external audit archive.",
        ],
    }


def run_live_investigation(
    *,
    since: str,
    until: str,
    limit: int = 100,
    fetcher: Callable[..., list[dict[str, Any]]] = fetch_configured_alerts,
) -> dict[str, Any]:
    start = _iso_utc(since, "since")
    end = _iso_utc(until, "until")
    if start > end:
        raise ValueError("--since must be earlier than or equal to --until")
    alerts = fetcher(limit=limit, since=start, until=end, order="asc")
    return build_live_report(alerts, since=start, until=end)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", required=True, help="Inclusive ISO-8601 start timestamp with timezone")
    parser.add_argument("--until", required=True, help="Inclusive ISO-8601 end timestamp with timezone")
    parser.add_argument("--limit", type=int, default=100, help="Maximum alerts to fetch (1–500; default 100)")
    parser.add_argument("--output", type=Path, help="Write JSON report to this path; default stdout")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 500:
        parser.error("--limit must be between 1 and 500")
    try:
        report = run_live_investigation(since=args.since, until=args.until, limit=args.limit)
        encoded = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
            print(json.dumps({
                "status": "completed",
                "report_path": str(args.output),
                "case_id": report["case"]["case_id"],
                "alerts": report["collection"]["alerts_returned"],
                "findings": len(report["investigation"]["findings"]),
                "response_mode": report["response"]["mode"],
            }, sort_keys=True))
        else:
            sys.stdout.write(encoded)
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"FIRSTLIGHT live Wazuh investigation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
