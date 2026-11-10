"""Evaluate SATARK against a locally held, independently labelled file corpus.

The evaluator reads raw bytes only through the static scanner. It never extracts
document text, executes samples, unpacks archives or accesses the network.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from file_guard.engine import scan_path, MAX_FILE_BYTES
from file_guard.intelligence import ThreatIntelligenceStore

ALERT_VERDICTS = {"Known threat", "Signature match", "Suspicious", "Needs review"}
LABELS = {"benign", "malicious"}
MAX_EVALUATION_FILES = 100_000


def safe_sample_path(root: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute() or "\\" in relative or "\x00" in relative:
        raise ValueError("Sample path must be a safe relative path.")
    base = root.resolve()
    candidate = root / relative
    cursor = root
    for part in Path(relative).parts:
        if part in ("", ".", "..") or (cursor / part).is_symlink():
            raise ValueError("Symbolic-link and traversal paths are not accepted.")
        cursor = cursor / part
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(base) or not resolved.is_file():
        raise ValueError("Sample path must resolve to a regular file inside the sample root.")
    return resolved


def calculate_metrics(rows: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    for row in rows:
        actual = row["actual"] == "malicious"
        predicted = bool(row["predicted_malicious"])
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif not actual and not predicted:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn

    def ratio(numerator: int, denominator: int):
        return numerator / denominator if denominator else None

    return {
        "evaluated": total,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, fn + tp),
        "accuracy": ratio(tp + tn, total),
    }


def evaluate(sample_root: Path, labels_csv: Path, intelligence: ThreatIntelligenceStore,
             *, yara_rules_path: Path | None = None, max_file_bytes: int = MAX_FILE_BYTES) -> dict:
    root = sample_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Sample root must be a directory.")
    if max_file_bytes < 1 or max_file_bytes > MAX_FILE_BYTES:
        raise ValueError("Evaluation file size limit must be between 1 byte and the scanner maximum.")

    rows = []
    errors = []
    with labels_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = {str(item).strip().lower() for item in (reader.fieldnames or [])}
        if not {"path", "label"}.issubset(fields):
            raise ValueError("Ground-truth CSV must include path and label columns.")
        for index, raw in enumerate(reader, 1):
            if index > MAX_EVALUATION_FILES:
                raise ValueError("Evaluation corpus exceeds the 100,000-file limit.")
            row = {str(key).strip().lower(): (value or "").strip() for key, value in raw.items() if key}
            label = row.get("label", "").lower()
            if label not in LABELS:
                errors.append({"row": index, "path": row.get("path", ""), "error": "INVALID_LABEL"})
                continue
            try:
                path = safe_sample_path(root, row.get("path", ""))
                result = scan_path(
                    path,
                    intelligence=intelligence,
                    yara_rules_path=str(yara_rules_path) if yara_rules_path else None,
                    max_bytes=max_file_bytes,
                )
            except (OSError, ValueError) as exc:
                errors.append({"row": index, "path": row.get("path", ""), "error": type(exc).__name__})
                continue

            signal_codes = [item.get("code", "") for item in result.signals]
            rows.append({
                "path": row["path"],
                "actual": label,
                "predicted_malicious": result.verdict in ALERT_VERDICTS,
                "verdict": result.verdict,
                "risk_level": result.risk_level,
                "sha256": result.sha256,
                "detected_type": result.detected_type,
                "signal_codes": signal_codes,
                "known_hash_label": (result.intelligence_match or {}).get("label", ""),
                "yara_matches": result.yara_matches,
            })

    metrics = calculate_metrics(rows)
    by_type = {}
    for file_type in sorted({row["detected_type"] for row in rows}):
        by_type[file_type] = calculate_metrics([row for row in rows if row["detected_type"] == file_type])

    return {
        "report_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scanner": "SATARK File Guard",
        "sample_root": str(root),
        "ground_truth_csv": labels_csv.name,
        "yara_enabled": bool(yara_rules_path),
        "metrics": metrics,
        "by_detected_type": by_type,
        "errors": errors,
        "results": rows,
        "limitations": [
            "Metrics apply only to this supplied labelled corpus and scanner configuration.",
            "Synthetic fixtures are regression tests, not real-world accuracy evidence.",
            "An alert verdict means triage/review is required; it is not proof of malware.",
            "A no-alert result is not proof of safety.",
            "The evaluator does not extract document text, execute samples, unpack archives or use a network.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, required=True, help="Directory containing labelled test files")
    parser.add_argument("--labels", type=Path, required=True, help="CSV with path,label columns")
    parser.add_argument("--database", type=Path, required=True, help="Local SQLite intelligence database path")
    parser.add_argument("--intelligence-csv", type=Path, help="Optional historical training snapshot CSV")
    parser.add_argument("--source-id", default="local-evaluation-snapshot", help="Provenance label for the imported training snapshot")
    parser.add_argument("--yara-rules", type=Path, help="Optional local YARA rules file")
    parser.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    args = parser.parse_args()

    store = ThreatIntelligenceStore(args.database)
    if args.intelligence_csv:
        with args.intelligence_csv.open("r", encoding="utf-8-sig", newline="") as source:
            imported = store.import_csv(source, args.source_id)
        print("Imported intelligence rows:", imported)

    report = evaluate(args.samples, args.labels, store,
                      yara_rules_path=args.yara_rules, max_file_bytes=args.max_file_bytes)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    with args.output_csv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=[
            "path", "actual", "predicted_malicious", "verdict", "risk_level",
            "sha256", "detected_type", "signal_codes", "known_hash_label", "yara_matches",
        ])
        writer.writeheader()
        for row in report["results"]:
            writer.writerow({**row,
                "signal_codes": ";".join(row["signal_codes"]),
                "yara_matches": ";".join(row["yara_matches"]),
            })
    print(json.dumps({
        "metrics": report["metrics"],
        "by_detected_type": report["by_detected_type"],
        "unscanned_errors": len(report["errors"]),
        "json_report": str(args.output_json),
        "csv_report": str(args.output_csv),
    }, indent=2))


if __name__ == "__main__":
    main()
