#!/usr/bin/env python3
"""Calculate transparent file-guard metrics from a human-labelled evaluation CSV.

Input columns: expected,predicted. Values are benign, malicious, or unknown
(predicted only). Unknown predictions count as abstentions, not clean files.
No sample binaries are read by this evaluator.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

LABELS = {"benign", "malicious"}


def evaluate_rows(rows):
    tp = fp = tn = fn = abstained = 0
    total = 0
    for line_number, row in enumerate(rows, 2):
        expected = str(row.get("expected", "")).strip().lower()
        predicted = str(row.get("predicted", "")).strip().lower()
        if expected not in LABELS or predicted not in LABELS | {"unknown"}:
            raise ValueError(f"Invalid expected/predicted label at CSV row {line_number}.")
        total += 1
        if predicted == "unknown":
            abstained += 1
        elif expected == "malicious" and predicted == "malicious":
            tp += 1
        elif expected == "benign" and predicted == "malicious":
            fp += 1
        elif expected == "benign" and predicted == "benign":
            tn += 1
        else:
            fn += 1

    positives = tp + fn + sum(1 for _ in ())  # abstentions are accounted separately below
    expected_malicious = tp + fn + sum(1 for _ in ())
    # Count expected class totals directly so abstentions remain in the denominator.
    # The loop above intentionally does not infer a label for unknown predictions.
    # Re-read is avoided by tracking class totals in the second pass below.
    return _metrics(tp, fp, tn, fn, abstained, total)


def _metrics(tp, fp, tn, fn, abstained, total):
    # False-negative rate is conservative: abstained cases are not silently treated benign.
    # The caller supplies expected-positive abstentions separately in the enriched path.
    classified = total - abstained
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    accuracy = (tp + tn) / classified if classified else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    return {
        "samples": total,
        "classified": classified,
        "abstained": abstained,
        "coverage": classified / total if total else 0.0,
        "confusion_matrix": {"true_positive": tp, "false_positive": fp,
                             "true_negative": tn, "false_negative": fn},
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy_on_classified": accuracy,
        "f1": f1,
        "note": "Metrics describe only the supplied labelled corpus, not real-world protection.",
    }


def evaluate_csv(path):
    with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = {name.strip().lower() for name in (reader.fieldnames or [])}
        if not {"expected", "predicted"}.issubset(fields):
            raise ValueError("CSV must include expected and predicted columns.")
        rows = []
        for line_number, raw in enumerate(reader, 2):
            row = {str(k).strip().lower(): (v or "").strip() for k, v in raw.items() if k}
            expected, predicted = row.get("expected", "").lower(), row.get("predicted", "").lower()
            if expected not in LABELS or predicted not in LABELS | {"unknown"}:
                raise ValueError(f"Invalid expected/predicted label at CSV row {line_number}.")
            rows.append((expected, predicted))
    tp = fp = tn = fn = abstained = abstained_malicious = total = 0
    for expected, predicted in rows:
        total += 1
        if predicted == "unknown":
            abstained += 1
            abstained_malicious += expected == "malicious"
        elif expected == "malicious" and predicted == "malicious":
            tp += 1
        elif expected == "benign" and predicted == "malicious":
            fp += 1
        elif expected == "benign" and predicted == "benign":
            tn += 1
        else:
            fn += 1
    result = _metrics(tp, fp, tn, fn, abstained, total)
    expected_positive = tp + fn + abstained_malicious
    result["recall_conservative"] = tp / expected_positive if expected_positive else None
    result["false_negative_rate_conservative"] = (
        (fn + abstained_malicious) / expected_positive if expected_positive else None
    )
    result["abstained_malicious"] = abstained_malicious
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="Human-labelled evaluation CSV")
    parser.add_argument("--output", type=Path, help="Optional JSON report destination")
    args = parser.parse_args()
    report = evaluate_csv(args.csv)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
