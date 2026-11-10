
"""
from __future__ import annotations

import argparse
import csv


def _metrics(tp, fp, tn, fn, abstained, total):
    classified = total - abstained
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    accuracy = (tp + tn) / classified if classified else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    return {

        "f1_classified": f1,
        "note": "Metrics describe only the supplied labelled corpus, not real-world protection.",
    }



    with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = {str(name).strip().lower() for name in (reader.fieldnames or [])}
        if not {"expected", "predicted"}.issubset(fields):
            raise ValueError("CSV must include expected and predicted columns.")
        rows = []
        for line_number, raw in enumerate(reader, 2):
            row = {str(k).strip().lower(): (v or "").strip().lower()
                   for k, v in raw.items() if k}
            expected, predicted = row.get("expected", ""), row.get("predicted", "")
            if expected not in LABELS or predicted not in LABELS | {"unknown"}:
                raise ValueError(f"Invalid expected/predicted label at CSV row {line_number}.")
            rows.append((expected, predicted))

    tp = fp = tn = fn = abstained = abstained_malicious = total = 0
    for expected, predicted in rows:
        total += 1
        if predicted == "unknown":
            abstained += 1
            if expected == "malicious":
                abstained_malicious += 1
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
    expected_negative = tn + fp + (abstained - abstained_malicious)
    result["recall_conservative"] = tp / expected_positive if expected_positive else None
    result["false_negative_rate_conservative"] = (
        (fn + abstained_malicious) / expected_positive if expected_positive else None
    )
    result["specificity_conservative"] = tn / expected_negative if expected_negative else None
    result["abstained_malicious"] = abstained_malicious
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)



if __name__ == "__main__":
    main()
