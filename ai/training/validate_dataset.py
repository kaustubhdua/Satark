from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED = {"id", "text", "expected_signal_categories", "label"}
ALLOWED_CATEGORIES = {"url", "ip", "language"}
ALLOWED_LABELS = {"needs_review", "insufficient_evidence"}


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(row, dict):
            errors.append(f"line {line_number}: row must be an object")
            continue
        missing = REQUIRED - row.keys()
        if missing:
            errors.append(f"line {line_number}: missing keys {sorted(missing)}")
            continue
        if not isinstance(row["id"], str) or not row["id"].strip() or row["id"] in seen:
            errors.append(f"line {line_number}: id must be unique and non-empty")
        seen.add(row["id"])
        if not isinstance(row["text"], str) or not row["text"].strip() or len(row["text"]) > 12_000:
            errors.append(f"line {line_number}: text must be non-empty and at most 12000 chars")
        categories = row["expected_signal_categories"]
        if not isinstance(categories, list) or any(c not in ALLOWED_CATEGORIES for c in categories):
            errors.append(f"line {line_number}: unsupported signal category")
        if row["label"] not in ALLOWED_LABELS:
            errors.append(f"line {line_number}: unsupported label")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/eval/synthetic.jsonl")
    args = parser.parse_args()
    path = Path(args.input)
    errors = validate(path)
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Dataset structure valid: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
