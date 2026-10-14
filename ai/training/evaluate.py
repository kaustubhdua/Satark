from __future__ import annotations

import json
from pathlib import Path

from service.engine import analyze_text


def main() -> int:
    path = Path("data/eval/synthetic.jsonl")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    exact = 0
    observed: dict[str, int] = {"tp": 0, "fp": 0, "fn": 0}
    for row in rows:
        actual = {signal.category for signal in analyze_text(row["text"])}
        expected = set(row["expected_signal_categories"])
        exact += actual == expected
        observed["tp"] += len(actual & expected)
        observed["fp"] += len(actual - expected)
        observed["fn"] += len(expected - actual)
        print(f'{row["id"]}: expected={sorted(expected)} actual={sorted(actual)}')
    precision = observed["tp"] / max(1, observed["tp"] + observed["fp"])
    recall = observed["tp"] / max(1, observed["tp"] + observed["fn"])
    print(f"synthetic_examples={len(rows)} exact_category_match={exact}/{len(rows)}")
    print(f"category_precision={precision:.3f} category_recall={recall:.3f}")
    print("WARNING: tiny synthetic smoke test only; not a security efficacy benchmark.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
