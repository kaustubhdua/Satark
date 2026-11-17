#!/usr/bin/env python3
"""Export SATARK learning content from its Python source of truth to the web app.

`scam_challenge.py` (the deterministic question generators) and `ui/learning.py`
(the Academy lessons) remain the single source of truth. This script writes the
JSON the Next.js app plays, and `tests/test_learning_export.py` fails if the
committed JSON drifts from what the Python code generates.

    python scripts/export_learning_content.py          # rewrite JSON
    python scripts/export_learning_content.py --check  # exit 1 if out of date
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "web" / "src" / "data" / "learning"


def build() -> dict[str, str]:
    """Return {filename: file text} for every exported file."""
    import scam_challenge as sc
    from ui import learning

    bank = sc.sc_build_bank()
    files: dict[str, str] = {}

    tiers: dict[int, dict[str, list[dict]]] = {}
    for level in range(1, 101):
        tier = sc.sc_tier_for_level(level)
        tiers.setdefault(tier, {})[str(level)] = [
            {"id": q["id"], "category": q["category"], "question": q["question"],
             "options": q["options"], "answer": q["answer"], "explanation": q["explanation"]}
            for q in bank[level]
        ]
    for tier, levels in sorted(tiers.items()):
        files[f"scam-challenge-tier-{tier}.json"] = _dump({"tier": tier, "levels": levels})

    files["ranks.json"] = _dump([
        {"roman": r["roman"], "name": r["name"], "lo": r["lo"], "hi": r["hi"], "color": r["color"]}
        for r in sc.SC_RANKS
    ])
    files["lessons.json"] = _dump([
        {"title": title, "copy": copy, "steps": steps} for (_icon, title, copy, steps) in learning.LESSONS
    ])
    files["constants.json"] = _dump({
        "maxPoints": sc.SC_MAX_POINTS, "questionsPerLevel": 10, "levels": 100,
        "tierBoundaries": {"1": 10, "2": 20, "3": 40, "4": 60, "5": 80, "6": 90, "7": 100},
    })
    # Scoring parity: the web engine must reproduce the Python function exactly.
    times = [0, 0.25, 0.5, 1, 2.5, 3.7, 7.77, 10, 18, 30, 45.5, 60, 120, 600]
    files["points-parity.json"] = _dump({
        "correct": [[t, sc.sc_compute_points(True, t)] for t in times],
        "incorrect": [[t, sc.sc_compute_points(False, t)] for t in times],
        "negativeElapsed": [-5, sc.sc_compute_points(True, -5)],
    })
    return files


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def main(argv: list[str]) -> int:
    files = build()
    if "--check" in argv:
        stale = [n for n, text in files.items() if not (OUT / n).is_file() or (OUT / n).read_text(encoding="utf-8") != text]
        extra = sorted(p.name for p in OUT.glob("*.json") if p.name not in files) if OUT.is_dir() else []
        if stale or extra:
            print("Out of date: " + ", ".join(stale + extra))
            return 1
        print(f"{len(files)} learning files are up to date.")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8")
    print(f"Wrote {len(files)} files to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
