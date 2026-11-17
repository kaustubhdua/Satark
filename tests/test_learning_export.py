from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import scam_challenge as sc
from scripts import export_learning_content as exporter
from ui import learning

OUT = exporter.OUT


class LearningExport(unittest.TestCase):
    def test_committed_web_data_matches_python_source_of_truth(self):
        files = exporter.build()
        for name, text in files.items():
            path = OUT / name
            self.assertTrue(path.is_file(), f"{name} missing; run scripts/export_learning_content.py")
            self.assertEqual(path.read_text(encoding="utf-8"), text, f"{name} is stale; run scripts/export_learning_content.py")
        self.assertEqual({p.name for p in OUT.glob("*.json")}, set(files), "unexpected extra learning files")

    def test_question_bank_is_complete_and_well_formed(self):
        total = 0
        seen_ids = set()
        for level in range(1, 101):
            tier = sc.sc_tier_for_level(level)
            data = json.loads((OUT / f"scam-challenge-tier-{tier}.json").read_text(encoding="utf-8"))
            questions = data["levels"][str(level)]
            self.assertEqual(len(questions), 10, f"level {level}")
            for q in questions:
                total += 1
                self.assertNotIn(q["id"], seen_ids)
                seen_ids.add(q["id"])
                self.assertEqual(len(q["options"]), 4)
                self.assertEqual(len(set(q["options"])), 4, q["id"])
                self.assertIn(q["answer"], range(4))
                self.assertGreater(len(q["explanation"]), 40, q["id"])
                self.assertNotRegex(q["question"] + " ".join(q["options"]), r"\{[a-z_]+\}", f"unfilled template in {q['id']}")
        self.assertEqual(total, 1000)

    def test_generation_is_deterministic(self):
        first = exporter.build()
        sc.sc_build_bank.clear() if hasattr(sc.sc_build_bank, "clear") else None
        self.assertEqual(first, exporter.build())

    def test_ranks_cover_every_level_exactly_once(self):
        ranks = json.loads((OUT / "ranks.json").read_text(encoding="utf-8"))
        covered = [lv for r in ranks for lv in range(r["lo"], r["hi"] + 1)]
        self.assertEqual(covered, list(range(1, 101)))
        for level in (1, 10, 11, 55, 100):
            expected = sc.sc_rank_for_level(level)["name"]
            self.assertEqual(next(r["name"] for r in ranks if r["lo"] <= level <= r["hi"]), expected)

    def test_lessons_match_academy(self):
        lessons = json.loads((OUT / "lessons.json").read_text(encoding="utf-8"))
        self.assertEqual(len(lessons), len(learning.LESSONS))
        for exported, (_icon, title, copy, steps) in zip(lessons, learning.LESSONS):
            self.assertEqual(exported, {"title": title, "copy": copy, "steps": steps})

    def test_points_function_properties(self):
        self.assertEqual(sc.sc_compute_points(False, 1), 0)
        self.assertEqual(sc.sc_compute_points(True, 0), sc.SC_MAX_POINTS)
        self.assertEqual(sc.sc_compute_points(True, 10_000), int(sc.SC_MAX_POINTS * 0.08))
        previous = sc.SC_MAX_POINTS + 1
        for t in range(0, 120):
            current = sc.sc_compute_points(True, t)
            self.assertLessEqual(current, previous)
            previous = current

    def test_tier_boundaries_constant_matches_python(self):
        constants = json.loads((OUT / "constants.json").read_text(encoding="utf-8"))
        for tier, upper in constants["tierBoundaries"].items():
            self.assertEqual(sc.sc_tier_for_level(upper), int(tier))
            self.assertEqual(sc.sc_tier_for_level(upper + 1) if upper < 100 else int(tier) + 1, int(tier) + 1)


if __name__ == "__main__":
    unittest.main()
