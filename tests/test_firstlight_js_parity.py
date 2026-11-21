"""The JavaScript port used by the browser-only workspace must match this engine exactly.

web/tests/fixtures/firstlight-parity.json is generated from the Python engine; web/tests/firstlight-parity.test.mjs
checks the JavaScript port against it. This test fails if the engine or rules change without regenerating it.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_firstlight_parity_fixture as generator  # noqa: E402


class FirstlightJsParityFixtureTests(unittest.TestCase):
    def test_fixture_matches_python_engine(self):
        committed = json.loads(generator.FIXTURE.read_text(encoding="utf-8"))
        regenerated = json.loads(generator.render())
        self.assertEqual(
            committed, regenerated,
            "FIRSTLIGHT engine/rules changed: run `python scripts/generate_firstlight_parity_fixture.py` and update "
            "web/src/lib/firstlight-engine.mjs so the browser-only workspace behaves the same.",
        )

    def test_fixture_exercises_every_rule(self):
        data = json.loads(generator.FIXTURE.read_text(encoding="utf-8"))
        seen = {f["title"] for case in data["cases"] for f in case["expected"]["findings"]}
        missing = {title for title in generator._RULES} - seen
        self.assertFalse(missing, f"parity fixture does not cover rules: {sorted(missing)}")


if __name__ == "__main__":
    unittest.main()
