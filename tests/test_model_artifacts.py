import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ModelArtifactTests(unittest.TestCase):
    def test_web_models_are_byte_identical_to_trained_models(self):
        for name in ("url-host-v1.json", "message-v1.json"):
            self.assertEqual((ROOT / "ml/models" / name).read_bytes(), (ROOT / "web/src/lib/models" / name).read_bytes(), name)

    def test_parity_fixture_is_current(self):
        sys.path.insert(0, str(ROOT))
        from scripts.generate_model_parity_fixture import build
        committed = json.loads((ROOT / "web/tests/fixtures/model-parity.json").read_text(encoding="utf-8"))
        self.assertEqual(build(), committed)

    def test_models_publish_provenance_and_heldout_metrics(self):
        for name in ("url-host-v1.json", "message-v1.json"):
            model = json.loads((ROOT / "ml/models" / name).read_text())
            self.assertGreater(model["metrics"]["test_roc_auc"], 0.9)
            self.assertIn("split", model["training"])
            self.assertTrue(any("sha256" in key for key in model["training"]))


if __name__ == "__main__":
    unittest.main()
