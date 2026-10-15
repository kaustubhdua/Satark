"""Guard production smoke checks against following arbitrary HTTP redirects."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/production-smoke.yml"


class ProductionSmokeRedirectPolicyTests(unittest.TestCase):
    def test_public_route_probe_does_not_follow_redirects(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^          check_route\(\) \{.*?^          \}", workflow
        )
        self.assertIsNotNone(match, "production route probe must exist")
        route_probe = match.group(0)
        self.assertNotIn("--location", route_probe)
        self.assertNotIn("--location-trusted", route_probe)
        self.assertIn("--max-time 20", route_probe)
        self.assertIn('[[ "$status" != "200" ]]', route_probe)

    def test_smoke_collects_failures_before_failing(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("failures=0", workflow)
        self.assertIn("record_failure()", workflow)
        self.assertIn('if [[ "$failures" -gt 0 ]]; then', workflow)
        self.assertIn('check_route "/tools"', workflow)
        self.assertIn('check_route "/qr"', workflow)
        self.assertIn('"/api/version"', workflow)


if __name__ == "__main__":
    unittest.main()
