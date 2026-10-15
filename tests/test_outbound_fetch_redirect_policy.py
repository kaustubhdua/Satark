"""Keep provider API fetches from silently following redirects."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FETCH_PATHS = (
    "web/src/app/api/audit/verify/route.ts",
    "web/src/app/api/cases/route.ts",
    "web/src/app/api/evidence/[id]/verify/route.ts",
    "web/src/app/api/evidence/records/route.ts",
    "web/src/app/api/evidence/route.ts",
    "web/src/app/api/findings/route.ts",
    "web/src/app/api/reports/[id]/route.ts",
    "web/src/app/api/reports/route.ts",
    "web/src/lib/local-analysis.mjs",
)


class OutboundFetchRedirectPolicyTests(unittest.TestCase):
    def test_provider_fetches_reject_redirects(self):
        for relative in FETCH_PATHS:
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                fetch_count = len(re.findall(r"\bfetch(?:Impl)?\s*\(", source))
                redirect_count = len(re.findall(r"redirect:\s*['\"]error['\"]", source))
                self.assertGreater(fetch_count, 0, "expected provider fetches to be present")
                self.assertEqual(
                    redirect_count,
                    fetch_count,
                    "each provider fetch must explicitly reject redirects",
                )


if __name__ == "__main__":
    unittest.main()
