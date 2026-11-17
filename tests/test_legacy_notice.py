from __future__ import annotations

import re
import unittest
from pathlib import Path

from ui import legacy_notice
from ui.legacy_notice import LEGACY_PAGES, PORTED, RETIRED, STREAMLIT_ONLY

ROOT = Path(__file__).resolve().parents[1]
NAV = (ROOT / "ui/navigation.py").read_text(encoding="utf-8")
APP = (ROOT / "satark.py").read_text(encoding="utf-8")


def web_route_exists(route: str) -> bool:
    if route == "/":
        return (ROOT / "web/src/app/page.tsx").is_file()
    return (ROOT / "web/src/app" / route.strip("/") / "page.tsx").is_file()


class LegacyNoticeContract(unittest.TestCase):
    def test_every_sidebar_page_has_a_migration_entry(self):
        sidebar_pages = set(re.findall(r'\("([A-Za-z ]+)", "[^"]+"\)', NAV))
        self.assertTrue(sidebar_pages, "could not read sidebar pages")
        self.assertEqual(sidebar_pages, {entry.page for entry in LEGACY_PAGES})

    def test_every_dispatched_page_has_a_migration_entry(self):
        dispatched = set(re.findall(r'st\.session_state\.page == "([^"]+)"', APP))
        self.assertLessEqual(dispatched, {entry.page for entry in LEGACY_PAGES})

    def test_claimed_web_routes_really_exist(self):
        for entry in LEGACY_PAGES:
            for route in entry.web_routes:
                self.assertTrue(web_route_exists(route), f"{entry.page} points at missing web route {route}")

    def test_ported_and_retired_pages_name_a_web_destination(self):
        for entry in LEGACY_PAGES:
            self.assertIn(entry.status, {PORTED, RETIRED, STREAMLIT_ONLY})
            if entry.status in {PORTED, RETIRED}:
                self.assertTrue(entry.web_routes, f"{entry.page} claims to have moved but names no web route")

    def test_streamlit_only_pages_never_claim_to_be_ported(self):
        for entry in LEGACY_PAGES:
            text = legacy_notice.notice_text(entry.page)
            if entry.status == STREAMLIT_ONLY:
                self.assertIn("Streamlit-only", text)
                self.assertNotIn("now lives in the web app", text)

    def test_notice_is_rendered_on_every_page_before_dispatch(self):
        self.assertIn("render_legacy_notice(st.session_state.page)", APP)
        self.assertLess(APP.index("render_legacy_notice(st.session_state.page)"),
                        APP.index('if st.session_state.page == "FIRSTLIGHT"'))

    def test_unknown_page_gets_generic_notice(self):
        self.assertIn("legacy", legacy_notice.notice_text("Nope").lower())


if __name__ == "__main__":
    unittest.main()
