"""Migration notice for the legacy Streamlit interface.

The primary SATARK product is the Next.js workspace in ``web/`` backed by the
self-hosted FastAPI service. The Streamlit app remains for features that have no
web equivalent yet. This module is the single source of truth for what moved
where, so the banner, the docs and the tests cannot drift apart.
"""
from __future__ import annotations

from dataclasses import dataclass

import streamlit as st

PORTED = "ported"
RETIRED = "retired"
STREAMLIT_ONLY = "streamlit-only"


@dataclass(frozen=True)
class LegacyPage:
    page: str            # key used by st.session_state.page
    label: str
    status: str          # PORTED | RETIRED | STREAMLIT_ONLY
    web_routes: tuple[str, ...]
    note: str


LEGACY_PAGES: tuple[LegacyPage, ...] = (
    LegacyPage("FIRSTLIGHT", "FIRSTLIGHT", RETIRED, ("/firstlight", "/cases"),
               "Operational incident handling lives in the authenticated web workspace."),
    LegacyPage("Home", "Overview", PORTED, ("/",), "The web home page is the entry point."),
    LegacyPage("Analyze", "Investigate", PORTED,
               ("/investigate", "/url", "/image-review", "/qr", "/pdf-review", "/media-review"),
               "Text, URL, image, QR, PDF and video review all run in the web app."),
    LegacyPage("File Guard", "File Guard", STREAMLIT_ONLY, ("/native-sensor",),
               "Desktop file scanning stays here; the Android app provides the offline mobile scanner."),
    LegacyPage("History", "Session history", RETIRED, ("/cases", "/reports"),
               "Session-only history is replaced by persistent, audited cases and reports."),
    LegacyPage("Challenge", "Scam Challenge", PORTED, ("/challenge",),
               "The full 100-level challenge, ranks and progress run in the web app."),
    LegacyPage("Academy", "SATARK Academy", PORTED, ("/learn",),
               "The complete lesson set and quiz are in the web Academy."),
    LegacyPage("Classroom", "Classroom Mode", PORTED, ("/classroom",),
               "The session summary lives in the web Classroom; it stores counts only."),
)

_BY_PAGE = {entry.page: entry for entry in LEGACY_PAGES}

_STATUS_TEXT = {
    PORTED: "This feature now lives in the web app.",
    RETIRED: "This legacy page is retired.",
    STREAMLIT_ONLY: "This feature is still Streamlit-only and has not been ported.",
}


def legacy_entry(page: str) -> LegacyPage | None:
    return _BY_PAGE.get(page)


def notice_text(page: str) -> str:
    """Plain-text notice for a page; used by the banner and by tests."""
    entry = legacy_entry(page)
    if entry is None:
        return "This is the legacy SATARK Streamlit interface. The web workspace is the primary product."
    where = " ".join(entry.web_routes)
    suffix = f" Web: {where}." if where else ""
    return f"{_STATUS_TEXT[entry.status]} {entry.note}{suffix}"


def render_legacy_notice(page: str) -> None:
    """Render a compact, non-dismissable migration notice at the top of a legacy page."""
    entry = legacy_entry(page)
    text = notice_text(page)
    if entry is not None and entry.status == STREAMLIT_ONLY:
        st.info("Legacy interface · " + text)
    else:
        st.warning("Legacy interface · " + text)
