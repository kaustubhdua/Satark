"""Retired legacy FIRSTLIGHT page.

Operational FIRSTLIGHT now lives in the authenticated web workspace and self-hosted
API. This Streamlit compatibility route intentionally loads no sample incidents,
imports no evidence into an ephemeral session, and offers no simulated response.
"""
from __future__ import annotations

import streamlit as st


def render_firstlight() -> None:
    st.markdown(
        '<div class="workspace-eyebrow">SATARK / FIRSTLIGHT</div>'
        '<h1 style="margin-bottom:.2rem">FIRSTLIGHT incident workspace</h1>'
        '<p style="color:var(--text-secondary,#94a3b8);max-width:850px">'
        'The legacy Streamlit incident prototype has been retired. The operational '
        'workspace uses authenticated case storage, source-backed evidence and a '
        'separate guarded Wazuh integration.</p>',
        unsafe_allow_html=True,
    )
    st.info("This legacy page does not load training incidents, fabricate alerts, persist evidence, or simulate response actions.")
    st.warning("Do not use this page for operational incident handling. The authenticated FIRSTLIGHT backend must be configured and verified before real case data is submitted.")
    st.markdown("### Current integration boundary")
    st.markdown(
        "- Wazuh alert ingestion is optional and requires a private, trusted Indexer connection."
        "\n- Persistent cases and evidence require the self-hosted API, PostgreSQL and private evidence storage."
        "\n- Live response remains disabled by default and requires an authorized disposable-agent acceptance test."
    )
