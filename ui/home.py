"""SATARK home workspace."""
import streamlit as st
from ui.demo import get_demo_result


def render_home():
    """Render a calm entry point with one clear next step and compact discovery."""
    st.markdown(
        '<section class="ih-hero satark-home-hero">'
        '<div class="ih-hero-glow" aria-hidden="true"></div>'
        '<div class="ih-hero-copy">'
        '<div class="ih-kicker"><span class="ih-live-dot"></span> DIGITAL TRUST / INCIDENT INTELLIGENCE</div>'
        '<h1>Pause the panic.<br><span>Find the signal.</span></h1>'
        '<p class="ih-lede">Investigate suspicious content without the noise. Start with an incident, a message, a link or a file — then inspect the evidence and choose your next step.</p>'
        '<div class="ih-hero-actions"><span class="ih-proof"><b>01</b> Observe</span><span class="ih-proof"><b>02</b> Verify</span><span class="ih-proof"><b>03</b> Decide</span></div>'
        '<div class="ih-micro-note"><span class="ih-check">✓</span> Evidence-led · Explainable · Human-reviewed</div>'
        '</div>'
        '<aside class="ih-console satark-spotlight-card" aria-label="Illustrative investigation signal preview">'
        '<div class="ih-console-top"><div class="ih-console-brand"><span class="ih-console-mark">S</span><div><b>SATARK</b><small>THREAT INTELLIGENCE</small></div></div><span class="ih-demo-chip">EXAMPLE</span></div>'
        '<div class="spotlight-orb" aria-hidden="true"><span class="spotlight-orb-core"></span><span class="spotlight-orb-ring spotlight-orb-ring-a"></span><span class="spotlight-orb-ring spotlight-orb-ring-b"></span><span class="spotlight-orb-sweep"></span></div>'
        '<div class="spotlight-status"><span class="spotlight-status-dot"></span><span>OBSERVABLE SIGNALS</span><span class="spotlight-status-right">EXAMPLE VIEW</span></div>'
        '<div class="spotlight-signal"><span class="spotlight-signal-index">01</span><div><b>Urgency language</b><small>Pressure to act before verifying</small></div><span class="spotlight-signal-tag">REVIEW</span></div>'
        '<div class="spotlight-signal"><span class="spotlight-signal-index">02</span><div><b>Account action requested</b><small>Destination should be checked independently</small></div><span class="spotlight-signal-tag">CHECK</span></div>'
        '<div class="spotlight-footnote">Signals are observations — not proof of fraud.</div>'
        '</aside>'
        '</section>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<section class="ih-focus satark-firstlight-spotlight">'
        '<div class="ih-focus-index">INCIDENT WORKSPACE</div>'
        '<div class="ih-focus-main"><div class="ih-focus-title">FIRSTLIGHT <span>Incident Command</span></div>'
        '<p>Reconstruct an incident, verify evidence integrity, trace findings to records and review proposed response actions — without performing real-world changes.</p>'
        '<div class="spotlight-feature-row"><span>◈ Evidence integrity</span><span>↗ Investigation timeline</span><span>✓ Auditable decisions</span></div></div>'
        '<div class="ih-focus-aside"><span class="ih-status-pill"><span></span> TRAINING CASE</span><div>Start with a guided case.<br>Explore each stage when you need it.</div></div>'
        '</section>',
        unsafe_allow_html=True,
    )
    with st.container(key="home-actions"):
        col_primary, col_secondary, col_tertiary = st.columns([1.1, 1, .9], gap="small")
        with col_primary:
            if st.button("Open FIRSTLIGHT →", width="stretch", type="primary", key="goto_firstlight"):
                st.session_state.page = "FIRSTLIGHT"
                st.rerun()
        with col_secondary:
            if st.button("Start an investigation →", width="stretch", key="goto_analyze"):
                st.session_state.page = "Analyze"
                st.session_state.scroll_to_scanners = True
                st.session_state.demo_mode = False
                st.rerun()
        with col_tertiary:
            if st.button("View example report", width="stretch", key="demo_result"):
                st.session_state.result = get_demo_result()
                st.session_state.mode = "Text"
                st.session_state.demo_mode = True
                st.session_state.page = "Analyze"
                st.rerun()

    st.markdown(
        '<section class="ih-toolkit">'
        '<div class="ih-section-head"><div><div class="ih-kicker">THE TOOLKIT <span class="ih-section-count">02 / 03</span></div>'
        '<h2>Bring what you have.<br><span>Investigate from there.</span></h2></div>'
        '<p>Each scanner lives in its own focused workflow. Choose the artifact first; the workspace will guide the next step.</p></div>'
        '<div class="ih-capability-grid">'
        '<article class="ih-capability ih-capability-featured"><div class="ih-cap-top"><span>01</span><span class="ih-cap-icon">⌘</span></div><h3>Messages & text</h3><p>Review pressure tactics, impersonation cues and suspicious requests.</p><div class="ih-cap-tags"><span>SMS</span><span>EMAIL</span><span>TEXT</span></div></article>'
        '<article class="ih-capability"><div class="ih-cap-top"><span>02</span><span class="ih-cap-icon">↗</span></div><h3>Links & websites</h3><p>Inspect URL structure and eligible page content.</p><div class="ih-cap-tags"><span>URL</span><span>DOMAIN</span></div></article>'
        '<article class="ih-capability"><div class="ih-cap-top"><span>03</span><span class="ih-cap-icon">▧</span></div><h3>Images & QR</h3><p>Review visual claims, embedded text and QR content.</p><div class="ih-cap-tags"><span>IMAGE</span><span>QR</span></div></article>'
        '<article class="ih-capability"><div class="ih-cap-top"><span>04</span><span class="ih-cap-icon">▤</span></div><h3>PDFs & video</h3><p>Extract supported text, sample frames and optionally transcribe audio.</p><div class="ih-cap-tags"><span>PDF</span><span>VIDEO</span></div></article>'
        '</div></section>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<section class="ih-bottom-row">'
        '<div class="ih-bottom-note"><span class="ih-bottom-icon">↗</span><div><b>Pick up where you left off</b><p>Session history keeps completed reports available while this session is active.</p></div></div>'
        '<div class="ih-bottom-note"><span class="ih-bottom-icon">◎</span><div><b>Learn at your own pace</b><p>Review an example assessment before starting your own analysis.</p></div></div>'
        '</section>'
        '<section class="ih-trust"><div class="ih-trust-mark">i</div><div><div class="ih-trust-title">Designed for informed triage — not automatic truth.</div>'
        '<p>Risk scores are heuristic summaries; model confidence is not a calibrated probability. A missing signal does not prove content is safe. Avoid submitting passwords, OTPs, private keys or unnecessary personal data.</p></div><span class="ih-trust-label">USE WITH JUDGMENT</span></section>'
        '<footer class="ih-footer"><span>SATARK <b>×</b> FIRSTLIGHT</span><span>Clarity over panic. Evidence over assumption.</span></footer>',
        unsafe_allow_html=True,
    )
