"""Focused navigation and session controls for SATARK."""
import os
import streamlit as st


def configured_ollama_base_url():
    """Read the operator-controlled local Ollama endpoint."""
    return str(os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).strip().rstrip("/")


def render_sidebar(get_client, discover_models, choose_model, text_preferences, vision_preferences):
    with st.sidebar:
        st.markdown(
            '<div class="brand"><div class="brand-mark">S<span>·</span></div>'
            '<div><div class="brand-logo">SATARK</div>'
            '<div class="brand-tag">FIRSTLIGHT incident response · SATARK threat tools</div></div></div>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="side-label">Workspace</div>', unsafe_allow_html=True)
        _render_page_buttons([
            ("FIRSTLIGHT", "FIRSTLIGHT · Incident Command"),
            ("Home", "Overview"),
            ("Analyze", "Investigate"),
            ("History", "Session history"),
        ])

        st.markdown('<div class="side-label">Learn & practice</div>', unsafe_allow_html=True)
        _render_page_buttons([
            ("Challenge", "Scam Challenge"),
            ("Academy", "SATARK Academy"),
            ("Classroom", "Classroom Mode"),
        ])

        with st.expander("Local AI model", expanded=False):
            st.caption("SATARK uses an Ollama model running on infrastructure you control. No third-party AI API key is required.")
            st.code(configured_ollama_base_url(), language="text")
            st.caption("Default models: qwen2.5:3b for text and qwen2.5vl:3b for images. Download model weights once with Ollama; first-time downloads require internet access.")
            if st.button("Test local model connection", key="check_ai", use_container_width=True):
                try:
                    client = get_client()
                    available = discover_models(client)
                    st.session_state.available_models = available
                    if not available:
                        st.session_state.text_model = None
                        st.session_state.vision_model = None
                        st.error("Ollama is unreachable or no models are installed. Start Ollama and run ollama pull qwen2.5:3b.")
                    else:
                        st.session_state.text_model = choose_model(available, text_preferences)
                        st.session_state.vision_model = choose_model(available, vision_preferences)
                        st.success("Local Ollama reachable · " + str(len(available)) + " model(s) installed")
                except Exception as exc:
                    st.error("Local model connection failed (" + type(exc).__name__ + "). Check OLLAMA_BASE_URL and Ollama status.")


        with st.expander("Analysis context", expanded=False):
            role = st.selectbox(
                "Who is this for?",
                ["Student", "Teacher", "Working professional", "Parent / Guardian",
                 "Senior user", "Security learner"],
                index=0,
                key="analysis_audience",
            )

        st.markdown(
            '<div class="privacy"><span class="privacy-icon">↳</span>'
            '<div><strong>Privacy boundary</strong><p>History stays in this session. Submitted content is processed by your configured local model only when you start an analysis; no hosted AI provider is used. Do not submit passwords, OTPs, private keys or unnecessary personal data.</p></div></div>',
            unsafe_allow_html=True,
        )
    return None, role


def _render_page_buttons(pages):
    """Render one navigation group and keep active-page feedback consistent."""
    for page, label in pages:
        if st.button(
            label, key=f"nav_{page}", use_container_width=True,
            type="primary" if st.session_state.get("page") == page else "secondary",
        ):
            st.session_state.page = page
            st.rerun()
