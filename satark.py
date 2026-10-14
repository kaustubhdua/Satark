# 🧰 CORE PYTHON / SYSTEM
import os
from pathlib import Path
import re
import random
import time
import math
import json
import html
import hashlib
from datetime import datetime
from zoneinfo import ZoneInfo

# SATARK always displays timestamps in India Standard Time, regardless
# of what timezone the server the app happens to be running on is set
# to (e.g. most cloud hosts default to UTC, which made History/PDF
# timestamps look "wrong" — several hours off from local time).
IST = ZoneInfo("Asia/Kolkata")


def now_ist():
    return datetime.now(IST)

# 🌐 WEB / URL HANDLING
from urllib.error import HTTPError, URLError

# 🤖 AI / WEB APP
import streamlit as st
import streamlit.components.v1 as components

# 📄 FILE & IMAGE PROCESSING

# 📑 PDF GENERATION
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, PageBreak, KeepTogether
)
from reports import make_pdf_report
from satark_utils import safe_text, clean_json_text, normalize_check_value, check_class, THREAT_CHECKS, OFFICIAL_VERIFICATION_SOURCES
from radar_background import render_radar_background
from stepper_component import render_stepper
from config import MAX_HISTORY_ITEMS, MAX_TEXT_INPUT_CHARS, MAX_ANALYSES_PER_MINUTE
from rate_limiter import consume_analysis_slot
from analysis_engine import (
    clamp_score,
    is_scam_claim,
    normalize_result_consistency,
    risk_label,
    build_fallback_threat_analysis,
    build_final_conclusion,
    calibrate_confidence,
    normalize_result,
)
from ui.home import render_home
from ui.firstlight import render_firstlight
from ui.loading import render_intro_loader
from ui.navigation import render_sidebar
from ui.results import render_threat_analysis, render_verification_sources, render_evidence_ledger, render_evidence_review, render_investigation_timeline, render_threat_intelligence
from evidence_engine import extract_deterministic_evidence
from ui.history import render_history
from ui.learning import render_academy, render_classroom

from video_processing import (
    MAX_VIDEO_FRAMES,
    MAX_VIDEO_BYTES,
    _video_dependencies_available,
    extract_video_frames,
    pil_frames_to_data_urls,
    transcribe_video_audio,
)


from ai_provider import (
    get_client,
    TEXT_MODEL_PREFERENCES,
    VISION_MODEL_PREFERENCES,
    VISION_MODEL_IMAGE_LIMITS,
    discover_models,
    choose_model,
    model_status,
)


# ------------------------- AI analysis --------------------------
SYSTEM_PROMPT = """
You are SATARK, a careful digital-threat and content-authenticity analysis assistant.

Analyze the content for scams, phishing, social engineering, malware, impersonation,
suspicious links, credential theft, fraud, payment fraud, account takeover, malicious
QR codes, deepfakes, AI-generated/manipulated media, and fabricated or misleading claims.

Rules:
- Never claim certainty when evidence is weak. Distinguish evidence from inference.
- Confidence must reflect evidence strength: weak/ambiguous evidence → below 50; only
  strong, unambiguous evidence → above 85. Do not default high.
- Do not invent URLs, organizations, sender details, or facts not visible in the input.
- CRITICAL: Professional visual quality (clean logo, good typography, polished layout)
  is NOT evidence of truthfulness. A fabricated or AI-generated endorsement can look just
  as polished as a real one. Never let visual/production quality lower your Fake
  Information, Impersonation, or Deepfake Risk scores — judge those on the plausibility
  of the underlying claim, not the graphic design.
- For any image that asserts a specific named real person did/said/endorsed something,
  treat this as an unverified factual claim requiring scrutiny, not just a design
  element. Explicitly reason about real-world plausibility given who the person is and
  what role or position they are commonly known for (e.g. a person widely known to hold
  a government office, judicial role, regulatory position, or similar public-trust role
  making a commercial product endorsement is unusual and often against normal conduct
  norms — flag this tension). This applies generally to any named real person, not only
  political figures — also apply it to claimed celebrity, executive, or institutional
  endorsements that seem inconsistent with what is publicly known about that person or
  organization. Raise Fake Information / Impersonation to at least Medium when such a
  claim cannot be corroborated from the image alone.
- For images/video frames: inspect visible text, URLs, QR content, logos, layout,
  instructions, and whether content may be AI-generated, manipulated, or a deepfake.
  Identify factual claims (quotes, endorsements, identities, affiliations) that may need
  verification. Do NOT classify as Safe merely because it looks like a normal/professional
  graphic — cybersecurity safety and content authenticity are separate axes, and a "Safe"
  cybersecurity verdict must not imply the claims shown are true.
- If the image depicts a real, named person making an endorsement/claim that you cannot
  verify from the image alone, the verdict and summary MUST state plainly that this
  cannot be confirmed as genuine and should be independently verified before belief or
  sharing — do not phrase this as an optional suggestion buried only in recommendations.
- For URLs: consider domain mismatch, redirects, credential requests, urgency, impersonation.

Return ONLY valid JSON, no markdown, no code fences. Required schema:
{
  "risk_score": 0,
  "confidence": 0,
  "threat_category": "Safe / Phishing / Scam / Malware / Impersonation / Suspicious Link / Payment Fraud / Account Takeover / Unverified Claim / Other",
  "verdict": "one short sentence",
  "summary": "2-4 sentence plain-English explanation",
  "key_indicators": ["indicator 1", "indicator 2"],
  "recommendations": ["action 1", "action 2"],
  "scam_pattern": "one short pattern name",
  "threat_analysis": {
    "Scam Indicators": "Detected / Not detected / Low / Medium / High",
    "Phishing Signs": "Detected / Not detected / Low / Medium / High",
    "Deepfake Risk": "Detected / Not detected / Low / Medium / High",
    "Fake Information": "Detected / Not detected / Low / Medium / High",
    "Suspicious Links": "Detected / Not detected / Low / Medium / High",
    "Impersonation": "Detected / Not detected / Low / Medium / High",
    "Malware Indicators": "Detected / Not detected / Low / Medium / High",
    "Social Engineering": "Detected / Not detected / Low / Medium / High"
  },
  "final_conclusion": "2-4 sentence final conclusion explaining why the assessment was reached"
}
"""


from input_processing import (
    MAX_PDF_BYTES,
    MAX_IMAGE_BYTES,
    _uploaded_size,
    extract_pdf_text,
    image_to_data_url,
    images_to_data_urls,
    uploaded_fingerprint,
    single_file_fingerprint,
)


# ============================================================
# SATARK — Smart AI Threat Analysis & Risk Knowledge
# Streamlit entry point; feature modules are kept separate where practical
#
# Keeps the original SATARK analysis flow, while adding:
# - automatic local Ollama model discovery
# - resilient model selection based on provider discovery
# - improved result presentation
# - session history + report export
# - Scam Challenge
# - SATARK Academy
# - Classroom Mode
# - evidence / confidence / actions
# - privacy-first session storage
#
# CHANGES IN THIS VERSION:
# 1. calibrate_confidence() no longer force-floors confidence to 95-99.99%.
#    It now reports a value that actually reflects model + evidence strength,
#    across the full 0-100 range.
# 2. render_result() color-codes the confidence metric (red/amber/green)
#    so low-confidence results are visually distinct.
# 3. VISION_MODEL_PREFERENCES is now a real fallback chain instead of a
#    single hardcoded model; analyze_with_local_model tries each in order instead
#    of giving up after the first failure.
# 4. is_scam_claim / normalize_result_consistency now trust the model's
#    explicit threat_category field first, and only fall back to regex
#    parsing of prose when the category is missing/ambiguous. This makes
#    scam/phishing detection less fragile to wording changes.
# 5. SYSTEM_PROMPT's confidence instruction is now explicit about using the
#    full 0-100 range honestly instead of defaulting high.
# 6. NEW: Video scanner mode. Videos are analyzed by extracting a handful of
#    representative frames (via OpenCV) and, when ffmpeg/moviepy is available,
#    transcribing the audio track (via local Whisper) so speech-based scam
#    signals aren't missed. Frames + transcript are fed into the same
#    analyze_with_local_model pipeline used for images/text.
# ============================================================

st.set_page_config(
    page_title="SATARK + FIRSTLIGHT — Incident Response",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="auto",
)

# ----------------------------- CSS ----------------------------

st.markdown(
    "<style>" + Path(__file__).with_name("styles.css").read_text(encoding="utf-8") + "</style>",
    unsafe_allow_html=True,
)

# Full-screen OGL radar backdrop; content remains above it via CSS z-index.
render_radar_background()

# --------------------------- Helpers --------------------------

def analyze_with_local_model(client, content, mode, role, image_data_urls=None, available_models=None):
    """Run a SATARK analysis using an appropriate local model.

    Vision requests now try each model in VISION_MODEL_PREFERENCES in order
    instead of a single hardcoded model, so a deprecated/inaccessible vision
    model no longer breaks image/QR/video analysis entirely. Text scans keep
    the existing SATARK text-model fallback chain. Video mode reuses the
    vision pipeline: frames are converted to data URLs before this function
    is called, exactly like the Image mode.

    The model-list endpoint is treated as a hint only: if the key can call the
    model successfully, SATARK proceeds even when model discovery is incomplete.
    """
    available_models = available_models or set()
    image_data_urls = list(image_data_urls or [])

    if len(image_data_urls) > 6:
        image_data_urls = image_data_urls[:6]

    user_prompt = f"""
Analysis type: {mode}
User profile: {role}

Analyze this content carefully:
{content}

Return a complete SATARK result using the required JSON schema. Do not omit
fields. For threat_analysis, use exactly one of: Detected, Needs review,
Not detected, Low, Medium, High.
"""

    def call(model, repair=False):
        common = {
            "model": model,
            "temperature": 0 if repair else 0.1,
            "max_tokens": 900 if not repair else 800,
            "response_format": {"type": "json_object"},
        }

        if image_data_urls:
            # Respect per-model image-count limits (e.g. Qwen accepts at most
            # 3 images per request) instead of sending every frame/image and
            # letting the API reject the whole call.
            per_model_limit = VISION_MODEL_IMAGE_LIMITS.get(model, len(image_data_urls))
            urls_for_model = image_data_urls[:per_model_limit]
            multimodal_content = [{"type": "text", "text": user_prompt}]
            for image_url in urls_for_model:
                multimodal_content.append({
                    "type": "image_url",
                    "image_url": {"url": image_url},
                })
            common["messages"] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": multimodal_content},
            ]
            common["reasoning_effort"] = "none"
        else:
            common["messages"] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]

        return client.chat.completions.create(**common)

    if image_data_urls:
        # Try every configured vision model in order rather than only the
        # first one. This is the fallback chain fix — previously the loop
        # below would `break` after a single failure for image requests.
        discovered_first = [m for m in VISION_MODEL_PREFERENCES if m in available_models]
        undiscovered_fallbacks = [m for m in VISION_MODEL_PREFERENCES if m not in available_models]
        candidates = discovered_first + undiscovered_fallbacks
    else:
        discovered_first = [m for m in TEXT_MODEL_PREFERENCES if m in available_models]
        undiscovered_fallbacks = [m for m in TEXT_MODEL_PREFERENCES if m not in available_models]
        candidates = discovered_first + undiscovered_fallbacks

    errors = []
    rate_limited = False

    for model in candidates:
        try:
            response = call(model)
            choices = getattr(response, "choices", None) or []
            if not choices:
                raise RuntimeError("Local Ollama returned no choices.")
            message = getattr(choices[0], "message", None)
            if message is None:
                raise RuntimeError("Local Ollama returned an incomplete response.")
            raw = getattr(message, "content", "") or ""

            # Ollama returns a string. Be defensive if an SDK version
            # exposes structured content instead.
            if not isinstance(raw, str):
                if isinstance(raw, list):
                    raw = "".join(
                        item.get("text", "") if isinstance(item, dict) else str(item)
                        for item in raw
                    )
                else:
                    raw = str(raw)

            raw = raw.strip()
            if not raw:
                raise RuntimeError("The AI model returned an empty response.")

            try:
                parsed = json.loads(clean_json_text(raw))
            except (json.JSONDecodeError, TypeError, ValueError) as parse_error:
                # JSON mode should make this uncommon. If a provider/SDK still
                # returns malformed content, perform one controlled repair call
                # with JSON mode enabled instead of falling through to another
                # unrelated model.
                repair_prompt = (
                    "Convert the following SATARK analysis into one valid JSON object. "
                    "Return ONLY JSON. Use exactly these top-level keys: "
                    "risk_score, confidence, threat_category, verdict, summary, "
                    "key_indicators, recommendations, scam_pattern, threat_analysis, "
                    "final_conclusion.\n\n"
                    + raw
                )
                original_prompt = user_prompt
                user_prompt = repair_prompt
                try:
                    repair_response = call(model, repair=True)
                finally:
                    user_prompt = original_prompt

                repair_choices = getattr(repair_response, "choices", None) or []
                if not repair_choices or getattr(repair_choices[0], "message", None) is None:
                    raise RuntimeError("The AI provider returned no usable JSON repair response.")
                repaired = getattr(repair_choices[0].message, "content", "") or ""
                if not isinstance(repaired, str):
                    repaired = str(repaired)
                repaired = repaired.strip()
                if not repaired:
                    raise RuntimeError("The AI model returned an empty JSON repair response.")
                parsed = json.loads(clean_json_text(repaired))
                raw = repaired

            if not isinstance(parsed, dict):
                raise RuntimeError("The AI model returned JSON, but it was not a JSON object.")

            result = normalize_result(parsed, raw, model)
            result["scam_pattern"] = safe_text(
                parsed.get("scam_pattern", result.get("threat_category", "Needs review")),
                result.get("threat_category", "Needs review"),
            )
            return normalize_result_consistency(result)

        except Exception as exc:
            # Classify local model failures before discarding diagnostics. HTTP errors
            # can include request metadata, so never return their raw text to users.
            error_text = str(exc).lower()
            rate_limited = rate_limited or "rate_limit_exceeded" in error_text or "request too large" in error_text
            errors.append(f"{model}: {type(exc).__name__}")
            # Move on to the next candidate model instead of giving up
            # immediately — this applies to text, image and video requests now.
            continue

    # Never make the app unusable just because the optional local model is
    # offline. Return conservative local pattern signals, clearly marked as
    # insufficient evidence; never label a no-model result "Safe".
    lowered = safe_text(content).lower()
    indicators = []
    score = 0
    if re.search(r"https?://", lowered):
        indicators.append("URL present; destination reputation was not checked.")
        score += 8
    if re.search(r"\b(urgent|immediately|act now|account suspended|verify your account|last chance)\b", lowered):
        indicators.append("Urgency or account-pressure language.")
        score += 10
    if re.search(r"\b(password|passcode|otp|verification code|login credentials|private key)\b", lowered):
        indicators.append("Credential or secret-related language.")
        score += 20
    if re.search(r"\b(prize|processing fee|gift card|wire transfer|crypto payment|payment required)\b", lowered):
        indicators.append("Payment, prize, or transfer language.")
        score += 12
    if image_data_urls:
        indicators.append("Local vision model unavailable; image/video frames were not visually assessed.")
    if not indicators:
        indicators.append("Local model unavailable; no AI inference was performed.")

    category = "Phishing" if any("Credential" in item for item in indicators) else (
        "Scam" if any("Payment" in item for item in indicators) else (
            "Suspicious" if score else "Needs review"
        )
    )
    fallback_result = {
        "risk_score": min(80, score),
        "confidence": 15,
        "threat_category": category,
        "verdict": "Local model unavailable; manual review is required.",
        "summary": (
            "Ollama did not return a result. SATARK used only conservative local pattern checks; "
            "no AI inference or external reputation lookup was performed. This is insufficient "
            "evidence, not a safety verdict."
        ),
        "key_indicators": indicators[:8],
        "recommendations": [
            "Verify the sender and destination through an independent trusted channel.",
            "Do not enter credentials or payment details while investigating.",
            "Preserve the original evidence and retry after your local model is available.",
        ],
        "scam_pattern": "local-model-unavailable",
        "threat_analysis": build_fallback_threat_analysis({
            "threat_category": category,
            "key_indicators": indicators,
            "summary": "Local model unavailable; needs review.",
        }),
        "final_conclusion": "The configured local model did not complete inference. Treat these pattern matches as triage hints only and verify independently.",
    }
    return normalize_result_consistency(
        normalize_result(fallback_result, json.dumps(fallback_result), "local-deterministic-fallback")
    )


def confidence_css_class(confidence):
    """Color-code the confidence metric so low-confidence results are visually
    distinct instead of looking identical to high-confidence ones."""
    if confidence >= 85:
        return "safe"
    if confidence >= 50:
        return "caution"
    return "critical"


def render_result(result):
    score = clamp_score(result.get("risk_score", 50))
    label, css = risk_label(score, result.get("threat_category", ""))
    indicators = result.get("key_indicators", [])
    recs = result.get("recommendations", [])
    try:
        confidence = float(result.get("confidence", 70.0))
        if not math.isfinite(confidence):
            confidence = 0.0
    except (TypeError, ValueError, OverflowError):
        confidence = 0.0
    confidence = max(0.0, min(100.0, confidence))
    conf_css = confidence_css_class(confidence)
    category = html.escape(safe_text(result.get("threat_category", "Needs review")))
    verdict = html.escape(safe_text(result.get("verdict", "Manual review recommended.")))
    pattern = html.escape(safe_text(result.get("scam_pattern", category)))

    with st.container(border=True, key="result_report"):
        st.markdown(
            '<div class="result-head">SATARK <span class="result-head-divider">/</span> Investigation report</div>'
            '<div class="eyebrow">Evidence-first AI assessment • advisory, not a guarantee</div>',
            unsafe_allow_html=True,
        )

        a, b, c, d = st.columns(4)
        with a:
            st.markdown(
                f'<div class="metric"><div class="metric-label">Assessment signal</div>'
                f'<div class="metric-value {css}">{label}</div></div>',
                unsafe_allow_html=True,
            )
        with b:
            st.markdown(
                f'<div class="metric"><div class="metric-label">Risk score · heuristic</div>'
                f'<div class="metric-value">{score}/100</div></div>',
                unsafe_allow_html=True,
            )
        with c:
            st.markdown(
                f'<div class="metric"><div class="metric-label">Pattern</div>'
                f'<div class="metric-value metric-value-compact">{pattern}</div></div>',
                unsafe_allow_html=True,
            )
        with d:
            st.markdown(
                f'<div class="metric"><div class="metric-label">Model-reported confidence</div>'
                f'<div class="metric-value {conf_css}">{confidence:.2f}%</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown(
            f'<div class="bar" role="progressbar" aria-label="Risk score" '
            f'aria-valuemin="0" aria-valuemax="100" aria-valuenow="{score}">'
            f'<div style="width:{score}%"></div></div>',
            unsafe_allow_html=True,
        )
        st.caption(
            "Risk is a heuristic summary, not a probability. Model-reported confidence is not "
            "independently calibrated. A low score or missing signal does not guarantee safety."
        )

        if confidence < 50:
            st.info(
                "Confidence is low — the evidence found was limited or ambiguous. "
                "Treat this result as a starting point, not a final answer, and verify manually."
            )

        st.markdown(
            f'<div class="verdict"><strong>Final verdict</strong><br>{verdict}</div>',
            unsafe_allow_html=True,
        )

        if result.get("summary"):
            st.markdown("### 🔎 What SATARK found")
            st.markdown(
                f'<p class="result-summary">{html.escape(safe_text(result["summary"]))}</p>',
                unsafe_allow_html=True,
            )

        indicator_values = []
        if isinstance(indicators, (list, tuple)):
            indicator_values = [safe_text(item) for item in indicators if safe_text(item)]
        else:
            value = safe_text(indicators)
            indicator_values = [value] if value else []

        recommendation_values = []
        if isinstance(recs, (list, tuple)):
            recommendation_values = [safe_text(item) for item in recs if safe_text(item)]
        else:
            value = safe_text(recs)
            recommendation_values = [value] if value else []

        evidence_items = "".join(
            f'<div class="evidence-item">⚠️ {html.escape(item)}</div>'
            for item in indicator_values
        ) or '<div class="evidence-item">No specific indicators were returned.</div>'

        action_items = "".join(
            f'<div class="action-item"><span>✓</span><span>{html.escape(item)}</span></div>'
            for item in recommendation_values
        ) or '<div class="action-item">Review the content manually before acting.</div>'

        # Show the observable evidence before model interpretation. This is the
        # defining SATARK workflow: evidence first, generated explanation second.
        render_investigation_timeline(result)
        render_evidence_ledger(result.get("deterministic_evidence", []), result.get("analysis_mode", ""))
        render_evidence_review(result)

        left, right = st.columns(2)
        with left:
            st.markdown(
                f'<div class="evidence"><strong>AI interpretation</strong>{evidence_items}</div>',
                unsafe_allow_html=True,
            )
        with right:
            st.markdown(
                f'<div class="evidence"><strong>Recommended next steps</strong>{action_items}</div>',
                unsafe_allow_html=True,
            )
        render_threat_analysis(result, THREAT_CHECKS)
        render_threat_intelligence(result.get("threat_intelligence", {}))
        render_verification_sources(result, OFFICIAL_VERIFICATION_SOURCES)

        conclusion = html.escape(build_final_conclusion(result))
        st.markdown(
            f'<section class="report-section"><h3>💡 Final Conclusion</h3>'
            f'<div class="conclusion-card">{conclusion}</div></section>',
            unsafe_allow_html=True,
        )


def add_history(result, mode):
    if "history" not in st.session_state: st.session_state.history=[]
    entry = {
        "time": now_ist().strftime("%d %b %Y, %I:%M %p") + " IST",
        "mode": mode,
        "score": clamp_score(result.get("risk_score",50)),
        "category": result.get("threat_category","Needs review"),
        "verdict": result.get("verdict",""),
        "result": result,
    }
    st.session_state.history.insert(0,entry)
    st.session_state.history=st.session_state.history[:MAX_HISTORY_ITEMS]


# ==============================================================
# SCAM CHALLENGE v2 — GAME ENGINE (100 levels x 10 questions)
# Integrated module: CSS, question generators, game state,
# and render functions for the in-app Scam Challenge page.
# ==============================================================

from scam_challenge import (
    SC_CSS,
    sc_init_state,
    render_scam_challenge,
)


def init_state():
    defaults={
        "mode":"Text","result":None,"history":[],"page":"Home",
        "challenge_index":0,"challenge_score":0,"challenge_answered":False,
        "available_models":set(),"text_model":None,"vision_model":None,
        "last_input_fingerprint":"","analysis_request_id":"","demo_mode":False,"scroll_to_scanners":False,
    }
    for k,v in defaults.items():
        if k not in st.session_state: st.session_state[k]=v
init_state()
sc_init_state()  # Scam Challenge v2 session-state defaults
render_intro_loader()  # One-time, dismissible intro; app remains usable underneath

# --------------------------- Sidebar ---------------------------
_, role = render_sidebar(
    get_client,
    discover_models,
    choose_model,
    TEXT_MODEL_PREFERENCES,
    VISION_MODEL_PREFERENCES,
)
# ---------------------------- Hero -----------------------------
# The Home page has its own editorial hero. Keep Analyze/History focused on the active task.

# --------------------------- Pages -----------------------------
# --------------------------- Pages -----------------------------

if st.session_state.page == "FIRSTLIGHT":
    render_firstlight()


elif st.session_state.page == "Home":
    render_home()


elif st.session_state.page == "Analyze":

    # ==========================================================
    # AUTO-SCROLL TO SCANNER SECTION
    # ==========================================================

    # Invisible anchor placed immediately before scanner cards
    st.markdown(
        '<div id="satark-scanner-anchor"></div>',
        unsafe_allow_html=True
    )

    # Scroll to scanner section only after clicking
    # "Let SATARK Check It" from the Home page.
    if st.session_state.get("scroll_to_scanners", False):

        import streamlit.components.v1 as components

        components.html(
            """
            <script>
            setTimeout(function() {

                const el =
                    window.parent.document.getElementById(
                        'satark-scanner-anchor'
                    );

                if (el) {
                    el.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }

            }, 300);
            </script>
            """,
            height=0,
        )

        st.session_state.scroll_to_scanners = False


    # ==========================================================
    # SCANNER SELECTION
    # ==========================================================

    st.markdown(
        '<div class="section-title">What do you want to check?</div>'
        '<div class="section-copy">'
        'Choose a scanner. Six scanners cover text, links, images, documents, QR codes and video.'
        '</div>',
        unsafe_allow_html=True
    )

    scanner_rows = [
        [
            ("Text", "💬", "Messages, posts and suspicious text"),
            ("URL", "🔗", "Websites and suspicious links"),
            ("Image", "🖼️", "Screenshots and images")
        ],
        [
            ("PDF", "📄", "Text-based documents"),
            ("QR", "▣", "QR screenshots and QR-related images"),
            ("Video", "🎬", "Suspicious clips, reels and voice-call recordings")
        ]
    ]

    for row in scanner_rows:

        cols = st.columns(3)

        for col, (name, icon, copy) in zip(cols, row):

            with col:

                active = st.session_state.mode == name

                st.markdown(
                    f'''
                    <div class="scanner {"active" if active else ""}">
                        <div class="scanner-icon">{icon}</div>
                        <div class="scanner-title">{name}</div>
                        <div class="scanner-copy">{copy}</div>
                    </div>
                    ''',
                    unsafe_allow_html=True
                )

                if st.button(
                    f"Select {name}",
                    key=f"scanner_{name}",
                    use_container_width=True,
                    type="primary" if active else "secondary",
                ):
                    st.session_state.mode = name
                    st.session_state.result = None
                    st.session_state.last_input_fingerprint = ""
                    st.session_state.analysis_request_id = ""

                    # Unique trigger for EVERY scanner click.
                    # This makes the auto-scroll repeat indefinitely.
                    st.session_state.scroll_to_input_trigger = (
                        st.session_state.get("scroll_to_input_trigger", 0) + 1
                    )

                    st.rerun()


    # ==========================================================
    # SELECTED MODE
    # ==========================================================

    mode = st.session_state.mode


    # ==========================================================
    # AUTO-SCROLL TO INPUT SECTION
    # ==========================================================

    # Invisible anchor immediately above Security Analysis
    st.markdown(
        '<div id="satark-input-anchor"></div>',
        unsafe_allow_html=True
    )

    # A new number is generated every time one of the scanner
    # buttons is clicked. We only handle each number once, so
    # normal Streamlit reruns (typing/uploading) do not cause
    # unwanted scrolling.
    scroll_trigger = st.session_state.get(
        "scroll_to_input_trigger",
        0
    )

    handled_trigger = st.session_state.get(
        "handled_scroll_to_input_trigger",
        0
    )

    if scroll_trigger != handled_trigger:
        import streamlit.components.v1 as components

        components.html(
            f"""
            <script>
            (function() {{
                const trigger = "{scroll_trigger}";
                let attempts = 0;

                function scrollToSATARKInput() {{
                    const parentDoc = window.parent.document;

                    const el = parentDoc.getElementById(
                        "satark-input-anchor"
                    );

                    if (el) {{
                        el.scrollIntoView({{
                            behavior: "smooth",
                            block: "start"
                        }});
                        return true;
                    }}

                    return false;
                }}

                // Streamlit renders asynchronously after reruns,
                // so retry briefly until the anchor is available.
                const timer = setInterval(function() {{
                    attempts++;

                    if (
                        scrollToSATARKInput() ||
                        attempts >= 20
                    ) {{
                        clearInterval(timer);
                    }}
                }}, 100);
            }})();
            </script>
            """,
            height=0,
        )

        # Mark this trigger as handled. The next scanner click
        # creates a new trigger and therefore scrolls again.
        st.session_state.handled_scroll_to_input_trigger = (
            scroll_trigger
        )


    # ==========================================================
    # SECURITY ANALYSIS INPUT
    # ==========================================================

    mode_details = {
        "Text": ("💬", "Messages & text", "Inspect urgency, credential requests, impersonation cues and embedded indicators."),
        "URL": ("↗", "Links & websites", "Review URL structure and inspect eligible public-page text using bounded fetching."),
        "Image": ("▧", "Images & screenshots", "Review visible claims, instructions and image context without treating appearance as proof."),
        "PDF": ("▤", "PDF documents", "Extract supported document text for review. Scanned or image-only pages may provide limited evidence."),
        "QR": ("▦", "QR code images", "Inspect QR-related images and visible context. Do not open an unknown destination just to verify it."),
        "Video": ("▷", "Video & clips", "Review sampled frames and, when available, a transcript. This is not exhaustive frame-by-frame forensics."),
    }
    mode_icon, mode_title, mode_description = mode_details.get(
        mode, ("◈", "Investigation", "Choose a supported input to begin.")
    )
    st.markdown(
        '<div class="section-title">Security Analysis</div>'
        '<div class="selected-workflow">'
        '<div class="selected-workflow-icon">' + mode_icon + '</div>'
        '<div class="selected-workflow-copy">'
        '<div class="selected-workflow-kicker">SELECTED WORKFLOW · ' + html.escape(mode.upper()) + '</div>'
        '<div class="selected-workflow-title">' + html.escape(mode_title) + '</div>'
        '<p>' + html.escape(mode_description) + '</p>'
        '</div>'
        '<div class="selected-workflow-state"><span></span> Ready for input</div>'
        '</div>',
        unsafe_allow_html=True
    )

    uploaded = None
    image_data_urls = []
    video_file = None
    transcribe_audio = True


    # ==========================================================
    # TEXT
    # ==========================================================

    if mode == "Text":

        content = st.text_area(
            "Enter content",
            height=230,
            placeholder=(
                "Paste any message, post, SMS, "
                "social-media content or suspicious text here..."
            ),
            key=f"text_input_{mode}",
            max_chars=MAX_TEXT_INPUT_CHARS,
        )


    # ==========================================================
    # URL
    # ==========================================================

    elif mode == "URL":

        content = st.text_input(
            "Website URL",
            placeholder="https://example.com",
            type="url",
            key="url_input"
        )
        st.caption("URL reputation lookups are disabled in local-only mode. No indicator is sent to a third-party service.")


    # ==========================================================
    # PDF
    # ==========================================================

    elif mode == "PDF":

        uploaded = st.file_uploader(
            "Upload PDF",
            type=["pdf"],
            max_upload_size=25,
            help="Best results come from text-based PDFs. Maximum size: 25 MB.",
            key="pdf_input"
        )

        content = ""


    # ==========================================================
    # VIDEO
    # ==========================================================

    elif mode == "Video":

        video_file = st.file_uploader(
            "Upload video",
            type=[
                "mp4",
                "mov",
                "avi",
                "webm",
                "mkv",
                "m4v"
            ],
            accept_multiple_files=False,
            max_upload_size=50,
            help=(
                "SATARK extracts a handful of representative "
                "frames and, when possible, transcribes the audio. "
                "Max 50 MB."
            ),
            key="video_input"
        )

        transcribe_audio = st.checkbox(
            "Also transcribe and analyze the audio track "
            "(recommended for voice-call/scam-call videos)",
            value=True,
            key="video_transcribe_toggle"
        )

        content = (
            "Analyze the sampled video frames "
            "(and transcript, if provided) together "
            "as one investigation."
        )

        if video_file is not None:
            st.video(video_file, alt="Uploaded video preview for SATARK analysis")

        uploaded = None


    # ==========================================================
    # IMAGE / QR
    # ==========================================================

    else:

        uploaded = st.file_uploader(
            "Upload image",
            type=[
                "png",
                "jpg",
                "jpeg",
                "webp"
            ],
            accept_multiple_files=True,
            max_upload_size=10,
            help=(
                "Upload one or more screenshots, QR images, "
                "email screenshots or suspicious images. "
                "SATARK will analyze the selected images together."
            ),
            key=f"image_input_{mode}"
        )

        content = (
            "Analyze all supplied images together. "
            "Inspect visible text, links, logos, QR-related content, "
            "suspicious instructions, impersonation and "
            "social-engineering signals, and cross-image evidence."
        )

        if uploaded and len(uploaded) > 5:

            st.info(
                "SATARK will analyze the first 5 selected images "
                "together to keep the request reliable."
            )


    # ==========================================================
    # INPUT FINGERPRINT
    # ==========================================================

    if mode in {"Image", "QR"}:

        current_input_fingerprint = uploaded_fingerprint(uploaded)

    elif mode == "Video":

        current_input_fingerprint = single_file_fingerprint(
            video_file
        )

    else:

        current_input_fingerprint = ""


    if (
        mode in {"Image", "QR", "Video"}
        and current_input_fingerprint
        != st.session_state.get(
            "last_input_fingerprint",
            ""
        )
    ):

        st.session_state.last_input_fingerprint = (
            current_input_fingerprint
        )

        if current_input_fingerprint:

            st.session_state.result = None


    # ==========================================================
    # ANALYZE BUTTON
    # ==========================================================

    st.markdown(
        '<div class="analyze">',
        unsafe_allow_html=True
    )

    analyze_clicked = st.button(
        "🔍 Analyze with SATARK",
        use_container_width=True,
        type="primary",
        key="analyze_button"
    )

    st.markdown(
        '</div>',
        unsafe_allow_html=True
    )


    # ==========================================================
    # RUN ANALYSIS
    # ==========================================================

    if analyze_clicked:

        allowed, retry_after = consume_analysis_slot(MAX_ANALYSES_PER_MINUTE)
        if not allowed:
            wait_seconds = max(1, int(retry_after + 0.999))
            st.error(
                "SATARK has reached the shared per-process analysis limit. "
                f"Please wait about {wait_seconds} seconds before trying again."
            )
            st.stop()

        try:

            # Fresh request ID for every analysis
            st.session_state.analysis_request_id = (
                hashlib.sha256(
                    f"{datetime.now().isoformat()}|{mode}"
                    .encode("utf-8")
                ).hexdigest()[:16]
            )

            st.session_state.result = None
            st.session_state.vision_model = None

            client = get_client()

            st.markdown(
                '<div class="analysis-loader" '
                'aria-label="SATARK is analyzing">'
                '<span></span></div>',
                unsafe_allow_html=True
            )


            with st.spinner(
                "SATARK is reading the content, "
                "evaluating threat patterns and "
                "building your report…"
            ):

                available = discover_models(client)

                st.session_state.available_models = available


                # ==================================================
                # PREPARE INPUT
                # ==================================================

                if mode == "Text":

                    if not safe_text(content):

                        raise ValueError(
                            "Please enter some content to analyze."
                        )

                    prepared = content[:MAX_TEXT_INPUT_CHARS]


                elif mode == "URL":

                    if not safe_text(content):

                        raise ValueError(
                            "Please enter a URL."
                        )

                    prepared = fetch_url_text(content)

                    if not prepared.strip():

                        raise ValueError(
                            "The URL returned no readable content."
                        )


                elif mode == "PDF":

                    if uploaded is None:

                        raise ValueError(
                            "Please upload a PDF."
                        )

                    prepared = extract_pdf_text(uploaded)


                elif mode == "Video":

                    if video_file is None:

                        raise ValueError(
                            "Please upload a video."
                        )


                    if not _video_dependencies_available():

                        raise RuntimeError(
                            "Video analysis needs OpenCV installed "
                            "in this environment "
                            "(pip install opencv-python-headless "
                            "--break-system-packages), then restart "
                            "the app."
                        )


                    # ----------------------------------------------
                    # Extract representative frames
                    # ----------------------------------------------

                    frames, duration, warnings = (
                        extract_video_frames(video_file)
                    )

                    image_data_urls = (
                        pil_frames_to_data_urls(frames)
                    )


                    if not image_data_urls:

                        raise ValueError(
                            "SATARK could not extract usable "
                            "frames from this video."
                        )


                    if warnings:

                        st.warning(
                            "⚠️ " + " ".join(warnings)
                        )


                    # ----------------------------------------------
                    # Audio transcription
                    # ----------------------------------------------

                    transcript = ""

                    if transcribe_audio:

                        transcript = transcribe_video_audio(
                            video_file,
                            client
                        )


                    duration_note = (
                        f"Approx. duration: "
                        f"{duration:.1f} seconds. "
                        if duration
                        else ""
                    )


                    transcript_note = (

                        f"Audio transcript:\n{transcript}"

                        if transcript

                        else
                        "Audio transcript: not available "
                        "(silent, unsupported audio, or "
                        "transcription unavailable in this "
                        "environment)."
                    )


                    prepared = (
                        f"{content}\n"
                        f"{duration_note}"
                        f"Number of sampled frames: "
                        f"{len(image_data_urls)}.\n\n"
                        f"{transcript_note}"
                    )


                else:

                    if not uploaded:

                        raise ValueError(
                            "Please upload at least one image."
                        )


                    # ----------------------------------------------
                    # Fresh image conversion
                    # ----------------------------------------------

                    image_data_urls = (
                        images_to_data_urls(
                            uploaded[:5],
                            max_images=5
                        )
                    )


                    if not image_data_urls:

                        raise ValueError(
                            "The selected image(s) "
                            "could not be read."
                        )


                    prepared = (
                        f"{content}\n"
                        f"Number of images in this "
                        f"investigation: "
                        f"{len(image_data_urls)}"
                    )


                # ==================================================
                # COLLECT INDEPENDENT EVIDENCE BEFORE AI INTERPRETATION
                # ==================================================

                # These local observations are extracted before the model call.
                # They are supplied as context, then retained separately so the
                # report can distinguish observed signals from generated claims.
                if mode in {"Text", "URL", "PDF", "Video"}:
                    evidence_source = (
                        f"Submitted URL: {content}\n\nFetched page text:\n{prepared}"
                        if mode == "URL"
                        else prepared
                    )
                    deterministic_evidence = extract_deterministic_evidence(
                        evidence_source
                    )
                else:
                    # Image/QR workflows use vision analysis; do not imply that
                    # text-only local rules independently verified visual claims.
                    deterministic_evidence = []

                # Local-only mode never calls external reputation APIs.
                threat_intelligence = {
                    "results": [],
                    "provider_notes": ["External reputation lookups are disabled in local-only mode."],
                    "queried": False,
                }
                evidence_context_ti = json.dumps(
                    threat_intelligence.get("results", []),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                evidence_context = json.dumps(
                    deterministic_evidence,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )

                # ==================================================
                # BUILD PROMPT
                # ==================================================

                prompt = (
                    f"User profile: {role}\n"
                    f"Scanner mode: {mode}\n\n"
                    f"Submitted content and extracted content:\n{prepared}\n\n"
                    "Independent local rule observations (JSON; observations, not verdicts):\n"
                    f"{evidence_context}\n\n"
                    f"Local threat-intelligence status (external lookups disabled; no API was called):\n{evidence_context_ti}\n\n"
                    "Use these observations as a separate evidence source. Do not claim that "
                    "an observation proves fraud. Do not invent corroboration when the list is "
                    "empty. Clearly distinguish direct observations, inference, and unknowns. "
                    "For visual scans, reason only from the supplied image(s) and state what "
                    "cannot be verified from the image alone."
                )


                # ==================================================
                # LOCAL OLLAMA ANALYSIS
                # ==================================================

                result = analyze_with_local_model(
                    client,
                    prompt,
                    mode,
                    role,
                    image_data_urls,
                    available
                )

                # Preserve the independent evidence and scanner type in the report.
                result["analysis_mode"] = mode
                result["deterministic_evidence"] = deterministic_evidence
                result["threat_intelligence"] = threat_intelligence


            # ======================================================
            # SAVE RESULT
            # ======================================================

            st.session_state.result = result

            add_history(
                result,
                mode
            )

            st.session_state.page = "Analyze"

            st.success(
                "SATARK analysis complete."
            )


        except (ValueError, RuntimeError) as exc:

            st.error(
                f"⚠️ {exc}"
            )


        except (HTTPError, URLError) as exc:

            st.error(
                f"⚠️ Could not fetch that URL safely ({type(exc).__name__}). "
                "Check that the URL is reachable and publicly accessible."
            )


        except Exception as exc:

            st.error(
                "⚠️ SATARK could not complete the analysis. "
                "Check that your local Ollama service is running, "
                "input and model access."
            )

            # Do not echo raw provider/network exception strings into the UI:
            # SDK errors can contain request metadata or other sensitive details.
            st.caption(
                "Technical details were withheld to avoid exposing local runtime metadata. "
                "Check the server-side logs for the exception type and request context."
            )


    # ==========================================================
    # RESULT
    # ==========================================================

    if st.session_state.result:

        render_result(
            st.session_state.result
        )

        st.download_button(
            "Download PDF report",
            make_pdf_report(
                st.session_state.result,
                mode
            ),
            file_name="SATARK_security_report.pdf",
            mime="application/pdf",
            use_container_width=True
        )


# ==============================================================
# HISTORY
# ==============================================================

elif st.session_state.page == "History":
    render_history(st.session_state.history, make_pdf_report, risk_label)


elif st.session_state.page == "Challenge":

    # Scam Challenge v2: dedicated CSS is scoped to this page only so the
    # rest of SATARK's UI/UX (Home, Analyze, History, Academy, Classroom)
    # remains completely unchanged.
    st.markdown(SC_CSS, unsafe_allow_html=True)
    st.markdown(
        '<div class="pill" style="margin-bottom:14px">AI SECURITY • GAME • LEARN</div>',
        unsafe_allow_html=True,
    )
    render_scam_challenge()


elif st.session_state.page == "Academy":
    render_academy()


elif st.session_state.page == "Classroom":
    render_classroom(st.session_state.history)


# ==============================================================
# FOOTER
# FOOTER
# ==============================================================

st.markdown(
    '<div class="footer">'
    'SATARK • Smart AI Threat Analysis & Risk Knowledge<br>'
    'AI analysis is advisory. Always verify high-impact security '
    'decisions independently.<br>'
    'Session history is temporary and does not intentionally '
    'preserve submitted source content.'
    '</div>',
    unsafe_allow_html=True
)