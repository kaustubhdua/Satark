"""Static contracts for SATARK's modular UI and layout safeguards."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "satark.py").read_text(encoding="utf-8")
CSS = (ROOT / "styles.css").read_text(encoding="utf-8")
POLISH_CSS = (ROOT / "ui-polish.css").read_text(encoding="utf-8")
RADAR = (ROOT / "radar_background.py").read_text(encoding="utf-8")
STEPPER = (ROOT / "stepper_component.py").read_text(encoding="utf-8")
HISTORY = (ROOT / "ui/history.py").read_text(encoding="utf-8")
LEARNING = (ROOT / "ui/learning.py").read_text(encoding="utf-8")
HOME = (ROOT / "ui/home.py").read_text(encoding="utf-8")
NAV = (ROOT / "ui/navigation.py").read_text(encoding="utf-8")
FIRSTLIGHT = (ROOT / "ui/firstlight.py").read_text(encoding="utf-8")
LOADING = (ROOT / "ui/loading.py").read_text(encoding="utf-8")


class UIContractTests(unittest.TestCase):
    def test_entry_point_uses_modular_surfaces(self):
        for expected in (
            "from ui.home import render_home",
            "from ui.navigation import render_sidebar",
            "from ui.results import render_threat_analysis, render_verification_sources",
            "from ui.history import render_history",
            "from ui.learning import render_academy, render_classroom",
        ):
            self.assertIn(expected, APP)
        self.assertLess(len(APP), 55000)

    def test_result_renderers_receive_required_contract_arguments(self):
        self.assertIn("render_threat_analysis(result, THREAT_CHECKS)", APP)
        self.assertIn(
            "render_verification_sources(result, OFFICIAL_VERIFICATION_SOURCES)",
            APP,
        )

    def test_layout_guardrails_exist(self):
        for expected in (
            ".home-actions{",
            ".sr-only{",
            ".report-section{",
            ".workflow-grid{",
            "overflow-wrap:anywhere",
            "prefers-reduced-motion:reduce",
            "overflow-x:hidden",
        ):
            self.assertIn(expected, CSS)

    def test_learning_and_history_are_actionable(self):
        for expected in ("history_query", "history_mode_filter", "classroom_export", "academy_to_challenge"):
            self.assertIn(expected, HISTORY + LEARNING)

    def test_home_is_not_dependent_on_external_browser_runtimes(self):
        self.assertNotIn("esm.sh", RADAR)
        self.assertNotIn("esm.sh", STEPPER)

    def test_evidence_coverage_review_is_integrated(self):
        self.assertIn("render_evidence_review(result)", APP)
        self.assertIn("render_investigation_timeline(result)", APP)
        self.assertIn("def render_investigation_timeline", (ROOT / "ui/results.py").read_text(encoding="utf-8"))
        self.assertIn("investigation-stages", POLISH_CSS)
        self.assertIn("build_evidence_review", (ROOT / "ui/results.py").read_text(encoding="utf-8"))
        self.assertIn("evidence-review", CSS)

    def test_home_prioritizes_the_core_product_without_vanity_metrics(self):
        self.assertIn("Pause the panic.", HOME)
        self.assertIn("View example report", HOME)
        self.assertNotIn("guided sample report", HOME)
        self.assertIn("OBSERVABLE SIGNALS", HOME)
        self.assertNotIn("home-stats", HOME)

    def test_native_streamlit_theme_matches_custom_design_system(self):
        config = (ROOT / ".streamlit/config.toml").read_text(encoding="utf-8")
        self.assertIn('primaryColor = "#a9a6ff"', config)
        self.assertIn('backgroundColor = "#080b12"', config)
        self.assertIn('secondaryBackgroundColor = "#0e1421"', config)
        self.assertIn('textColor = "#f2f6ff"', config)
        self.assertIn('showErrorDetails = "none"', config)
        self.assertIn("maxUploadSize = 50", config)

    def test_video_limit_matches_host_upload_budget(self):
        config = (ROOT / "config.py").read_text(encoding="utf-8")
        video = (ROOT / "video_processing.py").read_text(encoding="utf-8")
        self.assertIn("MAX_UPLOAD_SIZE_MB = 50", config)
        self.assertIn("MAX_UPLOAD_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024", config)
        self.assertIn("MAX_VIDEO_BYTES = MAX_UPLOAD_BYTES", video)
        self.assertIn("max_upload_size=50", APP)
        self.assertNotIn("max_upload_size=200", APP)

    def test_active_scanner_has_a_distinct_native_control_state(self):
        self.assertIn('type="primary" if active else "secondary"', APP)
        self.assertIn(".scanner.active", CSS)

    def test_investigation_screen_has_contextual_workflow_guidance(self):
        self.assertIn("mode_details = {", APP)
        self.assertIn("selected-workflow", APP)
        self.assertIn("Video & clips", APP)
        self.assertIn(".selected-workflow{", CSS)
        self.assertIn("@media(max-width:680px)", CSS)

    def test_provider_check_does_not_claim_success_when_discovery_fails(self):
        self.assertIn("if not available:", NAV)
        self.assertIn("Could not verify provider access", NAV)
        self.assertIn("st.session_state.text_model = None", NAV)

    def test_primary_navigation_stays_focused(self):
        self.assertIn('("Home", "Overview")', NAV)
        self.assertIn('("Analyze", "Investigate")', NAV)
        self.assertIn('("History", "Session history")', NAV)
        self.assertIn('Learn & practice', NAV)
        self.assertIn('("Challenge", "Scam Challenge")', NAV)
        self.assertIn('("Academy", "SATARK Academy")', NAV)
        self.assertIn('("Classroom", "Classroom Mode")', NAV)

    def test_visual_polish_is_local_accessible_and_motion_sensitive(self):
        self.assertIn('with_name("ui-polish.css")', RADAR)
        self.assertIn("prefers-reduced-motion:reduce", POLISH_CSS)
        self.assertIn(".workspace-hero::after", POLISH_CSS)
        self.assertIn("mask-image:", POLISH_CSS)
        self.assertNotIn("https://", POLISH_CSS)

    def test_firstlight_import_tables_and_report_generation_are_opt_in(self):
        self.assertIn("Show normalized event inventory", FIRSTLIGHT)
        self.assertIn("Show rejected records", FIRSTLIGHT)
        self.assertIn("Prepare import report", FIRSTLIGHT)
        self.assertIn("firstlight_import_report_json", FIRSTLIGHT)
        self.assertIn("Download prepared import report (JSON)", FIRSTLIGHT)

    def test_firstlight_renders_only_the_selected_workspace(self):
        self.assertIn('active_workspace = st.selectbox(', FIRSTLIGHT)
        for section in ("Incident", "Evidence Integrity", "Investigation", "Response Center", "Audit Trail"):
            self.assertIn(section, FIRSTLIGHT)
        self.assertNotIn("st.tabs(", FIRSTLIGHT)

    def test_intro_loading_screen_is_branded_accessible_and_nonblocking(self):
        self.assertIn("from ui.loading import render_intro_loader", APP)
        self.assertLess(APP.index("render_intro_loader()"), APP.index("api_key, role = render_sidebar("))
        for expected in (
            "SATARK",
            "FIRSTLIGHT",
            "satark-arcade-shell",
            "satark-pixel-mascot",
            "satark-progress-segment",
            "satark-tip-card",
            "Pause before you click. Verify the sender and destination first.",
            "hostWindow.setInterval(() => {",
            "st.iframe(",
            "const hostWindow = window.parent;",
            "const doc = hostWindow.document;",
            'setAttribute("role", "dialog")',
            'setAttribute("aria-modal", "true")',
            "aria-live",
            "prefers-reduced-motion: reduce",
            "Skip intro",
            "overlay.remove()",
            "hostWindow.setTimeout(dismiss, reducedMotion ? 900 : 2600)",
            'event.key === "Escape"',
            'skipButton.focus({preventScroll: true})',
            "previousFocus.focus({preventScroll: true})",
        ):
            self.assertIn(expected, LOADING)
        self.assertIn('st.session_state.get("_satark_intro_seen", False)', LOADING)
        self.assertIn('st.session_state["_satark_intro_seen"] = True', LOADING)
        self.assertNotIn("components.html", LOADING)
        self.assertNotIn("https://", LOADING)

    def test_app_does_not_reference_missing_analysis_constants(self):
        self.assertIn("THREAT_CHECKS, OFFICIAL_VERIFICATION_SOURCES", APP)


if __name__ == "__main__":
    unittest.main()
