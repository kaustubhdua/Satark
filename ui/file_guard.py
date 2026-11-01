"""Offline file-security workspace."""
from pathlib import Path
from io import StringIO
import streamlit as st

from file_guard.engine import scan_stream
from file_guard.intelligence import ThreatIntelligenceStore

ROOT = Path(__file__).resolve().parents[1]
STORE_PATH = ROOT / "data" / "file_guard_intelligence.sqlite3"
RULES_PATH = ROOT / "rules" / "local_file_signatures.yar"

def render_file_guard():
    store = ThreatIntelligenceStore(STORE_PATH)
    stats = store.stats()
    st.markdown('<div class="pill">LOCAL DEVICE SECURITY · OFFLINE FILE GUARD</div>', unsafe_allow_html=True)
    st.title("File Guard")
    st.caption("Inspect fingerprints, file headers and locally installed signatures. No document text extraction, file execution or external reputation calls. Streamlit uploads go to the app host; use localhost for private scanning.")
    cols = st.columns(4)
    cols[0].metric("Historical indicators", f"{stats['total']:,}")
    cols[1].metric("Malicious hashes", f"{stats['malicious']:,}")
    cols[2].metric("Benign hashes", f"{stats['benign']:,}")
    cols[3].metric("Network lookups", "Disabled")

    st.markdown("### Scan received files")
    st.caption("Choose files saved from WhatsApp, Telegram, Downloads or another app. Android access is limited to files explicitly shared or exposed by the system picker.")
    uploads = st.file_uploader("Select files", accept_multiple_files=True, key="file_guard_uploads")
    if st.button("Run local scan", type="primary", disabled=not uploads, use_container_width=True):
        results = []
        bar = st.progress(0)
        for i, upload in enumerate(uploads):
            try:
                upload.seek(0)
                results.append(scan_stream(upload, upload.name, intelligence=store, yara_rules_path=RULES_PATH).to_dict())
            except Exception as exc:
                results.append({"filename": upload.name, "verdict": "Scan incomplete",
                                "risk_level": "unknown", "signals": [{"code":"SCAN_ERROR","severity":"warning","detail":type(exc).__name__}]})
            bar.progress((i + 1) / len(uploads))
        st.session_state.file_guard_results = results
        bar.empty()

    results = st.session_state.get("file_guard_results", [])
    if results:
        st.markdown("### Results")
        for item in results:
            with st.container(border=True):
                row = st.columns([4, 1])
                row[0].markdown(f"**{item['filename']}**")
                row[1].markdown(f"**{item['verdict']}**")
                facts = st.columns(3)
                facts[0].caption("Detected type: " + item.get("detected_type", "—"))
                facts[1].caption("Risk: " + item.get("risk_level", "unknown").upper())
                facts[2].caption("Size: " + f"{item.get('size_bytes', 0):,} bytes")
                if item.get("sha256"):
                    st.code(item["sha256"])
                for signal in item.get("signals", []):
                    st.write(f"• **{signal['code']}** — {signal['detail']}")
                if item["verdict"] == "No known threat detected":
                    st.info("No match in the enabled local checks. This is not proof the file is safe.")
                elif item["verdict"] in {"Known threat", "Signature match", "Suspicious"}:
                    st.error("Do not open or forward this file until independently reviewed.")

    st.markdown("### Import a historical intelligence snapshot")
    st.caption("Manual, offline import only. CSV columns: sha256,label; optional family,dataset_date. No live feed is queried.")
    with st.expander("Dataset import"):
        st.code("sha256,label,family,dataset_date\n<64-char-hash>,malicious,<family>,<YYYY-MM-DD>", language="csv")
        source = st.text_input("Dataset source / snapshot ID", key="file_guard_source")
        csv_file = st.file_uploader("Historical hash CSV", type=["csv"], key="file_guard_csv")
        if st.button("Import snapshot", disabled=not csv_file or not source.strip()):
            try:
                outcome = store.import_csv(StringIO(csv_file.getvalue().decode("utf-8-sig")), source.strip())
                st.success(f"Imported {outcome['inserted']:,}; duplicates {outcome['skipped']:,}; invalid rows {outcome['rejected']:,}.")
                st.rerun()
            except Exception as exc:
                st.error(f"Import rejected: {type(exc).__name__}: {exc}")

    st.markdown("### Privacy and coverage")
    st.markdown(
        "- Raw bytes are read only for hashing, file signatures and optional YARA byte-pattern matching. No document text is extracted.\n"
        "- Files are not executed, unpacked, previewed, uploaded or automatically deleted.\n"
        "- Historical exact-hash matching misses modified and previously unseen malware.\n"
        "- Unknown means no known indicator matched, not that the file is safe.\n"
        "- Android background monitoring and native Share-to-SATARK integration are a separate native-app milestone."
    )
