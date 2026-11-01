"""Offline file-security workspace."""
from datetime import datetime
import json
from pathlib import Path
from io import StringIO
import streamlit as st

from file_guard.engine import scan_stream
from file_guard.history import ScanHistory
from file_guard.intelligence import ThreatIntelligenceStore

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
STORE_PATH = DATA_DIR / "file_guard_intelligence.sqlite3"
HISTORY_PATH = DATA_DIR / "file_guard_history.sqlite3"
RULES_PATH = ROOT / "rules" / "local_file_signatures.yar"

def render_file_guard():
    store = ThreatIntelligenceStore(STORE_PATH)
    history = ScanHistory(HISTORY_PATH)
    stats = store.stats()
    st.markdown('<div class="pill">LOCAL DEVICE SECURITY · OFFLINE FILE GUARD</div>', unsafe_allow_html=True)
    st.title("File Guard")
    st.caption("Static file triage using local fingerprints and signatures. No text extraction, file execution or external reputation calls. Streamlit uploads are received by this app host; run locally for a device-local workflow.")
    cols = st.columns(4)
    cols[0].metric("Historical indicators", f"{stats['total']:,}")
    cols[1].metric("Malicious hashes", f"{stats['malicious']:,}")
    cols[2].metric("Benign hashes", f"{stats['benign']:,}")
    cols[3].metric("Network lookups", "Disabled")

    st.markdown("### Scan received files")
    st.caption("For WhatsApp or Telegram, save or share the attachment into this scanner. Native Android Share-to-SATARK integration is planned; this Streamlit uploader is not an Android file-system integration.")
    uploads = st.file_uploader("Select files", accept_multiple_files=True, key="file_guard_uploads")
    if st.button("Run local scan", type="primary", disabled=not uploads, use_container_width=True):
        results = []
        bar = st.progress(0)
        for i, upload in enumerate(uploads):
            try:
                upload.seek(0)
                item = scan_stream(upload, upload.name, intelligence=store, yara_rules_path=RULES_PATH).to_dict()
                results.append(item)
                history.add(item)
            except Exception as exc:
                results.append({"filename": upload.name, "verdict": "Scan incomplete",
                                "risk_level": "unknown", "signals": [{"code":"SCAN_ERROR","severity":"warning","detail":type(exc).__name__}]})
            bar.progress((i + 1) / len(uploads))
        st.session_state.file_guard_results = results
        bar.empty()
        st.success(f"Completed {len(results)} file inspection(s).")

    results = st.session_state.get("file_guard_results", [])
    if results:
        st.markdown("### Latest inspection results")
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
                with st.expander("Deterministic agent trace"):
                    st.json(item.get("agent_trace", []))
                if item["verdict"] == "No known threat detected":
                    st.info("No match in enabled local checks. This is not proof the file is safe.")
                elif item["verdict"] in {"Known threat", "Signature match", "Suspicious"}:
                    st.error("Do not open or forward this file until independently reviewed.")
        st.download_button(
            "Export latest results (JSON)",
            data=json.dumps(results, ensure_ascii=False, indent=2),
            file_name=f"satark-file-guard-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.markdown("### Local scan history")
    recent = history.list_recent(50)
    if recent:
        st.dataframe(
            [{"Time (UTC)": row["scanned_at"], "File": row["filename"],
              "Type": row["detected_type"], "Verdict": row["verdict"],
              "Risk": row["risk_level"], "SHA-256": row["sha256"]} for row in recent],
            use_container_width=True, hide_index=True,
        )
        left, right = st.columns(2)
        left.download_button("Export history (JSON)", json.dumps(recent, ensure_ascii=False, indent=2),
                             file_name="satark-file-guard-history.json", mime="application/json",
                             use_container_width=True)
        if right.button("Clear local history", use_container_width=True):
            history.clear()
            st.rerun()
    else:
        st.caption("No scans have been recorded on this installation yet.")

    st.markdown("### Import a historical intelligence snapshot")
    st.caption("Manual import only. CSV columns: sha256,label; optional family,dataset_date. No live feed is queried.")
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
        "- The scanner does not execute, unpack, preview, forward to third-party providers or delete files. Streamlit sends uploaded bytes to its host.\n"
        "- History stores filenames, hashes, verdicts and signals, not file bytes. Use localhost for device-local storage.\n"
        "- Historical exact-hash matching misses modified and previously unseen malware. Unknown is not safe.\n"
        "- Android background monitoring and native Share-to-SATARK integration are not implemented yet."
    )
