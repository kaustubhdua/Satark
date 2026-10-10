"""FIRSTLIGHT incident command UI embedded in SATARK."""
from __future__ import annotations

import json
import streamlit as st

from firstlight_engine import (
    append_audit,
    apply_simulated_response,
    create_demo_case,
    investigate_case,
    seal_evidence,
    verify_audit_chain,
    verify_evidence,
    sha256_record,
)
from firstlight_ingest import IngestError, detect_event_patterns, ingest_event_artifact


def _init_firstlight_state() -> None:
    defaults = {
        "firstlight_case": None,
        "firstlight_evidence": [],
        "firstlight_audit": [],
        "firstlight_investigation": None,
        "firstlight_action_log": [],
        "firstlight_demo_seeded": False,
        "firstlight_import_result": None,
        "firstlight_import_findings": [],
        "firstlight_import_report_json": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _seed_demo() -> None:
    case = create_demo_case()
    evidence = [seal_evidence(event) for event in case["events"]]
    audit = []
    audit = append_audit(audit, "case_created", "demo_orchestrator", {"case_id": case["case_id"]})
    for item in evidence:
        audit = append_audit(audit, "evidence_collected", "evidence_agent", {
            "evidence_id": item["evidence_id"], "sha256": item["sha256"]
        })
    st.session_state.firstlight_case = case
    st.session_state.firstlight_evidence = evidence
    st.session_state.firstlight_audit = audit
    st.session_state.firstlight_investigation = None
    st.session_state.firstlight_action_log = []
    st.session_state.firstlight_demo_seeded = True


def render_firstlight() -> None:
    _init_firstlight_state()
    st.markdown(
        '<div class="workspace-eyebrow">SATARK / FIRSTLIGHT INCIDENT COMMAND</div>'
        '<h1 style="margin-bottom:.2rem">Every second matters. Every piece of evidence counts.</h1>'
        '<p style="color:var(--text-secondary,#94a3b8);max-width:850px">Preserve artifacts, correlate suspicious activity, inspect evidence integrity and review proposed response actions. The built-in training case is fictional; optional JSON/CSV imports are parsed locally and remain in this session.</p>',
        unsafe_allow_html=True,
    )
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.markdown("### Incident workspace")
        st.write("Open the account-compromise training case to review the investigation workflow.")
        if st.button("Open / reset training case", type="primary", use_container_width=True, key="fl_seed_demo"):
            _seed_demo()
            st.rerun()
    with right:
        st.markdown("### Workflow status")
        if st.session_state.firstlight_case:
            st.success("Training case loaded")
            st.caption(f"Case ID · {st.session_state.firstlight_case['case_id']}")
        else:
            st.info("No case loaded. Open the training case to begin.")
        st.caption("No real endpoint collection, network blocking or account changes are performed.")

    with st.container(border=True):
        st.markdown("### Import event evidence")
        st.write("Import a JSON event array or CSV with timestamp, source, kind and summary columns. Files are parsed locally; imported text is treated as untrusted data and is not sent to an AI provider.")
        st.caption("Limits: 5 MiB per artifact, 10,000 records, 4,096 characters per text field. Imported data remains in the current session only.")
        upload = st.file_uploader("Choose event file", type=["json", "csv"], key="fl_event_upload")
        if upload is not None and st.button("Validate and analyze import", type="primary", key="fl_import_run"):
            st.session_state.firstlight_import_result = None
            st.session_state.firstlight_import_findings = []
            st.session_state.firstlight_import_report_json = None
            try:
                imported = ingest_event_artifact(upload.getvalue(), upload.name)
                st.session_state.firstlight_import_result = imported
                st.session_state.firstlight_import_findings = detect_event_patterns(imported["events"])
                st.session_state.firstlight_audit = append_audit(
                    st.session_state.firstlight_audit,
                    "event_artifact_imported",
                    "session_operator",
                    {
                        "filename": imported["filename"],
                        "artifact_sha256": imported["artifact_sha256"],
                        "accepted_records": imported["record_count"],
                        "rejected_records": imported["rejected_count"],
                    },
                )
                st.rerun()
            except IngestError as exc:
                st.error(str(exc))
            except Exception:
                st.error("The artifact could not be processed. No content was sent to an external provider.")
        imported = st.session_state.firstlight_import_result
        if imported:
            st.markdown("#### Artifact provenance")
            st.code(json.dumps({
                "filename": imported["filename"],
                "format": imported["format"],
                "artifact_bytes": imported["artifact_bytes"],
                "artifact_sha256": imported["artifact_sha256"],
                "accepted_records": imported["record_count"],
                "rejected_records": imported["rejected_count"],
            }, indent=2), language="json")
            st.caption("The artifact hash identifies the exact uploaded bytes; it does not prove the source is truthful or authenticate the collector.")
            if imported["warnings"]:
                st.markdown("#### Normalization warnings")
                for warning in imported["warnings"]:
                    st.warning(warning)
            if imported["errors"] and st.checkbox(
                f"Show rejected records ({imported['rejected_count']})",
                key="fl_show_rejected_rows",
            ):
                st.markdown("#### Rejected records")
                st.dataframe(imported["errors"], use_container_width=True, hide_index=True)
            if st.checkbox(
                f"Show normalized event inventory ({imported['record_count']} records)",
                key="fl_show_normalized_events",
            ):
                st.markdown("#### Normalized events")
                st.dataframe([
                    {
                        "Event ID": event["event_id"],
                        "Timestamp (UTC)": event["timestamp"],
                        "Source": event["source"],
                        "Kind": event["kind"],
                        "Summary": event["summary"],
                        "Normalized record SHA-256": sha256_record(event),
                    }
                    for event in imported["events"]
                ], use_container_width=True, hide_index=True)
            st.markdown("#### Explainable detections")
            findings = st.session_state.firstlight_import_findings
            if findings:
                for finding in findings:
                    with st.container(border=True):
                        st.markdown(f"**{finding['finding_id']} · {finding['title']}**")
                        st.write(finding["explanation"])
                        st.caption(f"Rule: {finding['rule_id']} · Severity: {finding['severity']} · Confidence: {finding['confidence']} · Evidence: {', '.join(finding['evidence_ids'])}")
            else:
                st.info("No configured rule matched this artifact. This does not establish that the events are benign.")
            if st.button("Prepare import report", key="fl_prepare_import_report"):
                import_report = {
                    "provenance": {key: imported[key] for key in ("filename", "format", "artifact_sha256", "artifact_bytes", "record_count", "rejected_count")},
                    "events": imported["events"],
                    "normalized_record_sha256": {event["event_id"]: sha256_record(event) for event in imported["events"]},
                    "findings": findings,
                    "errors": imported["errors"],
                    "warnings": imported["warnings"],
                    "limitations": "Deterministic prototype rules only; no claim of completeness or proof of malicious activity.",
                }
                st.session_state.firstlight_import_report_json = json.dumps(import_report, indent=2, ensure_ascii=False)
            if st.session_state.firstlight_import_report_json:
                st.download_button(
                    "Download prepared import report (JSON)",
                    data=st.session_state.firstlight_import_report_json,
                    file_name="firstlight-import-report.json",
                    mime="application/json",
                    key="fl_import_export",
                )


    case = st.session_state.firstlight_case
    if not case:
        with st.container(border=True):
            st.markdown("#### Investigation workflow")
            st.markdown("- Evidence records are hashed independently of AI.")
            st.markdown("- Findings link to evidence IDs and label uncertainty.")
            st.markdown("- A hash mismatch is flagged as possible tampering.")
            st.markdown("- Consequential response proposals require an explicit approval before simulation.")
        return

    evidence = st.session_state.firstlight_evidence
    investigation = st.session_state.firstlight_investigation
    audit = st.session_state.firstlight_audit
    valid_count = sum(verify_evidence(item)["valid"] for item in evidence)
    a, b, c, d = st.columns(4)
    a.metric("Severity", case["severity"].upper())
    b.metric("Evidence records", len(evidence))
    c.metric("Integrity verified", f"{valid_count}/{len(evidence)}")
    d.metric("Audit chain", "VALID" if verify_audit_chain(audit) else "INVALID")

    active_workspace = st.selectbox(
        "Investigation workspace",
        ["Incident", "Evidence Integrity", "Investigation", "Response Center", "Audit Trail"],
        key="fl_workspace_section",
        help="Only the selected workspace is rendered, keeping large investigations responsive.",
    )

    if active_workspace == "Incident":
        st.markdown(f"### {case['title']}")
        st.info(case["scenario"])
        st.markdown("#### Collection priority")
        st.markdown("1. Preserve volatile endpoint and connection context where authorized.")
        st.markdown("2. Capture identity, endpoint, network and file artifacts with source timestamps.")
        st.markdown("3. Verify hashes and document gaps before interpreting the evidence.")
        if st.checkbox("Show event inventory", value=False, key="fl_show_case_inventory"):
            st.dataframe([
                {"Event ID": e["event_id"], "Time (UTC)": e["timestamp"], "Source": e["source"], "Type": e["kind"], "Summary": e["summary"]}
                for e in case["events"]
            ], use_container_width=True, hide_index=True)

    if active_workspace == "Evidence Integrity":
        st.markdown("### Evidence Integrity Challenge")
        st.write("Select an evidence record and deliberately alter its stored summary. Verification recalculates the hash; it does not ask the AI whether the record changed.")
        labels = [f"{item['evidence_id']} · {item['record']['summary']}" for item in evidence]
        selected_label = st.selectbox("Evidence record", labels, key="fl_tamper_select")
        selected_id = selected_label.split(" · ", 1)[0]
        item = next(row for row in evidence if row["evidence_id"] == selected_id)
        check = verify_evidence(item)
        st.code(json.dumps({"evidence_id": check["evidence_id"], "expected_sha256": check["expected_sha256"], "actual_sha256": check["actual_sha256"], "status": check["status"]}, indent=2), language="json")
        if check["valid"]:
            st.success("Record matches its stored baseline hash.")
        else:
            st.error("HASH MISMATCH — possible tampering detected. Treat this record as untrusted until independently resolved.")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Tamper with selected record", key="fl_tamper", use_container_width=True):
                item["record"]["summary"] = item["record"].get("summary", "") + " [INTEGRITY CHALLENGE]"
                st.session_state.firstlight_audit = append_audit(
                    st.session_state.firstlight_audit, "integrity_mismatch_injected",
                    "session_operator", {"evidence_id": selected_id, "purpose": "controlled integrity challenge"}
                )
                st.rerun()
        with col2:
            if st.button("Restore from original synthetic fixture", key="fl_restore", use_container_width=True):
                _seed_demo()
                st.rerun()
        st.caption("Restoring reloads the original training case and clears the current response-action log.")

    if active_workspace == "Investigation":
        st.markdown("### Coordinated investigation")
        if st.button("Run investigation workflow", type="primary", key="fl_investigate"):
            result = investigate_case(case, evidence)
            st.session_state.firstlight_investigation = result
            st.session_state.firstlight_audit = append_audit(
                st.session_state.firstlight_audit, "investigation_completed",
                "incident_orchestrator", {"case_id": case["case_id"], "finding_count": len(result["findings"])}
            )
            st.rerun()
        if investigation:
            st.markdown("#### Specialized agent run")
            st.dataframe(investigation["agents"], use_container_width=True, hide_index=True)
            st.markdown("#### Findings")
            for finding in investigation["findings"]:
                with st.container(border=True):
                    st.markdown(f"**{finding['finding_id']} · {finding['title']}**")
                    st.write(finding["explanation"])
                    st.caption(f"Severity: {finding['severity']} · Confidence: {finding['confidence']} · State: {finding['state']} · Evidence: {', '.join(finding['evidence_ids']) or 'none'}")
            if st.checkbox("Show reconstructed timeline", value=True, key="fl_show_investigation_timeline"):
                st.dataframe(investigation["timeline"], use_container_width=True, hide_index=True)
            st.markdown("#### Evidence gaps")
            for gap in investigation["gaps"]:
                st.warning(gap)
            report = {
                "case": case,
                "integrity": [verify_evidence(item) for item in evidence],
                "investigation": investigation,
                "audit_chain_valid": verify_audit_chain(st.session_state.firstlight_audit),
                "audit": st.session_state.firstlight_audit,
                "response_log": st.session_state.firstlight_action_log,
                "notice": "Training case only; this workflow does not perform live response or provide forensic certification.",
            }
            st.download_button(
                "Export FIRSTLIGHT incident report (JSON)",
                data=json.dumps(report, indent=2, ensure_ascii=False),
                file_name=f"{case['case_id'].lower()}-report.json",
                mime="application/json",
                key="fl_export_json",
            )
        else:
            st.info("Run the workflow to generate evidence-linked findings, a timeline and explicit investigation gaps.")

    if active_workspace == "Response Center":
        st.markdown("### Human approval gate")
        st.write("Every action below is simulated. Approval is checked server-side in the workflow function; no real system is touched.")
        if not investigation:
            st.info("Run the investigation first to load response proposals.")
        else:
            for proposal in investigation["response_proposals"]:
                with st.container(border=True):
                    st.markdown(f"**{proposal['action_id']} · {proposal['title']}**")
                    st.write(proposal["impact"])
                    st.caption(f"Risk: {proposal['risk']} · Status: {proposal['status']}")
                    approver = st.text_input("Approver / reviewer", value="Incident reviewer", key=f"fl_approver_{proposal['action_id']}")
                    approve_col, reject_col = st.columns(2)
                    with approve_col:
                        if st.button("Approve & simulate", key=f"fl_approve_{proposal['action_id']}", type="primary", use_container_width=True):
                            updated, log = apply_simulated_response(investigation["response_proposals"], proposal["action_id"], True, approver.strip() or "Unnamed reviewer")
                            investigation["response_proposals"] = updated
                            st.session_state.firstlight_action_log.append(log)
                            st.session_state.firstlight_audit = append_audit(st.session_state.firstlight_audit, "response_approved_and_simulated", approver.strip() or "Unnamed reviewer", log)
                            st.rerun()
                    with reject_col:
                        if st.button("Reject action", key=f"fl_reject_{proposal['action_id']}", use_container_width=True):
                            updated, log = apply_simulated_response(investigation["response_proposals"], proposal["action_id"], False, approver.strip() or "Unnamed reviewer")
                            investigation["response_proposals"] = updated
                            st.session_state.firstlight_action_log.append(log)
                            st.session_state.firstlight_audit = append_audit(st.session_state.firstlight_audit, "response_rejected", approver.strip() or "Unnamed reviewer", log)
                            st.rerun()
            if st.session_state.firstlight_action_log:
                st.markdown("#### Response action log")
                st.dataframe(st.session_state.firstlight_action_log, use_container_width=True, hide_index=True)


    if active_workspace == "Audit Trail":
        st.markdown("### Hash-chained audit trail")
        chain_valid = verify_audit_chain(st.session_state.firstlight_audit)
        if chain_valid:
            st.success("Audit chain verifies against its first entry.")
        else:
            st.error("Audit chain verification failed. The chain may have been altered.")
        st.dataframe(st.session_state.firstlight_audit, use_container_width=True, hide_index=True)
        st.caption("The audit chain is session-scoped and is not independently anchored or durable. Sensitive operational use requires protected persistence and access controls.")
