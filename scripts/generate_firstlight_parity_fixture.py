#!/usr/bin/env python3
"""Generate web/tests/fixtures/firstlight-parity.json from the Python FIRSTLIGHT engine.

The browser-only workspace runs a JavaScript port of the engine (web/src/lib/firstlight-engine.mjs).
Both test suites compare against this single golden file, so any divergence in rules, hashing, timestamp
handling or ordering fails CI. Regenerate with:  python scripts/generate_firstlight_parity_fixture.py
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from firstlight_engine import investigate_case, prioritize_evidence, sha256_record, verify_evidence  # noqa: E402
from firstlight_rules import rule_metadata, _RULES  # noqa: E402

FIXTURE = ROOT / "web" / "tests" / "fixtures" / "firstlight-parity.json"
# Every timestamp in the investigation cases is far in the past, so recency scoring is 0 and results do
# not depend on the wall clock. Recency is covered separately with an explicit `now`.
NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def env(event_id, kind, source, summary, timestamp, details=None, **extra):
    record = {"event_id": event_id, "timestamp": timestamp, "source": source, "kind": kind, "summary": summary,
              "details": details if details is not None else {}}
    record.update(extra)
    return {"evidence_id": event_id, "record": record, "sha256": sha256_record(record), "integrity_status": "verified"}


def tampered(item):
    item = json.loads(json.dumps(item))
    item["record"]["summary"] += " [edited after sealing]"
    return item


def build_cases():
    chain = [
        env("E1", "authentication", "Identity provider", "Successful login from a new device", "2025-03-01T09:00:00Z",
            {"account": "ana@example.org", "result": "success", "novel_source": True}),
        env("E2", "session", "Identity provider", "Session established", "2025-03-01T09:01:00+00:00", {"account": "ana@example.org"}),
        env("E3", "message", "Mail gateway", "URGENT: confirm your password via lookalike-bank.invalid", "2025-03-01T08:50:00Z"),
        env("E4", "email", "Mail gateway", "Mailbox rule created: inbox forwarding to outside address", "2025-03-01T09:05:00Z"),
        env("E5", "audit", "Identity provider", "MFA method changed for the account", "2025-03-01T09:10:00Z"),
        env("E6", "process", "EDR", "Process started", "2025-03-01T09:20:00Z",
            {"host": "ws-01", "parent": "OUTLOOK.EXE", "process": "powershell.exe"}),
        env("E7", "process", "EDR", "suspicious process launched from attachment path", "2025-03-01T09:21:00Z", {"host": "ws-02"}),
        env("E8", "connection", "Firewall", "Outbound connection", "2025-03-01T09:30:00Z", {"host": "ws-01", "destination": "C2.EXAMPLE.invalid"}),
        env("E9", "file", "EDR", "File created", "2025-03-01T09:40:00Z", {"path": "C:\\Users\\ana\\Temp\\q1.zip"}),
        env("E10", "filesystem", "EDR", "Archive staged for upload", "2025-03-01T09:41:00Z"),
        env("E11", "process", "EDR", "Rule hit", "2025-03-01T09:22:00Z", {"rule": "unusual_parent_child"}),
        env("E12", "network", "Proxy", "Request logged", "2025-03-01T09:31:00Z", {"disposition": "suspicious"}),
    ]
    wazuh = []
    for index, level in enumerate([6, 7, 9, 10, 11, 12, 16, 17, "12", " 8 ", "x", True, 8.5, None, 0]):
        wazuh.append(env(f"W{index}", "log", "Wazuh", f"Alert {index}", "2025-04-01T00:00:00Z",
                         {"provider": "wazuh-indexer", "rule_level": level, "rule_groups": ["authentication_failed", 5, "MFA"]}))
    wazuh.append(env("W-other", "log", "Wazuh", "Other provider", "2025-04-01T00:00:00Z", {"provider": "elastic", "rule_level": 14}))
    timestamps = [
        env("T1", "authentication", "IdP", "Successful login unfamiliar", "2025-05-01T10:00:00", {"account": "bo", "result": "Success"}),
        env("T2", "session", "IdP", "Session", "2025-05-01T12:30:00+02:00", {"account": "bo"}),
        env("T3", "session", "IdP", "Session before login", "2025-05-01T09:59:59.999999Z", {"account": "bo"}),
        env("T4", "login", "IdP", "login successful new browser", "2025-05-01", {"account": "cy"}),
        env("T5", "session", "IdP", "Session invalid time", "not-a-time", {"account": "cy"}),
        env("T6", "process", "EDR", "proc", "2025-05-01T10:00:00.5+00:00", {"host": "h"}),
        env("T7", "network", "FW", "suspicious flow", "2025-05-01T10:00:01Z", {"host": "h"}),
        env("T8", "network", "FW", "suspicious flow, other host", "2025-05-01T10:00:02Z", {"host": "other"}),
        env("T9", "session", "IdP", "Session leap day", "2024-02-29T10:00:00Z", {}),
        env("T10", "session", "IdP", "Session bad day", "2025-02-30T10:00:00Z", {}),
    ]
    unicode_case = [
        env("U1", "message", "Mail", "Urgent: 名前 😀 password", "2025-06-01T00:00:00Z", {"k\uff5e": 1, "k\U0001F600": 2, "é": "ü", "n": None, "t": True}),
        env("U2", "file", "EDR", "Dossier ÀÉÎ", "2025-06-01T00:00:01Z", {"path": "/TMP/Données.GZ"}),
    ]
    odd = [
        env("D1", "login", "IdP", "login successful unfamiliar", "2025-07-01T00:00:00Z", {"account": "z", "result": "success"}),
        env("D1", "session", "IdP", "second record with the same id", "2025-07-01T00:00:05Z", {"account": "z"}),
        {"evidence_id": "D2", "record": "not-a-dict", "sha256": "x"},
        {"evidence_id": "D3", "record": {"event_id": "D3", "kind": "file", "summary": "x", "details": "text"}, "sha256": ""},
        "not-an-envelope",
    ]
    swapped = env("S1", "authentication", "IdP", "login new device success", "2025-08-01T00:00:00Z", {"result": "success", "novel_source": True})
    swapped["evidence_id"] = "S-other"
    cases = {
        "account-takeover-chain": chain,
        "wazuh-levels": wazuh,
        "timestamps-and-correlation": timestamps,
        "unicode-and-key-ordering": unicode_case,
        "no-rule-matched": [env("N1", "note", "Analyst", "Routine maintenance window", "2025-09-01T00:00:00Z")],
        "tampered-and-swapped": [tampered(chain[0]), chain[3], swapped],
        "odd-shapes": odd,
        "empty": [],
    }
    out = []
    for name, evidence in cases.items():
        result = investigate_case({"case_id": f"case-{name}", "title": name}, evidence)
        verdicts = [verify_evidence(item) for item in evidence]
        out.append({"name": name, "case": {"case_id": f"case-{name}", "title": name}, "evidence": evidence,
                    "expected": result, "expected_verdicts": verdicts})
    return out


def build_priority_cases():
    recent = [
        env("R1", "process", "EDR", "suspicious activity", "2026-11-20T11:55:00Z"),
        env("R2", "login", "IdP", "Login", "2026-11-20T11:20:00Z"),
        env("R3", "log", "Syslog", "entry", "2026-11-20T08:00:00Z"),
        env("R4", "file", "EDR", "file", "2026-11-19T20:00:00Z"),
        env("R5", "memory", "EDR", "dump", "2026-11-20T12:30:00Z"),
        env("R6", "connection", "FW", "x", "2026-11-18T00:00:00Z"),
        tampered(env("R7", "network", "FW", "x", "2026-11-20T11:59:00Z")),
    ]
    return [{"name": "recency", "now": NOW.isoformat().replace("+00:00", "Z"), "evidence": recent,
             "expected": prioritize_evidence(recent, now=NOW)}]


def build():
    rules = {title: rule_metadata(title) for title in _RULES}
    rules["__unmapped__"] = rule_metadata("not a registered rule")
    return {"generated_by": "scripts/generate_firstlight_parity_fixture.py", "rules": rules,
            "cases": build_cases(), "priority_cases": build_priority_cases()}


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(render(), encoding="utf-8")
    print(f"wrote {FIXTURE.relative_to(ROOT)}")
