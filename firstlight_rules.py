"""Versioned metadata for FIRSTLIGHT's deterministic triage rules.

ATT&CK mappings are candidate investigation context, not proof that a technique
occurred. Every rule is a triage heuristic and must be corroborated against source
telemetry before an analyst makes a conclusion or response decision.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

RULE_VERSION = "1.0.0"

_RULES: dict[str, dict[str, Any]] = {
    "Wazuh source detection alert": {
        "rule_id": "FL-WAZUH-001",
        "attack_techniques": [],
        "logic_type": "source_severity_context",
        "limitations": ["Preserves Wazuh rule severity context; does not independently validate the source detection."],
    },
    "Unfamiliar successful login": {
        "rule_id": "FL-IDENTITY-001",
        "attack_techniques": ["T1078"],
        "logic_type": "single_event_heuristic",
        "limitations": ["A novel login context is not proof of account compromise."],
    },
    "Mailbox forwarding or rule change": {
        "rule_id": "FL-MAIL-001",
        "attack_techniques": ["T1114.003"],
        "logic_type": "single_event_heuristic",
        "limitations": ["The rule or forwarding destination must be independently checked for authorization."],
    },
    "Authentication setting changed": {
        "rule_id": "FL-IDENTITY-002",
        "attack_techniques": ["T1098"],
        "logic_type": "single_event_heuristic",
        "limitations": ["The event does not establish whether the change was unauthorized."],
    },
    "Social-engineering indicators": {
        "rule_id": "FL-PHISH-001",
        "attack_techniques": ["T1566"],
        "logic_type": "keyword_heuristic",
        "limitations": ["Message wording alone does not establish phishing or user interaction."],
    },
    "Potentially suspicious endpoint activity": {
        "rule_id": "FL-ENDPOINT-001",
        "attack_techniques": ["T1204.002"],
        "logic_type": "keyword_heuristic",
        "limitations": ["FIRSTLIGHT has not inspected the underlying file or process in this rule."],
    },
    "Unusual process ancestry": {
        "rule_id": "FL-ENDPOINT-002",
        "attack_techniques": ["T1059"],
        "logic_type": "process_relationship_heuristic",
        "limitations": ["Parent/child process context needs endpoint corroboration; suspicious ancestry can be legitimate."],
    },
    "Potentially suspicious network activity": {
        "rule_id": "FL-NETWORK-001",
        "attack_techniques": [],
        "logic_type": "network_indicator_heuristic",
        "limitations": ["Destination reputation is not independently checked; temporal correlation does not prove causation."],
    },
    "Possible data staging": {
        "rule_id": "FL-DISCOVERY-001",
        "attack_techniques": ["T1074"],
        "logic_type": "file_path_heuristic",
        "limitations": ["File paths and archive names do not prove collection, staging, or exfiltration."],
    },
    "Follow-on identity session": {
        "rule_id": "FL-IDENTITY-003",
        "attack_techniques": ["T1078"],
        "logic_type": "temporal_correlation",
        "limitations": ["A session following authentication is expected in normal activity; verify account and session provenance."],
    },
}

_RULES_BY_ID = {entry["rule_id"]: title for title, entry in _RULES.items()}


def rule_metadata(title: str) -> dict[str, Any]:
    """Return a defensive copy of versioned metadata for a known rule title."""
    entry = _RULES.get(title)
    if entry is None:
        return {
            "rule_id": "FL-UNMAPPED-000",
            "rule_version": RULE_VERSION,
            "rule_source": "FIRSTLIGHT",
            "attack_techniques": [],
            "logic_type": "unmapped",
            "rule_limitations": ["No versioned rule metadata is registered for this finding."],
        }
    return {
        **deepcopy(entry),
        "rule_version": RULE_VERSION,
        "rule_source": "FIRSTLIGHT",
        "rule_limitations": list(entry["limitations"]),
    }


def validate_rule_registry() -> None:
    """Raise if rule identifiers or ATT&CK technique identifiers are malformed."""
    if len(_RULES_BY_ID) != len(_RULES):
        raise ValueError("FIRSTLIGHT rule IDs must be unique")
    for title, entry in _RULES.items():
        if not title or not re.fullmatch(r"FL-[A-Z]+-\d{3}", entry["rule_id"]):
            raise ValueError(f"Invalid FIRSTLIGHT rule entry: {title!r}")
        for technique in entry["attack_techniques"]:
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                raise ValueError(f"Invalid ATT&CK technique ID: {technique}")
