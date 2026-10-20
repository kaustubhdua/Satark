# FIRSTLIGHT deterministic detection rule registry

**Registry version:** 1.0.0

FIRSTLIGHT adds stable rule identifiers and version metadata to deterministic findings. These rules are bounded triage heuristics, not a replacement for source-native detections and not proof of compromise. ATT&CK mappings below are candidate investigative context only; they do not establish that a technique occurred.

| Rule ID | Finding | Logic type | Candidate ATT&CK mapping | Key limitation |
|---|---|---|---|---|
| FL-WAZUH-001 | Wazuh source detection alert | Source severity context | None asserted | Preserves Wazuh rule level; does not independently validate the source detection |
| FL-IDENTITY-001 | Unfamiliar successful login | Single-event heuristic | T1078 — Valid Accounts | Novel context is not proof of account compromise |
| FL-MAIL-001 | Mailbox forwarding or rule change | Single-event heuristic | T1114.003 — Email Forwarding Rule | Authorization and destination require independent review |
| FL-IDENTITY-002 | Authentication setting changed | Single-event heuristic | T1098 — Account Manipulation | Does not establish whether the change was unauthorized |
| FL-PHISH-001 | Social-engineering indicators | Keyword heuristic | T1566 — Phishing | Wording alone does not establish phishing or interaction |
| FL-ENDPOINT-001 | Potentially suspicious endpoint activity | Keyword heuristic | T1204.002 — Malicious File | Underlying file/process is not inspected by this rule |
| FL-ENDPOINT-002 | Unusual process ancestry | Process relationship heuristic | T1059 — Command and Scripting Interpreter | Requires endpoint corroboration; unusual ancestry can be legitimate |
| FL-NETWORK-001 | Potentially suspicious network activity | Network indicator heuristic | None asserted | Destination reputation is not independently checked |
| FL-DISCOVERY-001 | Possible data staging | File-path heuristic | T1074 — Data Staged | Archive/path indicators do not prove staging or exfiltration |
| FL-IDENTITY-003 | Follow-on identity session | Temporal correlation | T1078 — Valid Accounts | A session following authentication is normal in many cases |
| FL-GENERIC-000 | No rule matched — analyst review required | No rule match | None asserted | No match is not a safety clearance |

## Change control

- Rule IDs are stable identifiers; the registry version changes when rule semantics or mappings change.
- Every finding must preserve its supporting evidence IDs and disclose its rule limitations.
- A rule change should include positive and negative fixtures, schema validation, and a regression run against representative recorded events.
- ATT&CK mappings should be reviewed against the current MITRE ATT&CK knowledge base before release.
- Do not describe a rule as validated against live telemetry until its source mapping and false-positive/false-negative behavior have been measured on an authorized test environment.
