# SATARK File Guard — offline mobile file inspection

## Direction
SATARK is adding an app-oriented, local-first file security workflow. This first milestone adds a bounded Python scanner, a local SQLite hash index and a focused Streamlit workspace. The Python engine is intended to remain the detection source of truth behind a native Android adapter.

## Hard constraints
- No hosted analysis APIs, API keys, cloud lookups, telemetry uploads or live feed polling.
- Use only a traceable historical dataset snapshot explicitly imported by the operator.
- Do not read chat/message content, extract document text, OCR images or render media.
- Do not execute, install, preview, unpack, delete or quarantine files.
- Raw bytes must still be read for SHA-256, magic-byte identification and optional YARA pattern matching. “Does not read content” means no semantic/content extraction, not zero byte access.
- “No known threat detected” is not a safety guarantee.

## Agent design reference
Inspired by the routing, gated workflow, human approval and trace-based evaluation patterns catalogued in NirDiamant/GenAI_Agents. The implementation deliberately does not adopt the repository's hosted-model/API notebooks or add a runtime dependency. SATARK uses deterministic specialist agents:
1. Router: file signature and extension identify relevant checks.
2. Hash specialist: exact SHA-256 lookup against the local historical index.
3. Signature specialist: optional local YARA rules.
4. Metadata specialist: extension/signature mismatch and double-extension checks.
5. Evidence fusion: explicit verdict precedence, with exact malicious hash > YARA match > suspicious mismatch > no known match.
6. Human review: report only; never automatically delete or block.
7. Trace evaluation: fixed regression tests, no LLM judge.

Reference: https://github.com/NirDiamant/GenAI_Agents

## Dataset
The SQLite store starts empty. No fabricated indicators are bundled. Import a legally usable, date-stamped CSV snapshot with sha256,label and optional family,dataset_date. Conflicting labels fail closed.

### Candidate historical sources

- **SOREL-20M (2020):** the project describes a metadata SQLite database containing SHA-256, labels, tags and counts. The complete distribution is roughly 8 TB and the metadata database alone is about 3.5 GB; obtain and process only the metadata needed, and review its terms before using or redistributing derived indicators. It is PE-focused, so it does not provide equal coverage for APK, PDF, Office or media files.
- **EMBER 2017/2018:** the official repository describes feature vectors extracted from PE files, not a ready-made universal hash feed. It is useful for reproducible PE feature-model research, not as a drop-in mobile file hash database.
- **YARA rules:** local byte-pattern signatures complement exact hash matching, but they are not a complete threat feed. Keep each rule pack versioned and provenance-tagged; do not fetch rules at scan time.

A frozen snapshot detects exact known hashes only; even one changed byte alters SHA-256. For the first mobile release, prefer a compact, legally usable hash-only export derived from an approved historical source rather than shipping raw malware samples or huge research corpora.

## Android access model
Android app sandboxing means SATARK cannot freely read WhatsApp or Telegram private databases/directories. The native app should support:
- ACTION_SEND / ACTION_SEND_MULTIPLE: user shares selected attachment to SATARK.
- ACTION_OPEN_DOCUMENT: user picks an individual file.
- ACTION_OPEN_DOCUMENT_TREE: user grants access to a specific visible directory tree.
- Persisted URI permissions for user-approved folders.
- WorkManager for best-effort scheduled scans, with visible last-scan and granted-folder state.

WhatsApp/Telegram shared media may be accessible through system-provided storage locations on some Android versions; access varies. Do not claim private chat or unrestricted app-storage access. Kotlin should handle Android intents, content URIs, permissions, notifications and lifecycle; Chaquopy or an equivalent embedded Python runtime can invoke this Python scanner.

## 24/7 / real-time claim
With a frozen dataset, real-time means a newly shared or discovered accessible file is scanned immediately (foreground) or at the next OS-permitted background-work opportunity against the installed historical snapshot. It does not mean new malware intelligence arrives automatically. Android may defer background work for battery and lifecycle reasons; never promise second-by-second scanning.

## Current milestone and gaps
Implemented: Python hash/signature inspection, SQLite historical hash import, local-only Streamlit UI, and offline tests.
Not yet implemented: native Android package, Share-to-SATARK receiver, Storage Access Framework bridge, persistent URI grants, WorkManager scheduling, YARA rule pack, and a populated licensed historical dataset. Streamlit upload is a development workflow, not native phone background monitoring.
