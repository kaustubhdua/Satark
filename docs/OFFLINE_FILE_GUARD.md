# SATARK File Guard — offline mobile file inspection

## Product direction

SATARK File Guard is an app-oriented, local-first file-security workflow for files received through WhatsApp, Telegram, downloads, email attachments and other apps. The Android app invokes the deterministic Python inspection engine using Chaquopy; there is no hosted analysis API or runtime network permission.

## Detection boundary

- SHA-256 exact-match lookup against a historical, locally imported SQLite index.
- Magic-byte identification for common document, archive, executable, image and Android DEX formats.
- Extension/signature mismatch and double-extension heuristics.
- Optional YARA rules in the desktop Python engine when local `yara-python` and a reviewed rules file are installed. The first Android build does not bundle YARA.
- No document text extraction, OCR, rendering, archive unpacking, file execution, preview, deletion or automatic quarantine.
- Unknown files are not labelled safe. A no-match verdict means only that enabled checks found no known indicator.

## Agent architecture

Inspired by workflow patterns in NirDiamant/GenAI_Agents without importing its hosted-LLM/API tutorial dependencies:

The current implementation records an inspectable `agent_trace` for each file:
1. **Router:** choose static checks based on detected file type and optional YARA configuration.
2. **Magic/signature specialist:** identify supported magic bytes and compare against the filename extension.
3. **Metadata specialist:** flag double extensions and annotate executable extensions without treating the extension alone as malware.
4. **SHA-256 intelligence specialist:** perform an exact local lookup and retain source provenance.
5. **YARA specialist:** run reviewed local byte-pattern rules when configured; distinguish missing rules, missing dependency, no match and rule errors.
6. **Evidence fusion:** deterministic precedence: known malicious SHA-256 > YARA match > suspicious metadata > no known indicator. A benign hash does not override suspicious evidence.
7. **Human review and trace evaluation:** present every specialist's observations and test deterministic behavior with fixtures; no LLM judge or hidden generated verdicts.

This adapts the independent-agent and evidence-fusion architecture from the user's CyberSentinel project in `kaustubhdua/jai-hack`. The file scanner deliberately replaces learned network-flow models with static deterministic specialists: training a flow classifier would not improve byte-signature matching and would introduce unnecessary API/model dependencies.

Reference: https://github.com/NirDiamant/GenAI_Agents

## Android implementation

The standalone Android project is in `android/` and uses Kotlin + Chaquopy 17.2 / Python 3.13. Chaquopy's current requirements are minSdk 24 and supported Android Gradle Plugin versions 7.3–9.4; this project targets Android API 35, minSdk 24 and 64-bit ARM/emulator ABIs.

Implemented in the Android scaffold:
- Android Sharesheet receivers for `ACTION_SEND` and `ACTION_SEND_MULTIPLE`.
- System file picker using `ACTION_OPEN_DOCUMENT`.
- User-granted directory selection using `ACTION_OPEN_DOCUMENT_TREE`.
- Persisted URI read permission for the selected tree.
- Local Python SHA-256 and file-signature scanning.
- Local SQLite scan history and historical CSV hash snapshot import.
- WorkManager one-time and daily scheduled folder scans, bounded to 1,000 files, 8 directory levels, 64 MB/file and 512 MB/run.

The user chooses which files or folder are accessible. SATARK does not access WhatsApp/Telegram private chat databases or private app directories. A sender's temporary URI grant is used for a shared attachment; the app does not assume it can persist that sender grant.

## 24/7 and real-time claims

A frozen dataset cannot discover newly emerging threats. Real-time means a newly shared file is inspected immediately against the currently installed historical snapshot. Scheduled folder scans are best-effort: Android may defer WorkManager tasks according to battery, Doze, app standby and device scheduling. Periodic WorkManager jobs have a 15-minute minimum interval and no exact-time guarantee; SATARK uses a 24-hour interval and must not claim continuous 24/7 monitoring.

## Historical dataset research

- **SOREL-20M:** PE-focused research corpus with hash metadata; large and subject to licensing/redistribution review. Not universal Android/PDF/Office coverage.
- **EMBER:** PE static-feature research data, not a universal cross-platform SHA-256 feed.
- **YARA:** local byte-pattern rules complement exact hash matching but are not a complete feed.
- The app ships with an empty local indicator database. Import only a date-stamped, legally usable CSV snapshot with `sha256,label` and optional `family,dataset_date` columns. Conflicting labels fail closed.

## Streamlit interface boundary

The Streamlit File Guard page is a developer interface. Uploaded bytes are transferred to the Streamlit host. Run it on localhost or a trusted private host if you want scans to remain on your own machine. The Android app is the intended mobile local-processing path.

## Validation and release

- `.github/workflows/android-file-guard.yml` compiles Python modules, runs deterministic tests and builds a debug APK.
- A successful CI build is required before treating the Android scaffold as build-verified.
- Device validation is still required for WhatsApp/Telegram sender compatibility, scoped-storage provider behavior, low-memory handling, Android 13+ behavior, background scheduling and OEM battery restrictions.
- A signed release APK/AAB, Play Store compliance review, privacy policy and physical-device QA are not yet supplied.
