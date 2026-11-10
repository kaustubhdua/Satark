<div align="center">

# SATARK — Offline File Guard

### Android-first · Python detection engine · Local-only scanning

**Inspect file fingerprints and signatures. Keep private content on-device.**

SATARK is an Android-first file-security application for scanning files that a user explicitly shares, selects, or makes available through an Android folder permission. The Kotlin layer handles Android integration; the Python engine performs static inspection and local SQLite lookups.

**No hosted detection APIs. No API keys. No file uploads. No chat reading. No cloud dependency for Android scanning.**

[![CI](https://github.com/kaustubhdua/Satark/actions/workflows/ci.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/ci.yml)
[![Android File Guard](https://github.com/kaustubhdua/Satark/actions/workflows/android-file-guard.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/android-file-guard.yml)
[![Web CI](https://github.com/kaustubhdua/Satark/actions/workflows/web-ci.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/web-ci.yml)
[![CodeQL](https://github.com/kaustubhdua/Satark/actions/workflows/codeql.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/codeql.yml)

<img src="assets/satark-banner.svg" alt="SATARK" width="900">

</div>

---

## Product direction

SATARK is a **local static file inspection tool**, not a chatbot, message reader, cloud antivirus, or promise of guaranteed protection. Its first mobile workflow is:

1. Receive a file through Android's **Share to SATARK** action (for example, from WhatsApp or Telegram).
2. Or choose a file with Android's system picker, or grant access to a specific folder.
3. SATARK copies only the selected file into a bounded temporary location, streams it through the Python inspection engine, and removes the temporary copy.
4. The engine computes file fingerprints, checks format signatures and bounded structural indicators, and compares supported hashes with the on-device historical database.
5. The app displays the verdict, reasons, dataset provenance, and a local evidence report. Scan history is stored on-device.

The app does not access another app's private chat database. It cannot silently inspect private WhatsApp or Telegram messages or their app-private storage. A file must be explicitly shared or made accessible through Android's permission model.

## What SATARK inspects

“Does not read file content” needs a precise technical meaning. SATARK does **not interpret document text, render/preview documents, OCR images, transcribe media, or read message bodies**. Static file detection still needs to inspect bytes:

| Check | What is accessed | Why |
| --- | --- | --- |
| SHA-256 | Entire file, streamed in bounded chunks | Identify an exact known file without loading it all into memory |
| Header / magic bytes | A bounded prefix | Identify the actual file format |
| Extension consistency | Filename plus detected format | Flag mismatches such as an executable named `invoice.pdf` |
| Byte signatures | Bounded byte windows / configured patterns | Detect selected known suspicious markers |
| Structural checks | Selected PE, ELF and DEX fields | Identify malformed or unusual executable structure |
| File metadata | Name and size exposed by Android | Add context and enforce resource limits |
| Historical hash lookup | Local SQLite indicator index | Match a known historical indicator |

The scanner is deterministic and explainable. A signature or structural anomaly is a signal, not proof of malicious intent. A clean result means **no threat was detected by the checks and historical indicators available in this build**; it does not prove that a file is safe.

### Current detection boundaries

- The bundled mobile starter database is a **pinned EMBER2024 APK training subset**, not the entire EMBER2024 corpus.
- The verified starter snapshot contains 208,000 unique APK SHA-256 indicators: 104,000 malicious and 104,000 benign. It stores hashes and labels, not malware binaries.
- EMBER/EMBER2024 are research datasets. Their labels and coverage do not establish commercial antivirus accuracy or complete coverage of WhatsApp/Telegram attachments.
- The Android build uses its implemented byte-signature and structural checks. Native YARA is **not bundled/enabled** in the Android app at this time. Optional desktop YARA support is separate.
- Static hashes identify exact known files. A modified or newly emerging file may not match a historical hash.
- Do not treat the benign label in a research dataset as a guarantee of safety.

## Android app capabilities

| Module | Current behavior |
| --- | --- |
| Quick scan | Scan a file shared to SATARK or selected through Android's file picker |
| WhatsApp / Telegram | Scan files the user explicitly shares from those apps; no private database access |
| Folder scan | Scan files inside a user-authorized Storage Access Framework tree |
| Background rescans | Best-effort WorkManager scheduling for authorized folders |
| Local intelligence | SQLite historical hash index, with dataset provenance/checksum validation |
| Security history | On-device scan history and locally verifiable hash-linked evidence entries |
| Evidence report | Metadata-only report with file hash, verdict, signals, provenance and integrity digest |
| Privacy | No Android Internet permission, remote lookup, upload, telemetry or hosted model call in the mobile scanner |

### What “24/7” means—and does not mean

SATARK can scan a file immediately when the user shares/selects it and can schedule periodic rescans of authorized folders. Android controls background scheduling, Doze, battery restrictions and OEM policies. WorkManager periodic work has a minimum 15-minute interval and is not an exact timer. SATARK therefore **cannot promise uninterrupted, second-by-second, 24/7 monitoring**.

The historical database is frozen to its documented revision. The app can inspect newly encountered files against that historical knowledge in real time, but it does not learn about newly emerging threats in real time. No threat-intelligence API or automatic feed is queried.

## Architecture

```text
WhatsApp / Telegram / Downloads / other apps
                    |
         User shares or selects a file
                    |
       Android Sharesheet / SAF grant
                    |
       Bounded temporary-file intake
                    |
           Kotlin Android layer
                    |
          Chaquopy Python bridge
                    |
          Python File Guard engine
          |        |         |
       SHA-256   file type   structure /
       stream    signatures byte markers
          |        |         |
          +--------+---------+
                   |
       Local SQLite historical index
                   |
        Explainable scan assessment
                   |
       Local history + evidence report
```

**Responsibilities**

- **Kotlin:** Android Sharesheet intents, Storage Access Framework, lifecycle, notifications, temporary-file handling and WorkManager.
- **Python:** streaming hashes, format identification, byte-pattern checks, bounded structural inspection, local dataset processing, verdict composition and SQLite history.
- **SQLite:** local historical indicators and scan/evidence history.
- **Chaquopy:** embeds the Python runtime in the Android app.

The mobile scanner does not need the repository's optional web backend. Supabase is not a runtime dependency. The Android app has no Internet permission and does not call hosted AI, malware reputation or threat-intelligence APIs. The optional legacy web workspace can use a locally hosted Ollama instance for its separate text-analysis features; a browser or server hosted on Vercel cannot reach an Ollama process running on your own computer. Ollama is not used by the Android File Guard.

## FIRSTLIGHT incident-response workspace

SATARK also includes **FIRSTLIGHT**, a self-hosted case-based incident investigation and response workspace. It is separate from the offline Android file scanner: the Android scanner needs no network permission or hosted service. FIRSTLIGHT uses open-source Wazuh for endpoint telemetry and guarded endpoint response; no proprietary endpoint-security provider or tenant is required.

FIRSTLIGHT capabilities include:

- Import bounded JSON/CSV telemetry, preserve private original evidence, verify SHA-256 integrity and reconstruct event timelines.
- Run deterministic Python detection/correlation rules with evidence references, uncertainty and explicit evidence gaps.
- Use optional local Ollama specialists for advisory analysis in both direct and durable background investigations; deterministic findings remain available without a model or paid AI API.
- Persist workspaces, memberships, cases, notes, evidence metadata, findings, report snapshots, audit events and durable investigation jobs in the self-hosted SQLAlchemy backend (PostgreSQL for production or SQLite for local development).
- Poll Wazuh through an optional private worker with an explicit agent allowlist, durable checkpoints and locally stored source snapshots.
- Request guarded Wazuh Active Response actions (`firewall-drop` for a validated IPv4 address or `disable-account` for a validated local account) with one allowlisted agent, four-eyes approval, a third-party executor, exact confirmation, at-most-once submission and independent verification.

**Managed database and proprietary endpoint-security services are not runtime dependencies.** The Android File Guard remains fully offline. Wazuh is self-hostable and its Manager API / Indexer credentials are configured only in the private FIRSTLIGHT server runtime; they are not used by the Android scanner.

Live response is disabled by default and is not triggered by AI. A provider submission is not proof of completed containment. Real-provider acceptance requires an authorized Wazuh lab manager and disposable allowlisted agent. See [FIRSTLIGHT overview](docs/FIRSTLIGHT.md), [Wazuh setup](docs/FIRSTLIGHT_WAZUH_INTEGRATION.md), [guarded response](docs/FIRSTLIGHT_LIVE_RESPONSE.md), and [backup/restore](docs/FIRSTLIGHT_BACKUP_RESTORE.md). For self-hosted PostgreSQL, Caddy HTTPS, secrets, deployment and recovery, follow the [production deployment runbook](docs/PRODUCTION_DEPLOYMENT.md).

## Build and run the Android app

### Requirements

- Android Studio / Android SDK
- JDK 17
- Gradle 8.13 (the wrapper/CI build uses the pinned project configuration)
- Python 3.13-compatible Chaquopy configuration

### Build a debug APK

From the repository root:

```bash
gradle -p android :app:assembleDebug --no-daemon
```

The APK is generated at:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

Install it on a test device or emulator:

```bash
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.satark.mobile/.MainActivity
```

The CI workflow builds the pinned historical starter SQLite database, verifies its metadata, packages it into the APK, builds the Android app and runs an emulator launch smoke test. The generated database assets are intentionally git-ignored: a plain local Gradle build without those generated assets still builds the app, but it starts without the bundled historical snapshot until you import a verified offline dataset or follow the asset-generation steps in the architecture guide. See [Android File Guard architecture](docs/ANDROID_FILE_GUARD_ARCHITECTURE.md) and [Android device QA checklist](docs/ANDROID_DEVICE_QA.md).

### Use the app

1. Open SATARK.
2. Share a file from WhatsApp, Telegram, a browser or a file manager using Android's Share menu and choose SATARK; alternatively tap the file-picker action.
3. Review the scan status, detected format, SHA-256, matched indicators and explanatory signals.
4. For folder scanning, choose a folder using Android's system folder picker and grant access.
5. Review local scan history and evidence reports.
6. Use the dataset import flow only for a supported historical snapshot whose source and converter manifests are available; the app verifies provenance and checksums before accepting it.

Do not use real malware on a personal device. Use harmless fixtures and an isolated test environment for development.

## Historical dataset and provenance

SATARK uses historical research data rather than a live cloud feed. The Android starter database is generated from a pinned EMBER2024 repository revision:

- Dataset project: [FutureComputing4AI / EMBER2024](https://github.com/FutureComputing4AI/EMBER2024)
- Pinned revision: `8cc201a3d2a1cb2957123eb5ad996d5a3178bbcc`
- Mobile starter scope: APK training split only
- Indicators: 208,000 unique SHA-256 hashes (104,000 malicious and 104,000 benign)
- SQLite asset size: 49,905,664 bytes
- Database SHA-256: `6a2fc4527e8a9e0cdd5d1c09fb4ea7c95f2f1a2ec56c238b3aab366b1af4ec47`
- SQLite integrity check: `ok`

No raw malware binaries are packaged in the app. The dataset is frozen at the pinned revision; there is no automatic update or network lookup. Research labels, collection bias, class balance and file-type coverage must be considered when interpreting a match.

Related research and tools:

- [EMBER](https://github.com/elastic/ember) — static PE feature dataset and tooling; not a universal hash feed.
- [SOREL-20M](https://github.com/sophos/SOREL-20M) — large PE research dataset with substantial storage and processing requirements.
- [YARA documentation](https://yara.readthedocs.io/) — local pattern-matching rule engine; native Android integration remains a separate, unshipped capability.
- [Android Storage Access Framework](https://developer.android.com/guide/topics/providers/document-provider) — user-mediated file and folder access.
- [Android WorkManager](https://developer.android.com/topic/libraries/architecture/workmanager) — deferrable background work, not guaranteed real-time scheduling.

## Privacy and security guarantees

The Android scanner is designed around least privilege:

- No reading WhatsApp/Telegram private databases, messages, contacts or chat text.
- No document text extraction, OCR, image interpretation, video/audio transcription or preview.
- No file execution, modification, archive extraction or automatic deletion.
- No file upload, cloud analysis, telemetry transmission, remote hash lookup or hosted AI call.
- No Android Internet permission in the mobile app manifest.
- File access is limited to explicit share intents, system file picker results and user-granted folder permissions.
- Temporary copies are bounded and cleaned up after scan attempts; the app records partial/not-started work rather than silently claiming all shared files were scanned.
- Evidence reports contain metadata and hashes, not original file bytes.

A local hash chain helps detect edits or reordering in retained records. It is not a digital signature, hardware-backed attestation, independently anchored audit service or certified forensic chain of custody.

## Tests, evaluation and release status

Run the Python File Guard tests from the repository root:

```bash
python -m unittest discover -s tests -p "test_file_guard*.py" -v
python -m unittest discover -s tests -p "test_android*.py" -v
python -m unittest discover -s tests -p "test_ember*.py" -v
python -m compileall -q file_guard android/app/src/main/python scripts
```

The repository also contains broader FIRSTLIGHT, migration, PostgreSQL and web regression suites. Those legacy suites are separate from the offline Android scanning path.

For labelled corpus evaluation:

```bash
python scripts/evaluate_file_guard.py evaluation.csv --output evaluation-report.json
```

The CSV must contain `expected` and `predicted` columns. Allowed predictions include `benign`, `malicious` and `unknown`; unknown predictions are counted as abstentions and reduce coverage. Use a legally acquired, independently labelled real-binary corpus. Synthetic fixtures and EMBER metadata alone are not sufficient to claim real-world antivirus performance.

**Release gates still required before public production/Play Store claims:**

- Exact-head CI and Android emulator launch checks passing.
- Physical-device validation of WhatsApp/Telegram sharing, SAF grants/revocation, reboot, Doze, notifications and OEM battery policies.
- Independently labelled binary-corpus evaluation reporting precision, recall, false positives, specificity, F1, abstention and file-type coverage.
- Low/mid-range device profiling for scan time, memory, battery and cleanup.
- Production signing keys, signed APK/AAB, privacy disclosures, store listing and Play review.

A CI-built debug APK or unsigned release artifact is not a Play Store-ready release. SATARK is a development-stage security aid, not a replacement for a maintained antivirus product.

## Open-source design references

The repository's product and UI work can draw on these projects without copying their branding or code wholesale:

- [shadcn/ui](https://github.com/shadcn-ui/ui) — accessible component patterns and composable UI ideas for the supporting web interface.
- [Magic UI](https://github.com/magicuidesign/magicui) — restrained motion and visual interaction references.
- [Tremor](https://github.com/tremorlabs/tremor) — dashboard information hierarchy and data visualization patterns.
- [Hallmark](https://github.com/Nutlope/hallmark) — modern product presentation and interface inspiration.
- [GenAI Agents](https://github.com/NirDiamant/GenAI_Agents) — educational agent patterns; not a dependency of the offline file scanner.

The Android product prioritizes native platform conventions, fast scanning, clear status, accessibility and low resource use over decorative animation.

## Repository map

| Path | Purpose |
| --- | --- |
| `android/` | Native Android app and Chaquopy Python integration |
| `file_guard/` | Desktop/shared Python static inspection engine |
| `scripts/` | Dataset provenance, starter DB generation and evaluation utilities |
| `tests/` | Engine, Android contract, dataset and regression tests |
| `docs/ANDROID_FILE_GUARD_ARCHITECTURE.md` | Android design and data flow |
| `docs/ANDROID_DEVICE_QA.md` | Physical-device QA and release checklist |
| `docs/FILE_GUARD_EVIDENCE_AND_EVALUATION.md` | Evidence report and evaluation guidance |
| `docs/MOBILE_PRODUCT_DESIGN.md` | Mobile product and UI design notes |
| `web/` | Supporting/legacy web workspace, not required for mobile scanning |
| `FIRSTLIGHT/` and related modules | Legacy incident-investigation prototype |

## Contributing

Contributions should preserve the mobile privacy contract and offline behavior. Please include focused tests for new file formats, signatures, dataset import logic, permission flows and evidence handling. Never commit malware binaries, personal files, API keys, signing keys or real private incident evidence. Do not claim “safe” based solely on a clean historical hash lookup.

---

**SATARK: local inspection, historical intelligence, user-controlled access.**
