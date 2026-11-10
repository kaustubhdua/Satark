# SATARK File Guard — Android app

SATARK is an Android-first, Python-based, offline-first file security application. Kotlin is limited to Android platform integration; the inspection and local intelligence engine is Python via Chaquopy.

## Product guarantees

- No Supabase runtime, Internet permission, cloud API, hosted AI, telemetry upload or remote hash lookup in the Android app.
- Files are inspected locally using SHA-256, bounded format signatures, extension consistency and an explicitly imported historical hash snapshot.
- The app does not extract document text, read chats, OCR images, render previews, unpack archives, execute, modify, upload or delete files.
- Share files from WhatsApp, Telegram, browsers and file managers to SATARK, or select files/folders using Android's system pickers.
- Only user-shared files and explicitly granted folder trees are accessible. Private WhatsApp/Telegram databases and other apps' private directories are inaccessible by design.

## Build

Requirements: JDK 17, Android SDK Platform 36 / Build Tools 36.0.0, Gradle 8.13, Android Gradle Plugin 8.13.2, and Python 3.13 for Chaquopy build integration.

    gradle -p android --no-daemon :app:assembleDebug

The debug APK is written to android/app/build/outputs/apk/debug/app-debug.apk. GitHub Actions builds and uploads the APK as satark-file-guard-debug-apk.

## Use

1. Install the debug APK on an Android 7.0+ device (API 24+).
2. Share one or more files from WhatsApp or Telegram to SATARK, or use Choose a file.
3. For folder scanning, choose a folder through Android's directory picker and grant read access.
4. Start an immediate scan or opt into best-effort 15-minute / daily WorkManager rescans.
5. Import historical CSV snapshots by multi-selecting the matching `*_manifest.json` file and its CSV parts. For EMBER2024, SATARK requires the manifest and verifies each CSV SHA-256 before import. Up to 256 CSV parts can be imported per batch; split larger snapshots into batches and keep the same manifest. Keep the original source manifest and record the dataset cutoff.
6. View imported historical hash coverage (total, malicious and benign indicators), and clear local scan history independently from the intelligence database.

## Historical dataset

The default research source is EMBER2024, with labelled feature metadata covering Win32, Win64, .NET, APK, ELF and PDF samples collected through 2024-12-14. EMBER2024 is a research dataset, not a complete universal hash feed. SATARK converts metadata hashes/labels to CSV; it does not download or bundle malware binaries. Download and conversion are explicit operator actions on a trusted development machine. Transfer the generated CSV parts to the phone for local import.

For a compact malicious-only starter snapshot, prepare the EMBER2024 challenge set (6,315 labelled malicious samples) first:

    python scripts/download_ember2024.py --output-dir data/ember2024 --split challenge --file-type all
    python scripts/import_ember2024.py --input-dir data/ember2024 --output-dir data/ember2024-csv --split challenge --file-type all

Then import the generated CSV part(s) in the app and keep the generated manifest alongside the snapshot. For benign/malicious coverage across specific formats, separately prepare APK, PDF, ELF or PE train/test subsets. Do not combine conflicting labels; the importer rejects a hash whose existing label conflicts.

The frozen database does not learn new threat intelligence. A newly discovered malware sample, or a modified sample with a different SHA-256, may not match the historical hash table. The app displays imported total, malicious and benign counts so users can see whether hash intelligence is actually installed.

## Background scanning and Android limits

WorkManager's periodic interval minimum is 15 minutes, but execution is inexact and can be delayed by Doze, battery optimization, provider availability or OEM behavior. SATARK therefore provides event-driven Share-to-SATARK scanning plus best-effort folder rescans; it cannot promise uninterrupted, second-by-second 24/7 monitoring.

Android 11+ restricts access to other apps' private data and app-specific external directories. SATARK cannot bypass these controls. A folder tree must be explicitly selected by the user, and Android may block protected locations such as Android/data, Android/obb and the Download root from tree selection.

## Limits

- Maximum 64 MB per file; up to 20 shared files per foreground share event.
- Folder worker: bounded by file count, depth and total bytes per run.
- The Android build currently uses SHA-256, format signatures and filename/signature checks. Native YARA is not bundled in the mobile APK.
- The intelligence database is empty until the user imports a properly licensed, provenance-labelled snapshot.
- A no-match verdict means only that enabled local checks found no indicator; it is not a guarantee of safety.

## Privacy

All Android scan processing, imported intelligence and scan history remain in app-private storage. The app manifest intentionally omits the Internet permission. The source URI is read only under the temporary share grant; folder URI access is persisted only after explicit user selection and can be revoked in the app.


## Evidence reports and evaluation

Each shared-file scan returns a versioned JSON evidence report containing a UTC timestamp, file metadata, SHA-256, verdict, signals, local dataset provenance, YARA capability state, agent trace and a canonical report digest. The digest is an integrity check only; it is not a signature or certified chain-of-custody proof. No original file bytes or extracted text are placed in the report.

A labelled evaluation CSV can be measured on a development machine:

    python scripts/evaluate_file_guard.py evaluation.csv --output evaluation-report.json

Use benign/malicious expected labels and benign/malicious/unknown predictions. Unknown counts as an abstention and reduces measured coverage. Metrics must be reported with the corpus composition and must not be presented as real-world detection rates.

Native YARA is not bundled in the Android APK. The desktop optional YARA path must not be advertised as an Android capability.
