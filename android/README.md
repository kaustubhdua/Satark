# SATARK File Guard — Android app

This is a standalone Android Studio/Gradle project. It embeds the SATARK Python scanner with Chaquopy and has no `INTERNET` permission.

## Build

Requirements:
- Android Studio with Android SDK Platform 36 and Build Tools installed, or JDK 17 + Android SDK command-line tools.
- Python 3.13 on the build machine (Chaquopy uses Python 3.13).
- Gradle 8.13.

From the repository root:

```bash
gradle -p android :app:assembleDebug
```

The debug APK is written to:

```
android/app/build/outputs/apk/debug/app-debug.apk
```

Open the `android/` folder in Android Studio if you prefer the IDE. The CI workflow builds this same debug APK and uploads it as the `satark-file-guard-debug-apk` artifact.

## Use

1. Install the debug APK on an Android 7.0+ device (API 24+).
2. Open SATARK File Guard, or use Share from WhatsApp/Telegram and select SATARK.
3. Alternatively choose one or more files with the Android system file picker.
4. To scan a folder, choose a folder through Android's directory picker. SATARK stores only the user-granted URI permission and scans that folder.
5. Import a historical CSV snapshot using the source ID field and import button. You can multi-select all converter-generated CSV parts in one import operation.
6. Review local scan history. Clear history or the imported threat database independently. Stop background scans while retaining folder access, or remove folder access to release the saved permission and cancel scheduled scans.
7. Allow notifications if you want alerts when a scheduled scan finds files needing review.

## Historical dataset preparation

The recommended historical source is EMBER2024 (2023-09-24 through 2024-12-14), which provides SHA-256 labels across Win32, Win64, .NET, APK, ELF and PDF. The app does not download data or contact a threat-intelligence feed. On a trusted development computer, acquire the public dataset once and convert its local JSONL metadata:

```bash
python scripts/download_ember2024.py --output-dir data/ember2024 --split train --file-type APK
python scripts/import_ember2024.py --input-dir data/ember2024 --output-dir data/ember2024-csv --split train --file-type APK
```

Repeat for PDF, ELF or PE if those formats are needed. Transfer the generated CSV parts to the phone and multi-select them in the import picker. Each part is 25,000 rows by default; confirm it is below the 64 MB import limit. Keep the generated manifest with the snapshot for provenance. The APK itself has no Internet permission.

## Limits

- Maximum 64 MB per file, 20 shared files per foreground share event.
- Folder worker: up to 1,000 files, 8 directory levels, 64 MB per file and 512 MB per run.
- Frequent 15-minute and daily periodic scans are best-effort; Android may defer either. The 15-minute option is not exact and neither schedule is continuous 24/7 monitoring.
- Only the selected folder tree is accessible. WhatsApp/Telegram private message stores and private app directories are not accessed.
- The bundled Android scanner uses SHA-256, magic bytes and filename/signature checks. It does not currently bundle YARA.
- The historical intelligence database is empty until the user imports a licensed, provenance-labelled CSV.
- No file is executed, unpacked, previewed, modified, uploaded or deleted.

## Privacy

All Android scan processing and databases stay in the app's private storage. The app manifest intentionally omits the Internet permission. Incoming share URIs are read only for the duration of the grant. Selected folder access is persisted only after explicit user action.
