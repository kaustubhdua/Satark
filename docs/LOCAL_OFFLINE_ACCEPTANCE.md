# SATARK Android offline acceptance checklist

This is the acceptance procedure for the primary SATARK File Guard product. It does not use Supabase, a hosted API, API keys, cloud AI or an online threat feed. Run it against a physical Android device and a locally prepared, legally acquired historical dataset.

## Product contract

- Native Android application with the Python scanner embedded through Chaquopy.
- Android manifest has no `INTERNET` or `ACCESS_NETWORK_STATE` permission.
- Files are inspected locally by SHA-256, fixed file-format signatures, conservative built-in byte-pattern heuristics for selected PDF/OLE/script/DEX markers, extension consistency, filename heuristics and imported local intelligence.
- No semantic document text extraction, OCR, preview, archive unpacking or execution.
- WhatsApp/Telegram attachments are accessible only when the sender explicitly shares them to SATARK.
- Folder scanning is limited to a tree the user selects through Android's Storage Access Framework.
- Dataset acquisition is a separate one-time workstation operation. Scanning never downloads new data.
- WorkManager is best-effort; it does not promise continuous 24/7 monitoring.

## Build and install

Requirements: JDK 17, Android SDK Platform 36, Build Tools 36.0.0, Gradle 8.13 and Python 3.13 for Chaquopy. The app targets Android 16 / API 36 and must be tested with edge-to-edge system bars on Android 15/16.

```bash
gradle -p android --no-daemon :app:assembleDebug
```

Install the debug APK on a test device. A debug APK is not a signed production release.

## Prepare a historical snapshot

The repository includes a manual **Prepare EMBER2024 historical snapshot** GitHub Actions workflow. Choose the historical split and file-type subset, then download its CSV/provenance artifact from the workflow run. It uses the public archive downloader without an API key and does not commit dataset files to Git.

The recommended research source is EMBER2024. It contains labelled metadata for Win32, Win64, .NET, APK, ELF and PDF samples observed through 2024-12-14. Start with its compact challenge set if device storage is limited:

```bash
python scripts/download_ember2024.py --output-dir data/ember2024 --split challenge --file-type all
python scripts/import_ember2024.py --input-dir data/ember2024 --output-dir data/ember2024-csv --split challenge --file-type all
```

Keep the source and converted manifests. Verify each CSV part's SHA-256 against the generated manifest before transferring it to the device. Import the parts using a unique source/snapshot ID. The database should remain empty until the operator explicitly imports a snapshot.

A dataset label is research provenance, not proof that the original file is currently malicious or benign. The challenge set is malicious-only and cannot provide a benign denominator for accuracy measurement. Do not report precision/recall from this import alone.

## Physical-device test matrix

1. **Single share:** share one harmless PDF from WhatsApp, one from Telegram, one from a browser and one from a file manager. Confirm the scan starts without copying the file to a server.
2. **Multiple share:** share multiple attachments where the source app supports it. Confirm duplicate URIs are scanned once and the 20-file cap is enforced.
3. **Picker:** select one file and multiple files through `ACTION_OPEN_DOCUMENT`.
4. **Folder permission:** select a folder through `ACTION_OPEN_DOCUMENT_TREE`, run an immediate scan, restart SATARK and confirm the persisted grant remains usable.
5. **Revocation:** revoke folder access in Android settings or SATARK. Confirm scheduled work stops and access errors do not crash the app.
6. **Background scheduling:** opt into 15-minute and daily scans separately. Confirm choosing one cancels the other. Observe actual run times; do not expect exact scheduling.
7. **Lifecycle:** reboot the device, force-stop the app, enable battery saver and enter Doze. Record whether jobs are deferred and how SATARK recovers.
8. **Notifications:** test notification permission granted, denied and later enabled. Notification content should contain counts only, not file names or paths.
9. **Limits:** test empty files, unknown signatures, files at the configured size limit, oversized files, large folders, deep folders and unreadable document-provider entries.
10. **Privacy:** capture manifest permission output and verify there is no Internet permission. Disconnect networking and repeat file scan, dataset lookup, history and report workflows.
11. **Persistence:** close/reopen the app and confirm scan history, imported hash counts and last-scan metadata persist locally.
12. **Battery/performance:** measure scan duration, peak memory and battery use for representative small, medium and maximum-sized files on low- and mid-range devices.

## YARA

The optional desktop YARA rule pack is compiled and tested in CI using `requirements-yara.txt`. Android includes pure-Python built-in byte-pattern heuristics and does not bundle native YARA. Physical-device checks should verify the built-in SHA-256, format-signature and byte-pattern paths; do not claim native YARA parity until a native Android ABI integration has been implemented and tested on-device.

## Acceptance evidence

Record:
- Git commit SHA and Android workflow run.
- Device model, Android version, OEM build and available RAM.
- APK SHA-256 and whether it is debug or release-signed.
- Share/picker/folder test outcomes for each source app.
- WorkManager actual run timestamps and deferrals.
- Notification behavior with permission granted/denied.
- Dataset source, snapshot ID, cutoff, file types, row counts and manifest SHA-256.
- Scan latency, peak memory, battery impact and limits tested.
- Any failures, reproduction steps and unresolved release blockers.

## Release gate

Do not call SATARK production-complete until physical-device QA, measured performance/battery tests, real snapshot import, independently labelled detection evaluation, privacy/store disclosures, signing and release-build verification are complete. CI passing and a debug APK are necessary but insufficient.
