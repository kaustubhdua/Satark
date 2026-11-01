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
5. Import a historical CSV snapshot using the source ID field and import button.
6. Review local scan history. Clear history or the imported threat database independently. Remove folder access at any time to release the saved permission and cancel scheduled scans.
7. Allow notifications if you want alerts when a scheduled scan finds files needing review.

## Limits

- Maximum 64 MB per file, 20 shared files per foreground share event.
- Folder worker: up to 1,000 files, 8 directory levels, 64 MB per file and 512 MB per run.
- Daily periodic scan is best-effort; Android may defer it. This is not 24/7 real-time monitoring.
- Only the selected folder tree is accessible. WhatsApp/Telegram private message stores and private app directories are not accessed.
- The bundled Android scanner uses SHA-256, magic bytes and filename/signature checks. It does not currently bundle YARA.
- The historical intelligence database is empty until the user imports a licensed, provenance-labelled CSV.
- No file is executed, unpacked, previewed, modified, uploaded or deleted.

## Privacy

All Android scan processing and databases stay in the app's private storage. The app manifest intentionally omits the Internet permission. Incoming share URIs are read only for the duration of the grant. Selected folder access is persisted only after explicit user action.
