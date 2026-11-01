# SATARK File Guard — privacy notice (development draft)

Last updated: 1 November 2026

## What the app does

SATARK File Guard statically inspects files that a user explicitly shares with the app or selects through Android's system file picker. The scanner calculates SHA-256 fingerprints, checks a limited set of file header signatures, compares fingerprints against a locally imported historical database, and may record suspicious filename/extension mismatches.

## What the app does not do

- It does not read WhatsApp or Telegram messages, chat databases, account credentials or private app directories.
- It does not extract document text, perform OCR, render media, unpack archives or execute files.
- It does not send files, hashes, scan results or telemetry to a server.
- It does not request network access.
- It does not automatically delete, quarantine, modify or block files.

## Storage

The Android app stores the imported hash database and scan history in its private application storage. Scan history contains file name, size, SHA-256, detected type, verdict, timestamp and rule signals; it does not store file bytes. The user can clear scan history from the app. Imported threat indicators remain until the app data is cleared or a future database-management control is used.

## Permissions and user control

A file shared from another app is accessed through the temporary URI permission supplied by Android. Folder scanning requires the user to choose a folder in Android's system picker and grant access. The app does not assume access to any other folders. The user can revoke folder access in Android settings or move/delete the selected folder.

## Dataset

The app's threat-intelligence database is empty by default. Users may import a CSV snapshot. The source identifier and supplied dataset contents are stored locally. Dataset provenance and licensing must be checked by the person importing the snapshot.

## Limitations

A match against a historical database is exact-hash matching. Modified or previously unseen malware may not match. A no-match result is not a guarantee of safety. Background scans use Android WorkManager and may be delayed by the operating system; they are not continuous 24/7 protection.

## Contact and release status

This is a development-stage privacy notice, not legal advice. Before public distribution, replace this section with the maintainer's verified contact details, complete Play Store Data Safety disclosures, and jurisdiction-specific privacy review. Do not publish invented contact information.
