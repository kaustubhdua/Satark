# SATARK Android File Guard — device QA plan

This checklist is for real-device validation. CI builds and emulator smoke tests cannot verify vendor-specific content providers, battery policies or actual WhatsApp/Telegram URI behavior.

## Device matrix

Test at minimum:
- Android 7/API 24 (minimum supported platform).
- Android 13/API 33 or later (runtime notification permission).

- One device with aggressive OEM background restrictions (for example Xiaomi/Redmi, Oppo/Realme, Vivo or Samsung battery management).

Record device model, Android build, SATARK APK SHA-256, test date and battery mode for every run.

## Share-to-SATARK tests

- Share one PDF, APK, image and generic binary from WhatsApp.
- Share multiple attachments from WhatsApp.
- Repeat single and multiple attachment tests from Telegram.
- Test from Files, Downloads and a browser download manager.
- Test long filenames, Unicode names, duplicate filenames, missing display names and zero-byte files.
- Test an attachment whose provider URI becomes unavailable before SATARK opens it.
- Test a file just below and just above the 64 MiB per-file limit.
- Verify that SATARK reports a clear error for unavailable/oversized files and does not crash.
- Verify the source app remains usable and no original file is modified.

Acceptance: each valid shared attachment is scanned once; multiple attachments are all accounted for; URI failures are explicit; no private chat database or message content is accessed.

## Storage Access Framework tests

- Select a folder with nested subfolders and representative files.
- Verify only the selected tree is scanned.
- Close/reopen SATARK and verify the persisted folder grant remains usable.
- Reboot the device and verify the permission and scheduled job state.
- Revoke folder access from Android settings and verify SATARK fails safely.
- Delete or move the selected folder and verify a clear recoverable error.
- Select a cloud-backed document provider and test provider disconnect/timeouts.
- Stop scheduled scans, then verify that folder permission remains until the user explicitly removes it.
- Remove folder access and verify the persisted URI grant is released and periodic work is cancelled.

Acceptance: no broad storage permission is requested; every scanned folder was explicitly granted by the user; revocation is respected.

## WorkManager and notification tests

- Enable the 15-minute periodic scan and verify that a unique schedule exists.
- Enable daily scanning and verify the previous periodic schedule is replaced.
- Stop background scanning and verify no new periodic work is enqueued.
- Test reboot, Doze, battery saver, app standby and OEM battery optimization.
- Record actual run times; do not expect exact 15-minute execution.
- Deny notification permission, run a background scan, then grant permission and retry.
- Verify notifications disclose only aggregate counts and no filenames or document content.

Acceptance: work is idempotent, bounded and cancellable; notifications respect permission; documentation continues to call scheduling best-effort, never guaranteed 24/7.

## Performance and cleanup

For 1, 100 and 1,000-file folders, record:
- Scan duration and files/second.
- Peak process memory (RSS/PSS).
- Battery delta and device temperature.
- Temporary cache size before, during and after scans.
- Number of completed, skipped, oversized and failed files.
- App responsiveness while a folder scan is running.

Verify temporary files are deleted after success, failure and worker cancellation. Confirm that the 64 MiB per-file, 512 MiB per-run and 1,000-file limits are enforced.

## Offline and privacy verification

- Enable airplane mode and disable Wi-Fi/mobile data.
- Scan a known fixture and an unknown fixture.
- Confirm no network permission exists in the installed APK manifest.
- Inspect device network logs during scan and scheduled work.
- Verify the report contains hashes, metadata and evidence only, never original bytes or extracted text.
- Verify that unknown/no-match files are not described as safe.

## Threat-intelligence validation

- Import a converter-produced EMBER2024 CSV set with its manifest.
- Confirm all imported parts are checksum-verified and source/date/type provenance is retained.
- Alter one byte in a CSV part and verify import is rejected.
- Test duplicate hashes and conflicting labels; conflicts must fail closed.
- Run a separately labelled, legally obtained benign/malicious file corpus through the scanner.
- Export predictions and run `scripts/evaluate_file_guard.py`.
- Report corpus composition, dataset cutoff, scanner commit, precision, recall, false-positive rate, coverage and confidence intervals. Do not infer production detection rates from EICAR or synthetic fixtures.

## Release blockers

Do not mark the app production-ready until the device matrix, real attachment flows, SAF revocation, background scheduling, performance profiling, dataset provenance, signed release build and privacy/store disclosures have been reviewed and recorded.
