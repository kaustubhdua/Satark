# SATARK architecture and threat model

## Product boundary

SATARK File Guard is the primary product: a native Android application with a Python inspection engine embedded through Chaquopy. Its security-critical workflow is local and offline. The Android app does not require Supabase, a hosted backend, a cloud AI provider, a threat-intelligence API, an API key, or an Internet permission.

The older Next.js, Streamlit, FIRSTLIGHT and self-hosted case-management components remain optional legacy/supporting tools in this repository. They are not required to install, scan files, store scan history, import historical intelligence or run scheduled folder scans on Android.

## Android components

- **Native Android shell (Kotlin):** handles Android Sharesheet intents, Storage Access Framework grants, notifications, lifecycle and WorkManager scheduling.
- **Python engine (Chaquopy):** computes SHA-256, reads bounded file signatures, checks extension/signature consistency, runs deterministic specialist checks, optionally evaluates YARA on supported desktop Python installations, and fuses evidence.
- **SQLite local stores:** hold explicitly imported historical hash indicators and metadata-only scan history in app-private storage.
- **Historical snapshot tools:** one-time workstation scripts acquire and convert the selected EMBER2024 metadata. The Android app never downloads, refreshes or queries a remote feed.
- **WorkManager:** performs bounded, user-authorized folder rescans. Android can defer these jobs; they are not a continuous monitoring daemon.

## File inspection and privacy

SATARK reads raw bytes because cryptographic hashing and signature checks require bytes. It does not semantically read or display document content.

Permitted inspection:
1. File name and size supplied by Android.
2. SHA-256 over the complete bounded file.
3. A bounded header read for known file-format signatures.
4. Filename extension versus detected-signature consistency.
5. Exact local SHA-256 lookup against the imported historical snapshot.
6. Optional byte-pattern rules on platforms where a reviewed YARA engine is installed.

Not performed:
- No document text extraction, OCR, image rendering, PDF preview or media decoding.
- No archive extraction, macro execution, script execution or sandbox execution.
- No file modification, deletion, upload or automatic quarantine.
- No WhatsApp/Telegram chat database access or access to another app's private storage.

A clean result means **"No known threat detected by enabled local checks."** It is not proof that the file is safe. Exact SHA-256 matching only identifies byte-identical files present in the selected snapshot.

## Android file access

- `ACTION_SEND` and `ACTION_SEND_MULTIPLE` receive files explicitly shared from WhatsApp, Telegram, browsers, email clients and file managers.
- `ACTION_OPEN_DOCUMENT` lets the user select individual files.
- `ACTION_OPEN_DOCUMENT_TREE` grants access only to a directory the user explicitly selects.
- Persisted folder access can be stopped or revoked from SATARK.
- The app cannot bypass Android's sandbox or read private messaging databases/directories.

Android's Storage Access Framework deliberately grants URI-based access to user-selected documents and trees. It does not grant arbitrary access to another app's private storage.

## Local protection and scheduling

A shared file is scanned immediately while the sender's URI grant is available. Folder scans are bounded by file count, recursion depth, per-file bytes and total run bytes. Users can request an immediate scan or opt into a 15-minute minimum periodic interval or a daily interval.

Periodic WorkManager jobs are inexact and may be deferred by Doze, battery saver, standby, OEM scheduling and document-provider availability. "24/7 protection" is therefore not a truthful platform guarantee. SATARK provides immediate inspection of shared files plus best-effort scheduled rescans; it does not continuously monitor every app or every filesystem event.

## Historical threat intelligence

EMBER2024 is a research feature dataset with SHA-256 labels and metadata for Win32, Win64, .NET, APK, ELF and PDF samples collected through 2024-12-14. It is not a universal live malware feed. SATARK converts labelled metadata only; it does not download or bundle malware binaries.

- Label 0 is benign, label 1 is malicious and unlabeled rows are excluded.
- Imports are explicit, local and provenance-labelled.
- A frozen dataset cannot discover threats first observed after its cutoff.
- A modified file has a different SHA-256 and may not match.
- Dataset coverage depends on the selected file types and splits.
- A no-match result is not a benign classification.

## YARA support

The repository includes an original local starter rule pack for PowerShell download/execute combinations, PDF active-content markers, OLE macro automation, JavaScript obfuscation clusters and standalone DEX dynamic-loading patterns. These are review heuristics, not definitive malware signatures. Their false-positive notes and synthetic regression corpus are documented in [LOCAL_YARA_RULES.md](LOCAL_YARA_RULES.md).

The desktop Python workflow can use optional `yara-python`. The Android APK does not currently bundle the native YARA engine; mobile detection remains SHA-256, fixed signatures, extension checks and filename heuristics. Do not claim mobile YARA support until a native Android ABI build and physical-device tests pass.

## Supabase-free supporting web backend

The optional legacy web workspace uses SATARK-owned FastAPI, SQLAlchemy and Alembic components. SQLite is the zero-configuration local/single-host option; PostgreSQL is optional for a self-hosted multi-instance deployment. This backend is independent of the Android scanner.

The application has no Supabase SDK, Supabase Auth, PostgREST, Supabase Storage, Supabase RPC, Supabase project URL or Supabase key requirement. The obsolete Supabase CLI configuration and migration directory have been removed. Existing data from any former hosted project is not automatically migrated or deleted; any needed export is a separate operator-owned task.

## Design references

- [Hallmark](https://github.com/Nutlope/hallmark): design review principles, hierarchy, accessibility and implementation QA.
- [shadcn/ui](https://github.com/shadcn-ui/ui): composable UI and accessibility patterns; not included as an Android runtime dependency.
- [Magic UI](https://github.com/magicuidesign/magicui): restrained motion and visual inspiration; React components are not used in the native app.
- [Tremor](https://github.com/tremorlabs/tremor): dashboard and data-visualization patterns; not included in the native runtime.
- [NirDiamant/GenAI_Agents](https://github.com/NirDiamant/GenAI_Agents): specialist routing and evidence trace ideas. Its model/API tutorial dependencies are not used; deterministic agents are preferable for reproducible offline byte inspection.

No code is vendored from those projects. Their licenses and runtime assumptions differ, and the Android product intentionally avoids unnecessary dependencies and hosted services.

## Release acceptance

A production release requires all of the following:
- Exact-commit Python, bridge, offline-contract, YARA and Android build tests pass.
- Physical-device validation of WhatsApp/Telegram sharing, multiple attachments, URI revocation and Android document providers.
- WorkManager validation across reboot, Doze, battery saver, low storage, interrupted scans and provider failures.
- Real EMBER2024 snapshot import with preserved provenance and checksum manifests.
- A representative independently labelled evaluation corpus and human-reviewed false positives; synthetic fixture metrics must not be marketed as real-world accuracy.
- Memory, CPU, latency and battery measurements on low- and mid-range Android devices.
- Signed release APK/AAB, privacy disclosures, store policy review and release signing-key custody.
- A clear incident and rollback plan.

A successful CI build verifies only the checks that ran. It does not substitute for physical-device testing, a signed release or measured detection quality.
