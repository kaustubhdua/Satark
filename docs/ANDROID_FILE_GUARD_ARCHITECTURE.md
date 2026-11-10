# SATARK File Guard — product and technical contract

**Product direction:** Android-first, Python-based, offline-first file threat inspection.

## Non-negotiable product boundaries

- The Android application is the primary product. Streamlit, Next.js, FIRSTLIGHT and the self-hosted web backend are legacy/supporting repository components, not required to scan files on Android.
- No Supabase runtime, hosted threat-intelligence API, cloud AI, telemetry upload, remote hash lookup, or Internet permission in the Android application.
- Kotlin is used only for OS integration (sharing, document-provider URIs, permissions, notifications and WorkManager). Python performs fingerprinting, signature checks, local intelligence lookup and scan-history persistence.
- No message-body access, chat database access, OCR, document text extraction, preview rendering, archive extraction, file execution, modification or deletion.
- Only files shared to SATARK or files within a directory explicitly granted by the user are in scope. The app cannot bypass Android's sandbox to inspect private WhatsApp or Telegram directories.
- Threat intelligence is frozen and imported explicitly by the user. Scanning never downloads or refreshes intelligence.

## What "does not read file content" means

The scanner must read bytes for SHA-256 and static signature checks. It does not interpret user-facing content. The permitted inspection surface is:

1. File size and display name supplied by Android.
2. SHA-256 over the complete byte stream.
3. Bounded header/form signatures used to identify the actual format.
4. Extension-versus-signature consistency.
5. Exact local hash lookup against a provenance-labelled historical snapshot.
6. Optional local byte-pattern rules only where a compatible rules engine and reviewed rule pack are installed.

No result may claim that an unrecognised or unmatched file is safe. The correct clean-state wording is **"No known threat detected by enabled local checks."**

## Android access model

- ACTION_SEND and ACTION_SEND_MULTIPLE: explicit Share-to-SATARK from WhatsApp, Telegram, browsers and file managers.
- ACTION_OPEN_DOCUMENT: user-selected files.
- ACTION_OPEN_DOCUMENT_TREE: user-selected folder tree with persistable read permission.
- No attempt to read another app's private database, private internal directory, or inaccessible Android/data / Android/obb paths.
- Folder scans use bounded WorkManager jobs. Android may defer periodic work due to Doze, battery policy, storage-provider availability or OEM behavior. The 15-minute interval is the platform minimum, not a real-time guarantee. Do not market this as uninterrupted 24/7 surveillance.
- A scan is triggered immediately for an explicitly shared file; periodic folder rescans are a best-effort safety net.

## Historical intelligence

EMBER2024 is a research dataset containing features and labels for roughly 3.2 million samples across Win32, Win64, .NET, APK, ELF and PDF, with a collection window ending 2024-12-14. It is not itself a ready-made universal malware hash feed. SATARK's converter extracts SHA-256 labels from dataset metadata; it does not download or bundle malware binaries. The app imports CSV snapshots locally and stores provenance.

Important limitations:
- Exact SHA-256 matching only identifies byte-identical samples represented in the imported snapshot.
- Any modification changes the hash and can evade exact matching.
- EMBER2024's file-type and time coverage is not universal; coverage varies by imported split and type.
- YARA and format signatures add different forms of coverage, but must not be described as proof of malware or safety.
- The frozen snapshot cannot identify newly discovered threats unless the user deliberately imports a separately versioned offline snapshot. That is outside the default no-new-data operating mode.

## Storage and privacy

- SQLite databases are stored in Android app-private storage.
- Scan history stores metadata and hashes, not file bytes.
- Incoming content URIs are read under temporary share grants. User-selected folder grants are persisted only after explicit consent.
- Scans have explicit file-count, directory-depth, per-file and per-run byte limits.
- No network permission is present in the Android manifest. Android CI enforces this as a contract.

## Release acceptance gates

A release is not complete until:
- Python unit tests pass for the root scanner and Android-bundled scanner parity.
- Android debug APK builds in CI.
- CI verifies no Android Internet permission and no network client usage in Android Python sources.
- Share-to-app, multi-share, picker, persisted folder permission, revocation, scan cancellation and notifications are tested on physical Android devices.
- WorkManager scheduling is tested across reboot, Doze, battery saver, low storage and revoked document-provider grants.
- Dataset import is tested with real, licensed EMBER2024 metadata snapshots and a verified manifest; no synthetic malware data is shipped.
- Performance, memory use, battery impact and scan limits are measured on representative low- and mid-range devices.
- Privacy policy, Play listing disclosures, signing, release APK/AAB and store-policy review are complete.

## Upstream references

- Android scoped storage: https://developer.android.com/about/versions/11/privacy/storage
- Storage Access Framework: https://developer.android.com/training/data-storage/shared/documents-files
- WorkManager periodic work: https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work
- EMBER2024 upstream: https://github.com/FutureComputing4AI/EMBER2024
- YARA documentation: https://yara.readthedocs.io/
- Chaquopy documentation: https://www.chaquo.com/chaquopy/doc/current/android.html

## Upstream design and implementation references

The requested open-source projects were reviewed for fit:

- [Hallmark](https://github.com/Nutlope/hallmark) is a design-quality skill for code agents. Apply its principles (clear hierarchy, real app task first, contrast/focus/reduced motion, responsive QA) when polishing interfaces; it is not an Android component library.
- [shadcn/ui](https://github.com/shadcn-ui/ui) provides accessible, composable React/web components under MIT. Reuse its interaction and accessibility patterns only if a separate web companion is built; do not add React to the native Android runtime.
- [Magic UI](https://github.com/magicuidesign/magicui) provides animated React/Tailwind components. Its animation restraint and visual ideas can inform the web companion, but its components do not drop into Android Views.
- [Tremor](https://github.com/tremorlabs/tremor) provides React dashboard components under Apache-2.0. Its chart/dashboard patterns can inform a future web analytics view; Android should use native UI primitives.
- [NirDiamant/GenAI_Agents](https://github.com/NirDiamant/GenAI_Agents) is a collection of generative-agent tutorials with a custom non-commercial license. It is not adopted as a scanner dependency: deterministic byte signatures and hash lookups are more reproducible, smaller, private and API-free for this product.

No code from these projects is vendored into the Android app. This avoids license ambiguity, unneeded web dependencies, and a mismatch between the user's offline/no-API requirement and agent frameworks that commonly rely on model orchestration or external services.

## Dataset snapshot and reproducibility

EMBER2024 is a labelled malware-research feature dataset, not a complete portable list of malware signatures. Its published corpus includes about 3.2 million records across Win32, Win64, .NET, APK, ELF and PDF, from 2023-09-24 through 2024-12-14. The challenge subset has 6,315 malicious records. SATARK can turn supported upstream hash/label metadata into a local SQLite import, but a research feature vector is not the original file and does not provide complete detection coverage.

For each snapshot imported into a device, the operator should retain the upstream source name, upstream release/cutoff, selected splits/file types, original and converted file SHA-256 values, conversion tool version, row counts, malicious/benign counts, and license. The app currently stores a source label per hash and does not yet enforce a cryptographically immutable whole-snapshot manifest; the source label is provenance metadata, not proof of authenticity. Do not claim otherwise.

The Android app intentionally does not fetch a dataset itself. Dataset acquisition and conversion are explicit offline preparation tasks on a trusted workstation; transfer only the converted CSV and manifest to the phone. The app is empty until this step occurs.

## Device memory/performance boundary

The current Kotlin bridge uses a bounded in-memory byte array (64 MiB per file) before calling Python. That provides a simple bounded scan contract, but it means a 64 MiB file can temporarily require more memory than its file size due to buffers, byte-array copies and Python interop. For low-memory Android devices, measure peak resident memory and latency before increasing limits. A future streaming Chaquopy bridge must be proven with Android ContentResolver streams before replacing this path.

