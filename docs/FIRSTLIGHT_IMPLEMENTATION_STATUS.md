# SATARK / FIRSTLIGHT implementation status — 2026-11-12

## Current architecture

SATARK and FIRSTLIGHT are a self-hosted, open-source-first security product. SATARK Android File Guard is the offline file-inspection application. FIRSTLIGHT is the authenticated case investigation, evidence, and guarded response workspace.

- **No hosted service dependency for Android scanning:** Android uses a native Kotlin shell and embedded Python inspection engine. Share-to-SATARK, the system picker, Storage Access Framework grants, bounded WorkManager scans, local scan history and evidence export are supported. The Android manifest has no Internet permission.
- **No managed database requirement:** the backend supports PostgreSQL for multi-worker production and SQLite for local single-instance use. Evidence objects are stored privately under the configured evidence directory.
- **FIRSTLIGHT investigation:** deterministic evidence sealing and verification, triage, correlation, timelines, evidence gaps, bounded imports, findings and report snapshots are persisted through the self-hosted API and worker.
- **Identity and workspace:** the Next.js app uses a same-origin server proxy and self-hosted session cookies. Tenant membership is checked server-side for cases, evidence, findings, reports, notes, approvals and audit workflows.
- **Wazuh ingestion:** read-only Indexer preview and an optional persistent worker are supported. The worker filters to an explicit agent allowlist, preserves source records and hashes, uses bounded overlapping query windows, deduplicates events and advances checkpoints only after durable persistence.
- **Wazuh response:** the current adapter is compatible with Wazuh Manager 4.14.x (lab bootstrap pinned to 4.14.10); it checks `/manager/info` and refuses Wazuh 5.x. Only fixed built-in Active Response commands are allowed: `firewall-drop` for a validated IPv4 address and `disable-account` for a validated local account on a separately allowlisted Linux/macOS lab agent. Actions are bound to one case and one numeric agent ID. A requester, distinct approver, third executor and independent verifier are required. The durable ledger records approval and execution state; ambiguous outcomes become `unknown` and are never retried automatically.
- **Local model support:** optional Ollama specialists can provide advisory summaries. Deterministic evidence and findings remain authoritative. Core workflows do not require hosted AI API keys.

## Wazuh-only provider boundary

FIRSTLIGHT uses Wazuh as its only endpoint telemetry and endpoint-response integration. The product has no proprietary endpoint-security SDK, external tenant registration, third-party identity dependency, response adapter or credential requirement. The API, web UI, CLI preview and documentation all describe the same Wazuh-only action model.

## Current validation

- Android Python engine tests and native APK compilation have passed on recent candidate revisions.
- The SATARK command-centre visual refresh is merged to `main` in PR #245. The evidence-first FIRSTLIGHT workspace is under review in PR #246; its exact-head API, web, container, CodeQL and general CI checks must finish successfully before merge.
- CodeQL and Phase 0 inventory have passed on recent candidate revisions.
- FIRSTLIGHT API, PostgreSQL integration, container and Android emulator jobs are still subject to exact-head completion. A cancelled or superseded run is not a pass. CI uses explicit unit-test fixtures only; the production FIRSTLIGHT workspace does not preload sample incidents.
- The CI PostgreSQL backup test uses a temporary database and a real `pg_dump` / `pg_restore` round trip. It is not a restore drill against the eventual production database.

## Release gates still open

1. **Exact candidate SHA:** all required Android, web, API/PostgreSQL/container, general CI, CodeQL, inventory and production-smoke contract checks must pass on the same final PR head. Neutral, skipped, cancelled, pending or missing checks are not green.
2. **Authorized Wazuh lab:** an operator must provision the pinned Wazuh 4.14.10 Docker lab, rotate all upstream default credentials, configure trusted TLS, create a read-only Indexer identity, enroll disposable agents and provide private Manager/Indexer endpoints and credentials. Do not upgrade the response integration to Wazuh 5.x without implementing and testing its new event-driven Active Response workflow.
3. **Representative alerts:** ingest actual alerts from the authorized lab and verify agent allowlisting, source preservation, hashes, tenant/case linkage, checkpoint advancement, duplicate handling and restart recovery.
4. **Wazuh Active Response:** keep the feature flag disabled until fixed commands have been tested against disposable allowlisted agents, including endpoint-side verification and an independently tested reversal/recovery path.
5. **Tenant isolation:** run authenticated cross-tenant negative tests with separate non-production identities. A skipped test caused by absent secrets is not a pass.
6. **Android device QA:** verify WhatsApp/Telegram share intents, picker/SAF grant and revocation, reboot, Doze and OEM behavior on physical supported devices. Emulator success is not a physical-device acceptance test.
7. **Malware evaluation:** evaluate an independently labelled real-file corpus and publish coverage, false-positive and false-negative results. A training hash snapshot is not antivirus assurance.
8. **Backup/restore:** run a quiesced, encrypted, off-host archive and isolated restore covering PostgreSQL/SQLite data, evidence objects and the FIRSTLIGHT response ledger. Verify hashes, audit chain, tenant isolation and application readback.
9. **Production:** configure a production host, DNS, TLS, secrets, durable volumes, private Wazuh network connectivity, email/MFA policy, monitoring, backup retention, release signing and rollback. Deploy the exact tested commit and verify `/api/version`, routes and authenticated workflows after deployment.

## Current release decision

**NO-GO for production readiness.** The code contains the intended self-hosted Wazuh-only architecture, evidence-first workspace and guarded response path, but real lab, device, tenant, backup and production acceptance evidence has not been supplied or independently verified. The response feature flag must remain disabled until the applicable lab gates above are complete. A green CI run alone is not production acceptance.

## Operator references

- [Wazuh lab setup and ingestion](FIRSTLIGHT_WAZUH_INTEGRATION.md)
- [Wazuh Active Response controls](FIRSTLIGHT_LIVE_RESPONSE.md)
- [Backup and restore](FIRSTLIGHT_BACKUP_RESTORE.md)
- [Production deployment](PRODUCTION_DEPLOYMENT.md)
- [Android File Guard architecture](ANDROID_FILE_GUARD_ARCHITECTURE.md)
- [Product completion roadmap](PRODUCT_COMPLETION_ROADMAP.md)
