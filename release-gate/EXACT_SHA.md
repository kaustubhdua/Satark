# Exact-commit release gate

This manifest is a deliberate trigger for a coordinated full-stack validation. The Android File Guard, FIRSTLIGHT API, Web CI, general CI, CodeQL and Phase 0 inventory workflows must all evaluate the same candidate SHA.

## Candidate validation contract

- The CI run set must show the exact same commit SHA for every workflow.
- All required jobs must complete successfully; neutral, skipped, cancelled, pending or missing checks are not green.
- Android CI must build the APK, run offline engine tests, and pass the emulator launch/accessibility smoke test.
- FIRSTLIGHT CI must run the Wazuh response adapter tests, PostgreSQL integration and isolated pg_dump/pg_restore drill, production Compose validation, and container build/import checks. The dedicated Restic backup image must also build successfully and prove that its pg_dump client matches the production PostgreSQL 16 major version.
- Web CI must pass type-checking, tests, dependency audit, production build, browser smoke and accessibility checks.
- General CI must pass tenant isolation, authenticated case/evidence/report workflows, backup archive round-trip tests and browser checks.

The manifest itself does not claim any environment-dependent acceptance test. Physical Android, a live authorized Wazuh manager/agent, and a public production host still require separate operator evidence.


## Latest response adapter gate

The legacy direct-response CLI is preview-only. Real actions are available only through the authenticated FIRSTLIGHT case approval API, with Wazuh-only fixed commands and explicit agent allowlists.


## PostgreSQL role hardening

The dedicated backup role is NOINHERIT and BYPASSRLS. It has explicit read privileges for backups and membership only for controlled restore ownership transfer; the API runtime role does not receive BYPASSRLS or backup credentials.


## Agent allowlist intersection

The account-disable action is advertised only when its OS-specific agent IDs intersect the general live-response allowlist. The API rechecks both lists at execution time.


## Regression cleanup

The legacy response-action test suite now validates the Wazuh guardrails, the response ledger test asserts numeric agent binding, and the archive includes the SQLite response-ledger snapshot helper.

## Provider independence invariant

- The runtime source, dependency manifests, container configuration, Android app source, web source, and deployment configuration must remain free of Microsoft Defender/Entra SDKs, endpoints, OAuth credentials, and provider-specific response actions.
- The CI boundary scan covers the complete web app (including build configuration), Android sources and Gradle manifests, Python services/scripts, container/deployment configuration, and GitHub workflow definitions.
- `scripts/check_no_microsoft_runtime.py` enforces this invariant in FIRSTLIGHT API CI. Historical migration documentation may describe the removal; it is not a runtime dependency.
- Wazuh is the supported endpoint telemetry/response integration. Keep Active Response disabled until the authorized disposable-agent acceptance gate passes.

## Off-host backup gate

- The production backup profile uses the open-source Restic client and refuses to report success unless the encrypted archive is uploaded to a separately configured repository and the repository check completes.
- The remote repository password must be held outside the host and outside Git; the backup container receives it as a read-only secret.
- A successful CI pg_dump/pg_restore test is not proof that the production S3-compatible repository or independent recovery host is configured. Record a real restore drill before production acceptance.
