# Exact-commit release gate

This manifest is a deliberate trigger for a coordinated full-stack validation. The Android File Guard, FIRSTLIGHT API, Web CI, general CI, CodeQL and Phase 0 inventory workflows must all evaluate the same candidate SHA.

## Candidate validation contract

- The CI run set must show the exact same commit SHA for every workflow.
- All required jobs must complete successfully; neutral, skipped, cancelled, pending or missing checks are not green.
- Android CI must build the APK, run offline engine tests, and pass the emulator launch/accessibility smoke test.
- FIRSTLIGHT CI must run the Wazuh response adapter tests, PostgreSQL integration and isolated pg_dump/pg_restore drill, production Compose validation, and container build/import checks.
- Web CI must pass type-checking, tests, dependency audit, production build, browser smoke and accessibility checks.
- General CI must pass tenant isolation, authenticated case/evidence/report workflows, backup archive round-trip tests and browser checks.

The manifest itself does not claim any environment-dependent acceptance test. Physical Android, a live authorized Wazuh manager/agent, and a public production host still require separate operator evidence.
