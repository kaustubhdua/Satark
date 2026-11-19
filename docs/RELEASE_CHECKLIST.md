# Release checklist (copy per release, fill every line, link evidence)

A release is not "done" until each item has a link, a value, or an explicit **N/A with reason**.
Leave anything unverified as **NOT VERIFIED**; do not tick it.

## Identity
- [ ] Commit SHA: `________` (must equal the deployed build)
- [ ] Tag / release notes: ________
- [ ] Deployment ID / host: ________
- [ ] Rollback target (previous SHA or image digest) and tested rollback command: ________

## Automated evidence (link each run)
- [ ] Python suite (`pytest tests`) — run URL: ________
- [ ] Web: typecheck, `npm test`, production build — run URL: ________
- [ ] Browser + accessibility smoke (desktop and mobile) — run URL: ________
- [ ] PostgreSQL integration with RLS (`SATARK_TEST_POSTGRES_URL`) — run URL: ________
- [ ] Container image builds and compose config — run URL: ________
- [ ] Dependency audits (`pip-audit`, `npm audit`) — open alerts: ________
- [ ] Live journey (`web/tests/live-journey.mjs`) against the release candidate — output: ________

## Configuration (see `docs/SELF_HOSTING.md`)
- [ ] `.env` generated with `scripts/bootstrap_selfhost.py`; secrets stored outside git
- [ ] `/tools` readiness rows read as expected: storage ____ · rate limiting ____ · FIRSTLIGHT API ____ · Wazuh ____
- [ ] `GET /api/health/storage` answers on the API; rate limiter returns HTTP 429 under a test burst
- [ ] Backups: last restore drill date and result (`scripts/postgres_backup_restore_drill.py`): ________

## Manual / environment-dependent (record NOT VERIFIED if not run)
- [ ] Wazuh live acceptance (`scripts/accept_firstlight_wazuh_live.py`): ________
- [ ] SMTP verification and password-reset email delivered: ________
- [ ] MFA enrollment and sign-in: ________
- [ ] S3 evidence backend against the real bucket (if enabled): ________
- [ ] Android APK on a physical device: ________

## Known limitations shipped with this release
- [ ] Listed in release notes (supported formats: `docs/SUPPORTED_FORMATS.md`; auth matrix: `docs/AUTHORIZATION_MATRIX.md`)
- [ ] Missing provider dependencies and unresolved security findings with documented risk acceptance: ________

Sign-off: ________ (name, date)
