# SATARK release hardening checklist

This checklist is evidence-based. A code change or green build is not proof of a successful live deployment.

## Automated checks
- [ ] Frontend dependency lockfile is committed and npm ci succeeds from a clean checkout.
- [ ] Frontend TypeScript check and production build pass.
- [ ] FIRSTLIGHT CSV parser unit tests pass.
- [ ] Existing Python unit tests and browser smoke tests pass.
- [ ] CodeQL and dependency vulnerability checks pass with no untriaged high/critical findings.

## Runtime verification
- [ ] Desktop browser smoke test at 1440px and mobile test at 390px; no horizontal overflow.
- [ ] Main navigation, back/forward navigation, form validation, loading/error states, and FIRSTLIGHT import/export workflows verified.
- [ ] API success and controlled failures tested using synthetic, non-sensitive inputs.
- [ ] Provider key and model confirmed in the hosting environment without exposing secret values.
- [ ] Public deployment commit SHA matches the approved release commit.
- [ ] Rollback path and monitoring owner confirmed.

## Boundaries
FIRSTLIGHT is a synthetic training workspace. Its in-browser hashes are not an externally anchored chain of custody. The Groq route's in-memory rate limiter is best-effort and is not a shared/global abuse control. Do not represent these features as production forensic guarantees.

## Sign-off
Release status: **BLOCKED until all applicable checks above have recorded passing evidence.**
