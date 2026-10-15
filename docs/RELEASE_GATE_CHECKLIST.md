# SATARK Release Gate Checklist

Use this checklist before merging a security-sensitive change or promoting a revision to production. A green unit-test job alone is not a release decision.

## 1. Protect the release branch

Configure repository rules for `main` in GitHub settings; a Markdown file in the repository does not enforce these settings.

- Require pull requests; prohibit direct pushes, force pushes, and branch deletion.
- Require the always-on checks for the exact head SHA: `validate` (CI), `frontend` (Web CI), `test` (SATARK AI CI), and `Analyze Python` (the CodeQL workflow job). Confirm exact check names and originating apps on a fresh test pull request before saving the ruleset.
- The Web CI and SATARK AI CI workflows must run on every pull request before their checks are required; path filters on pull requests can leave required checks pending.
- Confirm whether GitHub exposes an additional distinct `CodeQL` check beyond the `Analyze Python` job before requiring it. Do not guess or require duplicate contexts without verification.
- Require approval from a reviewer other than the author where a second reviewer is available; dismiss stale approvals after new commits and require conversations to be resolved.
- Require all required checks to pass for the exact head SHA. A skipped production-smoke job is not evidence that production is healthy.
- `Production smoke check` is triggered by deployment status, schedule, or manual dispatch rather than ordinary pull requests. Treat it as a post-deployment release gate, not a required merge check.
- Revisit rules whenever workflow/job names change. Do not silently remove a failing check to make a merge possible.

## 2. Security and data-isolation gate

- Run the complete repository test suite, typecheck, production build, and browser smoke/accessibility tests on the exact candidate SHA.
- Verify request and response byte limits before parsing/buffering, including malformed `Content-Length`, missing `Content-Length`, fragmented streams, invalid UTF-8, oversized multipart input, and stored-evidence downloads.
- Verify that deterministic findings, score, category, and next steps remain authoritative; optional model output is untrusted interpretation only.
- Confirm decoded QR destinations are never fetched or opened automatically. Only the explicit same-origin analysis request is permitted.
- Run cross-tenant read/write, viewer-role, evidence-object access, tamper, retention, and deletion tests with separate least-privilege non-production accounts.
- Inspect the Supabase project, schema, and migration history before database work. Preserve `satark_*`, RLS, private storage, and unrelated Nihdhoom data. Apply only reviewed forward-only idempotent migrations; no destructive migration without explicit approval.
- Keep production rate limiting fail-closed. A missing or unavailable shared limiter is a release blocker, not a reason to fall back to process-local limits.

## 3. Provider and infrastructure gate

- Configure shared rate limiting through the authorized deployment account. Never place secrets in source control, issues, logs, screenshots, or chat.
- Test provider timeout, redirect, malformed response, oversized response, and outage paths. Report unavailable providers as unavailable; never fabricate a verdict or successful lookup.
- Confirm Vercel deployment status and relevant usage/storage counters before starting a build. If `build-rate-limit` is active, stop repeated build attempts and investigate usage through normal account controls.
- Do not upgrade, spend, change DNS/credentials, delete deployments, or bypass quota controls as part of a routine release.
- Confirm that the selected production deployment's Git commit SHA exactly matches the intended release SHA.

## 4. Production smoke gate

After the authorized deployment is ready, verify the exact production alias and SHA, then test:

- `/api/health` and its dependency/configuration reporting;
- `/api/analyze` with benign and suspicious synthetic inputs, including expected fail-closed behavior if shared limiting is not configured;
- `/tools`, `/qr`, `/investigate`, `/image-review`, `/reports`, and `/firstlight`;
- sign-in, tenant-scoped case creation/read/update, evidence upload/verification, and export using synthetic non-production data;
- desktop and narrow-mobile layouts, keyboard navigation, readable errors/loading/empty states, and automated accessibility checks;
- response security headers and absence of user-supplied URL destination fetches.

Do not infer health from an empty error-log window. Record each check as PASS, FAIL, BLOCKED, or NOT TESTED with the candidate SHA and timestamp.

## 5. Rollback and operational readiness

- Identify the previous known-good production deployment and rehearse the documented rollback path without deleting evidence or unrelated deployments.
- Confirm backup/restore evidence, retention/deletion behavior, incident ownership, alert routing, and provider outage handling.
- Record unresolved limitations, including any feature not migrated (for example, PDF/document or video/media analysis) and any browser-dependent QR support.
- Stop release promotion on any unresolved tenant-isolation, authorization, data-loss, rate-limit, or provenance failure.

## Release decision record

Record the repository SHA, production deployment ID/SHA, required-check results, tenant-isolation result, rate-limit/provider result, smoke/accessibility result, rollback reference, known limitations, and approving owner. Never mark an unexecuted check as passing.
