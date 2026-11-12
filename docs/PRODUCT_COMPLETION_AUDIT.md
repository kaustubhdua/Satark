# SATARK product completion audit

**Review date:** 2026-11-12  
**Repository:** `kaustubhdua/Satark`  
**Release posture:** release candidate under validation; **not accepted for production incident data yet**  
**UI refresh:** PR #245 merged to `main`  
**Evidence-first FIRSTLIGHT changes:** PR #246 open; exact-head CI required

This audit separates implemented code, automated test evidence, and external operational acceptance. A feature is not production-ready because a screen exists, a configuration template exists, or a CI mock passes.

## Product definition

SATARK is an offline Android file-inspection application and a self-hosted security operations platform. FIRSTLIGHT is the case-based investigation and evidence workspace. Wazuh is the open-source endpoint telemetry and guarded response integration. The product does not depend on Microsoft Defender or hosted AI for its core deterministic workflows.

The website should present the working operations product, not a hackathon pitch. The command-centre visual refresh was merged in PR #245. The evidence-first FIRSTLIGHT workspace changes in PR #246 remove the seeded training incident and session-only simulated response decisions from the main investigation workflow.

## Production deployment observed on 2026-11-12

The current production Vercel deployment was queried directly, not inferred from a preview:

- Production deployment: `dpl_GnsYvPmnkg1sGPPedaBJed9ZUbP4`, state `READY`, source `main`.
- Deployed revision: `b9ac20e07c7360803d93fe111c795f405b1b15fd`.
- `/api/version` returned the same revision.
- `/api/health` returned `configuration-only`, not a live dependency probe.
- The snapshot reported FIRSTLIGHT investigation proxy and Wazuh proxy as **not configured**, and persistent storage as **not configured**.
- Shared Upstash rate limiting was configured but its live connectivity was explicitly unverified.
- The production Vercel environment-variable inventory did not include `SATARK_API_INTERNAL_URL`; no self-hosted API upstream is currently wired to this deployment.
- Public route smoke checks returned HTTP 200 for `/`, `/investigate`, `/tools`, `/firstlight`, `/url`, `/qr`, `/pdf-review`, `/image-review`, `/media-review`, `/cases`, `/reports`, `/login`, `/native-sensor`, `/learn`, `/api/version` and `/api/health`. A page returning 200 proves route rendering only, not that its authenticated workflows or backing services work.
- `GET /api/auth/session` returned HTTP 503 with `The self-hosted SATARK API is not configured.`; `GET /api/firstlight/wazuh/alerts?limit=1` returned the same 503. Login, persistent cases and Wazuh access are therefore not operational through the current production deployment.
- The unauthenticated `/firstlight` request returned the secure-session loading shell. An authenticated case workflow has not been exercised against production.

**Consequence:** production currently serves the Next.js website and local deterministic analysis surfaces, but FIRSTLIGHT persistence, Wazuh preview/ingestion and guarded response are not live through the public deployment. The health endpoint correctly discloses this. Do not describe the whole product as live or production-ready until the private API, durable database/evidence storage, and authorized Wazuh lab are connected and verified.

## Implementation vs acceptance

| Area | Implemented in repository | Still required before production acceptance |
| --- | --- | --- |
| Website | Responsive operations-console styling, interaction states, keyboard focus, reduced-motion support | Inspect authenticated production deployment at desktop/mobile sizes against exact deployed SHA |
| FIRSTLIGHT evidence | Wazuh alert preview, permitted JSON/CSV imports, digest checks, persistent case path, evidence-linked findings | Authorized Wazuh source; verify provenance and saved-case readback |
| Import integrity | Source timestamps/summaries mandatory; missing source fields remain unknown; source IDs preserved; absent IDs receive a visibly labelled digest-derived local import key | Validate real exports from each supported source and document field compatibility |
| Production data policy | No seeded sample incident in production FIRSTLIGHT workspace; no fabricated alert summaries or event timestamps | Keep test fixtures isolated to tests; review integrations for demo fallbacks |
| Identity and tenancy | Self-hosted session cookies, same-origin proxy, database authorization and PostgreSQL RLS implementation | Separate non-production identities; adversarial cross-tenant and concurrency tests on deployed non-owner roles |
| Wazuh ingestion | Read-only Indexer integration and persistent worker with agent allowlisting, source snapshots, deduplication and checkpoints | Provision private Wazuh 4.14.10 lab, rotate defaults, trusted TLS, read-only credentials, actual alerts and restart/replay tests |
| Wazuh response | Separate guarded Manager workflow, fixed built-in actions, numeric agent allowlists, distinct requester/approver/executor and independent verification states | Keep disabled; test disposable lab agents, target binding, approval expiry, replay resistance, ambiguous outcomes, reversal and endpoint state |
| Android File Guard | Offline Android manifest/runtime, native shell, Python inspection engine, local history and export | Physical-device QA across supported Android/OEM versions, Share/SAF permission lifecycle, reboot, Doze and large files |
| Detection quality | Deterministic byte/structure checks, historical hash matching, explainable evidence-linked findings; EMBER2024 APK hash subset documented | Independently labelled real-file evaluation; publish coverage, false-positive/negative rates, corpus date/licensing and abstention behavior |
| Database and durability | PostgreSQL/SQLite persistence, Alembic migrations, tenant RLS, private evidence storage, backup utilities | Production privilege review; encrypted off-host backup; isolated restore, evidence readback, tenant checks, measured RPO/RTO and retention/deletion signoff |
| Operations | Docker Compose production template, Caddy/Nginx edge configuration, health/readiness routes, workers and deployment docs | Actual host, DNS/TLS, durable volumes, secrets, private Wazuh network, monitoring, incident owner and tested rollback |
| CI and supply chain | GitHub Actions, CodeQL, dependency audits, browser/accessibility smoke and PostgreSQL/container validation | All required checks green on exact final PR SHA; review advisories and pin/review container image digests |

## Real-data policy

- Production FIRSTLIGHT must load only real Wazuh records or explicitly imported source artifacts; no sample incident is preloaded.
- A missing source ID is not represented as a provider-issued ID. The UI labels a deterministic uploaded-file-digest-derived row key as a **local import identifier**.
- Missing source names and event types remain explicitly unknown.
- Wazuh preview records are previews, not saved evidence. The UI preview path does not claim to preserve the complete original Indexer document; the persistent worker is the source-preserving ingestion path.
- Unit tests necessarily use isolated test fixtures. Those fixtures are not production telemetry and must never be copied into deployment data.
- The Android EMBER2024 hash subset is a research/training indicator dataset, not live telemetry, a full malware corpus or a guarantee that an unflagged file is safe.
- Hash matching proves equality with a referenced digest only. It does not prove who collected a record, when it existed or whether the original source was truthful.

## Security and response boundaries

- Wazuh Indexer search is authenticated and read-only for alert ingestion. Wazuh Manager API is a separate privileged control plane.
- Wazuh response remains disabled by default. Do not set `SATARK_ENABLE_LIVE_RESPONSE=true` outside an authorized isolated lab until the full response acceptance suite has passed.
- A Wazuh alert is a detection signal, not independent proof of compromise. A successful API response is not sufficient proof that endpoint state changed.
- Browser activity is not a durable external audit anchor. Evidence storage and the response ledger require backup, restore and privileged-administrator threat review.
- Never connect production identities or endpoints to containment tests. Use disposable allowlisted agents and explicit recovery procedures.
- Do not submit sensitive incident evidence until tenant isolation, backup/restore, monitoring and deployment controls are independently accepted.

## Exact release gates

1. Complete PR #246 exact-head API, web, general CI, CodeQL and inventory checks. Pending, cancelled, skipped, neutral or superseded runs are not passes.
2. Reconcile PR #243 and release-gate changes without merging unverified or unrelated work.
3. Provision the private Wazuh 4.14.10 lab and verify Indexer ingestion with representative real alerts.
4. Validate guarded response only against disposable agents, including reversal and independent state verification. Keep the feature disabled otherwise.
5. Run authenticated multi-tenant negative tests with separate identities and a non-owner database role on the deployed candidate.
6. Perform physical Android device acceptance.
7. Run an independently labelled malware evaluation and publish measured limitations.
8. Run encrypted off-host backup and isolated restore; verify restored evidence readback and tenant boundaries.
9. Deploy the exact accepted SHA with TLS, secrets, persistent volumes, edge rate limits, monitoring and rollback.
10. Record deployed SHA, test evidence, owners, measured RPO/RTO, known limitations and a human go/no-go decision.

## Open-source reference basis

- Wazuh Indexer API: https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html
- Wazuh Server API: https://documentation.wazuh.com/current/user-manual/api/reference.html
- Wazuh Active Response configuration and allowlist: https://github.com/wazuh/wazuh/blob/main/docs/ref/modules/active-response/configuration.md
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

These references inform implementation and acceptance criteria; they do not substitute for lab or production evidence.
