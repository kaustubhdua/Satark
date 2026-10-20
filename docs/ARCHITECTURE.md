# SATARK / FIRSTLIGHT architecture and threat model

## System components

SATARK has two user interfaces and a shared investigation platform:

- **Next.js web workspace** — the primary multi-user interface for authenticated case work, evidence, findings, reports, approvals, and durable investigation jobs.
- **Streamlit workspace** — the legacy/local analysis interface. Its interactive session history is temporary and is not the durable case-management store.
- **Supabase Auth and Postgres** — user identity, tenant membership, case/evidence metadata, findings, reports, append-only audit records, approvals, investigation jobs, and Wazuh checkpoints. Row-level security (RLS) and tenant-scoped policies enforce access; the shared project also hosts other applications, so database operations must be limited to SATARK objects.
- **Private FIRSTLIGHT FastAPI service** — the canonical deterministic investigation engine and read-only Wazuh alert preview endpoint. It fails closed when the required bearer tokens are not configured.
- **Private persistent workers** — the Wazuh worker reads indexed alerts, revalidates its configured actor's membership, writes normalized evidence and provenance to an authorized case, and advances a durable checkpoint only after a fully drained query window. The investigation worker leases durable jobs and persists deterministic results. Neither worker performs live response actions.
- **Optional local Ollama** — self-hosted open-weight model inference. The default analysis path uses deterministic local rules and does not require third-party AI API keys. Model output is untrusted narrative and cannot independently authorize a finding or response.

## Trust boundaries

1. **Browser → Next.js:** browser state and request data are untrusted. Server routes validate the Supabase access token, bound request/response sizes, and do not expose private worker credentials.
2. **Next.js → Supabase:** authenticated user requests carry the user's token and rely on database grants and RLS. Service-role credentials must never be sent to the browser or configured as a public client variable.
3. **Next.js → FIRSTLIGHT API:** the server-side proxy injects a strong bearer token. The private API URL and token belong in server-side environment configuration, never in `NEXT_PUBLIC_*` variables.
4. **Persistent worker → Wazuh Indexer:** only a server-side, least-privilege read-only account may query the approved alert indices. The endpoint must be HTTPS with certificate validation unless an isolated lab explicitly opts into HTTP.
5. **Persistent worker → Supabase:** the service-role key is limited to a private worker host. The worker revalidates the configured tenant/case/actor membership around privileged operations and writes only tenant/case-bound object paths.
6. **SATARK → submitted URL or file:** external URL fetching and file parsing are hostile-input boundaries. Enforce network egress controls in addition to application-level validation.
7. **Application → Ollama:** submitted content is sent to the configured model server only when the optional local model feature is invoked. Keep Ollama on a private network and do not expose its unauthenticated endpoint to the public internet.

## Data flow

### Local threat triage

User input → bounded parsing/normalization → deterministic URL/text signals → optional self-hosted Ollama summary → constrained result normalization → findings and report.

The default Next.js analysis path does not call hosted AI or threat-intelligence APIs. A deterministic no-signal result is not proof that an artifact is safe, and a heuristic score is not a probability.

### FIRSTLIGHT investigation

Authenticated case/evidence request → canonical evidence digest verification → deterministic detection/correlation rules → evidence-linked findings → timeline reconstruction and explicit gaps → report/audit persistence.

Raw Wazuh source snapshots are stored in the private `satark-evidence` bucket under tenant/case-bound paths. The Storage policies permit viewer access to ordinary evidence but restrict raw `wazuh/<sha256>.json` snapshots to owner/responder/analyst membership. Hashes support integrity comparison; they do not prove that the source was truthful or independently collected.

### Wazuh ingestion and durable jobs

Wazuh Indexer → private read-only connector → normalized event IDs and source provenance → persistent worker → tenant/case-authorized evidence + durable checkpoint. Repeated polls are duplicate-safe; a failed poll must not advance the checkpoint. A separate private worker leases investigation jobs, persists the result, and then marks the job complete. Production operation still requires a reachable authorized Wazuh lab, least-privilege credentials, a provisioned SATARK tenant/case/member/actor, and real end-to-end verification.

## URL threat model

The URL scanner can cause outbound requests, so it is treated as an SSRF boundary. The application:

- permits only HTTP(S);
- rejects URL credentials and local hostnames;
- resolves hostnames and requires every answer to be globally routable;
- pins the connection to a validated IP while preserving the original hostname for TLS certificate validation and SNI;
- validates every redirect independently, limits redirect count, and blocks HTTPS-to-HTTP downgrade redirects; and
- bounds response bytes and rejects unsupported content types.

Application-level checks do not replace infrastructure egress controls. Block cloud metadata services and internal networks at the network layer, and retest in the actual hosting environment.

## AI and response-safety model

Models are untrusted analyzers, not authorities. Model narratives must remain distinct from observed evidence and deterministic rule output. Keep confidence calibrated to available evidence and expose uncertainty and gaps.

Response approvals currently support the simulated workflow; they are not proof of safe real-world execution. Do not enable live containment, account/session revocation, or network blocking until the target-bound authorization, durable approval consumption, audit trail, provider permissions, rollback/recovery, and real-provider tests have been independently validated. The current release keeps live response actions disabled.

## Persistence and privacy

- The Next.js workspace uses Supabase-backed durable workflows when its authentication, schema, RLS, and private API configuration are correctly provisioned.
- The legacy Streamlit workspace keeps its history in session state; do not treat that state as durable case storage.
- The `satark-evidence` bucket is private. Source snapshots are bounded and digest-verified. A SHA-256 digest alone is not an independently anchored chain of custody.
- Avoid uploading secrets or regulated data until the deployment's access controls, retention policy, backup/restore, and provider agreements are reviewed.
- Keep service-role keys, Wazuh credentials, and private API tokens in a secret manager or private runtime environment. Never commit secrets or expose them through client-side environment variables.

## Production release gates

Do not declare production-ready until all of the following are evidenced for the exact candidate revision:

1. All CI, CodeQL, web build, browser/accessibility, and isolated migration checks pass on the exact current `main` SHA.
2. The shared Supabase migration history is reconciled using the documented operator procedure. Preview the linked push and verify that exactly the two approved SATARK migrations are pending before applying them; never run a broad push if the dry-run differs.
3. Verify the six case-note, approval, and investigation-job policies use the private membership helper; verify the five SATARK foreign-key indexes and expected helper grants.
4. Deploy the exact current `main` SHA through the authorized Vercel Git integration, verify the production alias points to that SHA, and pass production smoke. If SSO blocks the smoke workflow, use an approved public custom domain or a narrowly scoped deployment-protection bypass; do not disable SSO globally or bypass deployment quotas.
5. Provision server-side `FIRSTLIGHT_API_URL`, strong `FIRSTLIGHT_API_TOKEN`, `FIRSTLIGHT_WAZUH_SYNC_TOKEN`, a private worker host, Wazuh Indexer URL/credentials, an agent allowlist, and a dedicated authorized SATARK tenant/case/actor. Keep the Supabase service-role key only on the private worker host.
6. Run a real Wazuh-to-evidence-to-checkpoint-to-investigation-to-report end-to-end test with authorized synthetic/lab telemetry, including retry, duplicate, revoked-membership, and recovery cases.
7. Verify backups and restore, retention/deletion controls, operational alerting, resource limits, outbound egress restrictions, and incident-response runbooks.
8. Keep live response actions disabled until a separate reviewed release explicitly validates the complete approval and provider execution path.

The current release status and exact external blockers are recorded in [FIRSTLIGHT implementation status](FIRSTLIGHT_IMPLEMENTATION_STATUS.md) and [deployment sign-off](DEPLOYMENT_SIGNOFF.md). Passing CI is necessary but does not prove live-provider or production readiness.
