# Hosted deployment: Vercel web app + managed backend

Use this when the web app runs on Vercel (for example `https://satark-rose.vercel.app`) and the FastAPI backend
runs on a managed container host. The self-hosted alternative that needs no hosted account is `docs/SELF_HOSTING.md`.

Vercel only serves the Next.js app. The four rows on `/tools` turn green when **both** halves below are in place.
Nothing here has been run against a live host by the maintainers; follow the verification steps at the end.

## Or run with no backend at all: browser-only mode
If `SATARK_API_INTERNAL_URL` is not set, `/api/health` reports `persistentStorage.configured: false` and the site
switches to **browser-only mode**: cases, notes, findings, evidence files, sealed report snapshots and the
hash-chained audit trail are kept in the visitor's own browser (IndexedDB) and are never uploaded. Evidence is
SHA-256 hashed and re-verified, reports are sealed over canonical JSON, and the audit chain is verified end to end.
Backup and restore are **Export / Import** on the Cases page.

**Run full investigation** works in this mode too: the same ten deterministic FIRSTLIGHT rules run in the browser
(`web/src/lib/firstlight-engine.mjs`, a port of `firstlight_engine.py`) over the saved evidence, after re-checking every
stored digest, and save findings, a sealed report and audit events. `scripts/generate_firstlight_parity_fixture.py` writes a
golden file from the Python engine that both `tests/test_firstlight_js_parity.py` and `web/tests/firstlight-parity.test.mjs`
check, so the two engines cannot drift apart silently.

Limits, stated plainly: data is only as durable as the browser profile (clearing site data erases it), there is no
sharing between people or devices, no sign-in, invitations or MFA, no optional local-model agents and no
live endpoint response (containment needs a Wazuh Manager). Whole-number floats (`1.0`) hash as `1` in the browser port and
integers above 2^53 lose precision; rules read strings and small integers, so findings are not affected. A person with devtools can edit their own local data, so the hashes detect accidental or casual
changes, not a determined local attacker. Set the backend variables below to get the shared, multi-user service.
`web/tests/local-journey.mjs` exercises this mode in a real browser and runs in the web CI workflow.

## Constraints that shape a hosted setup (from the code)
- **No shared disk.** The API and the investigation worker normally share `/data/evidence`. Managed hosts do not
  share a disk across services, so use the S3 backend (`SATARK_EVIDENCE_BACKEND=s3`). The images now include `boto3`.
  Any S3-compatible store works (AWS S3, Cloudflare R2, Backblaze B2, MinIO).
- **Database URL scheme.** Managed Postgres hands out `postgres://` or `postgresql://` URLs. The backend now maps both
  to the psycopg driver (`satark_backend.database_url`), so the provider's connection string can be pasted as is.
- **Migrations run on start.** The API image runs `alembic upgrade head` before serving; keep `SATARK_AUTO_CREATE_SCHEMA=false`.
- **Vercel request-body limit.** Serverless functions accept about 4.5 MB per request. The API allows 4 MiB evidence
  files, so a file near the limit plus multipart overhead can be rejected by Vercel before it reaches the API.
- **Upstream URL rules.** The web proxy only talks to an `https://` API (plain `http://` is accepted only for
  localhost and the Docker service name). Set `SATARK_PUBLIC_ORIGIN` to the exact public site origin, or unsafe
  requests are rejected as cross-origin.

## 1. Backend (any container host: Render, Railway, Fly.io, Coolify, Dokploy, ...)
Run two services from this repo plus a database and an object store.

| Service | Build | Start |
|---|---|---|
| API | `Dockerfile.firstlight-api` | image default (runs migrations, then uvicorn on 8788) |
| Investigation worker | `Dockerfile.firstlight-investigation-worker` | image default |
| PostgreSQL | managed or self-run | n/a |
| Object store | any S3-compatible bucket | n/a |

API **and** worker environment:

| Variable | Value |
|---|---|
| `SATARK_DATABASE_URL` | the provider's connection string |
| `SATARK_EVIDENCE_BACKEND` | `s3` |
| `SATARK_S3_BUCKET` | your bucket (`SATARK_S3_ENDPOINT_URL` / `SATARK_S3_REGION` for non-AWS stores) |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | credentials for that bucket (standard boto3 chain) |

API only:

| Variable | Value |
|---|---|
| `FIRSTLIGHT_API_TOKEN` | 32+ random bytes (`openssl rand -hex 32`); must equal the Vercel value |
| `FIRSTLIGHT_WAZUH_SYNC_TOKEN` | a different 32+ byte secret |
| `SATARK_MFA_ENCRYPTION_KEY` | a stable Fernet key (`python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) |
| `SATARK_PUBLIC_BASE_URL` | your Vercel site URL, used in e-mailed links |
| `SATARK_AUTO_CREATE_SCHEMA` | `false` |
| `SATARK_REQUIRE_EMAIL_VERIFICATION`, `SATARK_REQUIRE_MFA` | `true` for production; verification needs the `SATARK_SMTP_*` settings below |
| `SATARK_SMTP_HOST`, `SATARK_SMTP_PORT`, `SATARK_SMTP_USERNAME`, `SATARK_SMTP_PASSWORD`, `SATARK_SMTP_FROM` | a real SMTP account |
| `FIRSTLIGHT_WAZUH_*` | only if you run Wazuh (see `.env.example`); otherwise leave unset |

Leave `SATARK_ENABLE_LIVE_RESPONSE` unset: live containment actions stay disabled.

## 2. Vercel project environment variables
| Variable | Value |
|---|---|
| `SATARK_API_INTERNAL_URL` | `https://<your-api-host>` (no path, no credentials) |
| `FIRSTLIGHT_API_URL` | the same URL |
| `FIRSTLIGHT_API_TOKEN` | the same token as the API |
| `SATARK_PUBLIC_ORIGIN` | `https://satark-rose.vercel.app` (your exact origin) |
| `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | an Upstash database, or your own `serverless-redis-http` endpoint over `https://` |

Redeploy after saving variables; Vercel applies them only to new deployments.

## 3. Verify (do not skip)
1. `GET https://<api-host>/api/health/storage` returns 200.
2. `https://<site>/api/health` shows storage, the FIRSTLIGHT proxy and the shared limiter as configured (configuration only).
3. Run `SATARK_WEB_URL=https://<site> node web/tests/live-journey.mjs` against the site, with the worker running. It signs up,
   imports evidence, uploads and verifies a file, runs a durable investigation and checks the audit chain. If e-mail
   verification or MFA is required, the throwaway sign-up will stop at that step by design; use a staging backend with both off.
4. Send a burst of requests to `/api/analyze` and confirm HTTP 429.

## Example Render blueprint (untested template)
Based on the [Render Blueprint spec](https://docs.render.com/blueprint-spec). Plans and names are placeholders; check
current pricing and that background workers are available on the plan you choose.

```yaml
databases:
  - name: satark-db
    plan: basic-256mb
services:
  - type: web
    name: satark-api
    runtime: docker
    dockerfilePath: ./Dockerfile.firstlight-api
    healthCheckPath: /api/health/storage
    envVars:
      - { key: SATARK_DATABASE_URL, fromDatabase: { name: satark-db, property: connectionString } }
      - { key: SATARK_EVIDENCE_BACKEND, value: s3 }
      - { key: SATARK_AUTO_CREATE_SCHEMA, value: "false" }
      - { key: FIRSTLIGHT_API_TOKEN, sync: false }
      - { key: FIRSTLIGHT_WAZUH_SYNC_TOKEN, sync: false }
      - { key: SATARK_MFA_ENCRYPTION_KEY, sync: false }
      - { key: SATARK_PUBLIC_BASE_URL, sync: false }
      - { key: SATARK_S3_BUCKET, sync: false }
      - { key: AWS_ACCESS_KEY_ID, sync: false }
      - { key: AWS_SECRET_ACCESS_KEY, sync: false }
  - type: worker
    name: satark-investigation-worker
    runtime: docker
    dockerfilePath: ./Dockerfile.firstlight-investigation-worker
    envVars:
      - { key: SATARK_DATABASE_URL, fromDatabase: { name: satark-db, property: connectionString } }
      - { key: SATARK_EVIDENCE_BACKEND, value: s3 }
      - { key: SATARK_S3_BUCKET, sync: false }
      - { key: AWS_ACCESS_KEY_ID, sync: false }
      - { key: AWS_SECRET_ACCESS_KEY, sync: false }
```
