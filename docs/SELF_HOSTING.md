# Self-hosting SATARK: making the four readiness rows real

The **Integration readiness** panel on `/tools` reports server configuration. It cannot turn green by editing the
website; each row reflects settings on the server that serves the page. This guide maps every row to what it needs.
Everything below is open source and runs on one Linux host with Docker.

| Panel row | What it needs | How the stack provides it |
|---|---|---|
| Self-hosted persistent storage | `SATARK_API_INTERNAL_URL` pointing at the private FastAPI service, backed by PostgreSQL | `docker-compose.production.yml` (`db`, `firstlight-api`, `web`) |
| Shared rate limiting | `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` (any Upstash-compatible REST endpoint) | `redis` + `redis-rest` ([serverless-redis-http](https://github.com/hiett/serverless-redis-http), MIT). The web app accepts `https://` anywhere and plain `http://` only for loopback or a single-label Docker service name. |
| FIRSTLIGHT investigation API | `FIRSTLIGHT_API_URL` and a 32+ byte `FIRSTLIGHT_API_TOKEN` on the web service | Wired in the production compose file (previously missing from the `web` service) |
| Wazuh telemetry connector | A reachable Wazuh indexer and the `FIRSTLIGHT_WAZUH_*` settings | **Operator-supplied.** Use your own Wazuh, or the lab in `scripts/bootstrap_wazuh_lab.sh`. |

## Steps
1. `python3 scripts/bootstrap_selfhost.py --domain <your-domain> --email <you@example.org>` writes a private `.env`
   (mode 600, gitignored) with generated database passwords, API/sync/Redis tokens and the MFA key. It never
   overwrites an existing file and lists what only you can fill in (SMTP account, Wazuh details, backup repository).
2. Point DNS for the domain at the host, then `docker compose -f docker-compose.production.yml up -d`.
3. Open `/tools`. Rows 1-3 should read *configured*.

## What "configured" does and does not mean
The panel is configuration-only by design: it reports that settings are present and well-formed, **not** that the
database answers, that Redis counts correctly, or that Wazuh is reachable. Verify those separately:
`GET /api/health/storage` on the API, a burst of requests to confirm HTTP 429 from the analysis endpoint, and
`scripts/accept_firstlight_wazuh_live.py` against your Wazuh lab. Wazuh and Android device acceptance have not been run
by the maintainers in a live environment; do not describe them as verified until you have.

## Hosted alternatives (e.g. Vercel)
The web app can also run on a hosted platform. Then you must supply the same settings as environment variables
yourself: a publicly reachable HTTPS API URL for the FastAPI backend, `FIRSTLIGHT_API_URL`/`FIRSTLIGHT_API_TOKEN`,
and either an Upstash database or your own Redis REST proxy. A hosted web tier with no backend will keep showing
rows 1, 3 and 4 as not configured, which is accurate.
