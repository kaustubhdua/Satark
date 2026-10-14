# Run SATARK locally without third-party AI API keys

This is the supported local-first path for the Next.js web app and optional local language model. The analysis route defaults to deterministic local rules and does not call Groq, URLhaus, AbuseIPDB, or another third-party analysis service. If Ollama is configured, the submitted text is sent to that Ollama instance, which must be under your control.

## Requirements

- Docker Engine and Docker Compose plugin
- 8 GB RAM minimum for deterministic-only use; 16 GB RAM recommended for a small local model
- Disk space for the model you choose (model sizes vary)

## Start

From the repository root:

```bash
docker compose -f docker-compose.local.yml up --build -d
docker compose -f docker-compose.local.yml exec ollama ollama pull qwen2.5:3b
```

Open http://127.0.0.1:3000. The app and Ollama are bound to a private Docker network; only the web UI is published, and it is bound to host loopback. The first model pull requires internet access to download model files, but it does not require an API key. After the model is downloaded, inference runs locally. You may choose another model only after reviewing its license, hardware needs, and model-card limitations.

Check service state:

```bash
docker compose -f docker-compose.local.yml ps
docker compose -f docker-compose.local.yml logs --tail=100 web ollama
```

Stop without deleting downloaded model weights:

```bash
docker compose -f docker-compose.local.yml down
```

To delete the downloaded model volume as well, use `docker compose -f docker-compose.local.yml down -v`. This is destructive.

## What works in local-only mode

- URL parsing and redacted evidence excerpts
- Conservative deterministic signals for URL schemes, link shorteners, internationalized domain labels, urgency, credential-related language, payment pressure, and public IP literals
- Optional locally hosted Ollama summaries with bounded input, timeout, structured output validation, and deterministic fallback
- No third-party AI or threat-intelligence API calls from the default analysis route
- An explicit disclaimer that a heuristic score is not a probability and a no-signal result is not proof of safety

## Important boundaries

- The local heuristic engine is a prototype, not an antivirus, malware sandbox, reputation database, or proof of safety.
- The optional local model can hallucinate. Treat its narrative as untrusted and verify every statement against evidence.
- The model download needs an internet connection initially; no API key is required. You can pre-load a model in an offline environment and then disconnect.
- This Compose stack runs the web and model services only. Persistent case/evidence APIs still require the database environment documented in the project. Do not assume that cases, evidence, or reports are durable until their persistence path is configured and end-to-end tested.
- Do not expose port 3000 or Ollama to the public internet. Production deployment requires authentication, tenant authorization, shared abuse controls, TLS, backup/restore, privacy review, and operational monitoring.
- Existing legacy external-provider code remains available only through explicit `SATARK_ANALYSIS_MODE=groq`; it is not the default and is not needed for local analysis. Do not set that mode if you require a no-provider-key environment.

## Local analysis test

```bash
cd web
npm ci
npm run typecheck
npm test
npm run build
```
