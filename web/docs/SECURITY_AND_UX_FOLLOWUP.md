# SATARK Next.js security and UX follow-up

## Scope
The Next.js analysis route is local-only. It performs bounded deterministic checks and optionally sends evidence to a self-hosted Ollama service configured by the operator. It does not call third-party AI or reputation APIs. The Ollama endpoint is restricted to local or Docker-network hosts by the current adapter.

## Data handling
- No third-party AI or threat-intelligence API key is required for the Next.js analysis route.
- Submitted text is not persisted by the analysis API. The browser stores only the analysis result snapshot in session storage; it does not store the original submitted text.
- When Ollama is configured, submitted text is sent to that self-hosted inference process. Operators must secure the host and model logs.
- URL evidence excerpts remove URL user-info, query parameters, and fragments.
- A heuristic no-signal result is insufficient evidence, not a safety verdict.

## Limitations and release gates
- Local pattern rules are a triage aid, not an antivirus, sandbox, or comprehensive reputation service.
- The rate limiter is per process and is not shared across serverless instances. Public deployment requires platform-level abuse controls or a self-hosted shared limiter.
- The current local-only Compose stack does not configure durable case/evidence storage. Do not claim the full case lifecycle is persistent until database migrations, tenant isolation, evidence uploads, and report export pass end-to-end tests.
- The legacy Python/Streamlit app has separate code paths and must be migrated and independently audited before the entire repository can be described as no-key/local-only.
- Automated tests, Web CI, Python CI, CodeQL, deployment verification, and the full release checklist must pass before production claims.
