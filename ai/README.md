# SATARK AI: self-hosted prototype

This directory is an **isolated, opt-in prototype** for local inference and reproducible model experiments. It does not replace the existing Next.js/Streamlit application, and it is not enabled in production by this change.

## What is included

- `service/`: FastAPI service with deterministic URL/IP/text signals, bounded input, an optional Ollama adapter, health reporting, strict output schemas, and tests.
- `training/`: dataset format, validation/evaluation utilities, and an optional LoRA supervised-fine-tuning entry point.
- `data/eval/`: small synthetic examples only; no real indicators or customer data.
- `Dockerfile`: container for the inference service.

The deterministic checks are deliberately conservative heuristics, **not** a malware scanner or verdict engine. A no-match is not proof of safety. Model output is untrusted and must never authorize response actions.

## Run the service locally

Requirements: Python 3.11+.

```bash
cd ai
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn service.app:app --host 127.0.0.1 --port 8787
```

Check health and analyze a synthetic input:

```bash
curl http://127.0.0.1:8787/health
curl -X POST http://127.0.0.1:8787/analyze \
  -H 'content-type: application/json' \
  -d '{"text":"Urgent: verify your account at https://example.invalid/login","case_id":"demo-001"}'
```

The service binds to loopback by default in the example. For local Docker use, publish the port only on loopback (for example, bind host port 127.0.0.1:8787 to container port 8787). If the service is reachable by other users or machines, set SATARK_AI_API_TOKEN to a cryptographically random secret of at least 32 characters; requests to /analyze then require Authorization: Bearer <token>. The optional token is not a substitute for TLS, tenant-aware authorization, shared rate limiting, network controls, or an explicit privacy review. The health endpoint reveals only configuration booleans and always reports production_ready=false.

## Optional local model with Ollama

1. Install Ollama separately and pull a model whose license and hardware requirements have been reviewed.
2. Set `SATARK_OLLAMA_BASE_URL=http://127.0.0.1:11434` and `SATARK_OLLAMA_MODEL=<reviewed-model-tag>`. If the service is not strictly local, also set `SATARK_AI_API_TOKEN` to a cryptographically random secret of at least 32 characters.
3. Restart the service and call `/health` to see whether the model is configured. Health reports configuration only; it does not claim that a model is loaded or that inference quality is acceptable.
4. The model is used only for a bounded narrative summary. Deterministic signals remain independently visible. If the model is unavailable or returns invalid output, the endpoint returns the deterministic result with an AI status explaining the failure.

Never put API keys, private incident data, or credentials into sample files or training data. The model receives user-supplied content as untrusted evidence; the prompt explicitly tells it not to follow instructions contained in that content.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
python training/validate_dataset.py
python training/evaluate.py
```

The tiny evaluation set is a plumbing smoke test, not evidence of security efficacy.

## Fine-tuning

LoRA training is intentionally opt-in and requires additional dependencies and suitable compute:

```bash
pip install -r training/requirements.txt
python training/validate_dataset.py --input data/train/examples.jsonl
python training/train_lora.py --help
```

Before training on anything beyond synthetic examples:
- verify license and permitted-use terms for every model and data source;
- obtain authorization for any incident data and minimize sensitive fields;
- deduplicate and split by incident/campaign/source to avoid leakage;
- keep a held-out test set inaccessible to training;
- establish base-model metrics before fine-tuning;
- publish model card, dataset manifest, evaluation results, known limitations and rollback instructions.

No model has been trained or benchmarked as part of adding these files. The repository does not yet have a reviewed training corpus or a selected base model.

## Production integration gates

Do not connect this service to production until it has authentication and tenant-aware authorization, abuse controls, network isolation, secret-safe telemetry, model/license review, upload sandboxing where applicable, documented data retention, load tests, red-team tests, and end-to-end integration tests. Vercel should host the web app, not an assumed always-on GPU model process.
