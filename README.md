<div align="center">

# SATARK Sentinel
### Offline-first mobile file security and evidence-led threat inspection

**Inspect the file. Match the signature. Keep the content private.**

SATARK is an **Android-first, Python-based, offline-first file security application**. The mobile app inspects file fingerprints, SHA-256 hashes, format signatures and filename/signature mismatches against a locally imported historical dataset. Kotlin is used only for Android integration (Share, Storage Access Framework, notifications and WorkManager); Python performs the scan and local database work. The Android app has no Internet permission, Supabase runtime, hosted API, cloud AI or telemetry upload. FIRSTLIGHT, the browser workspace and earlier content-triage workflows remain legacy/supporting components.

[![Production smoke](https://github.com/kaustubhdua/Satark/actions/workflows/production-smoke.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/production-smoke.yml)
[![CI](https://github.com/kaustubhdua/Satark/actions/workflows/ci.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/ci.yml)
[![CodeQL](https://github.com/kaustubhdua/Satark/actions/workflows/codeql.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/codeql.yml)
[![FIRSTLIGHT API CI](https://github.com/kaustubhdua/Satark/actions/workflows/firstlight-api-ci.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/firstlight-api-ci.yml)
[![Web CI](https://github.com/kaustubhdua/Satark/actions/workflows/web-ci.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/web-ci.yml)
[![Android File Guard](https://github.com/kaustubhdua/Satark/actions/workflows/android-file-guard.yml/badge.svg)](https://github.com/kaustubhdua/Satark/actions/workflows/android-file-guard.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)

<img src="assets/satark-banner.svg" alt="SATARK Sentinel" width="1000">

</div>

---

> **Prototype and safety boundary:** SATARK is a learning and triage aid, not an antivirus, certified forensic product, or proof that content is safe or malicious. The configured Vercel production alias is `https://satark-rose.vercel.app`; its current deployed revision and runtime health must be verified by the production smoke workflow before calling the deployment release-ready. The repository Actions variable `SATARK_PRODUCTION_URL` can override the target if the domain changes. FIRSTLIGHT's demo incident is synthetic. Optional Microsoft Defender/Entra response adapters are opt-in, require tenant credentials and explicit target-bound confirmation, and have not been live-validated or connected to the current simulated approval UI. The session-based audit chain is not independently anchored chain-of-custody evidence. Use synthetic or public, non-sensitive data in the current demo.

## First-party native endpoint sensor

SATARK includes an independently authored, standard-library Linux sensor for bounded local authentication-log collection and explicit-path file-integrity snapshots. It emits normalized observations with source digests and a local hash-chained journal. It performs no network requests or automatic response actions and is not a full EDR or a claim of complete endpoint coverage. See the [operator guide](docs/NATIVE_ENDPOINT_SENSOR.md) and the web experience at `/native-sensor` when running the Next.js app. Wazuh remains an optional external telemetry adapter, not a SATARK runtime dependency.

## New product direction: SATARK File Guard

File Guard is the current product direction: a privacy-first local file scanner for files received through WhatsApp, Telegram, downloads and other apps.

- Python static inspection engine with SHA-256, file-format signatures, extension mismatch checks and local historical hash matching. Native YARA is not bundled in the Android app.
- Local SQLite intelligence store populated only through explicit import of a traceable historical CSV snapshot.
- No hosted analysis APIs, API keys, cloud reputation lookups, telemetry uploads or automatic dataset updates.
- Historical intelligence can be prepared from EMBER2024 (2023–2024, six file types) using the explicit one-time `scripts/download_ember2024.py` downloader and local `scripts/import_ember2024.py` converter; the app ships with no fabricated or preloaded indicators.
- No semantic file-content extraction, OCR, preview, execution, archive unpacking or automatic deletion.
- Android access is permission-based: Share-to-SATARK, Android system file picker and explicitly granted folder access. Private messaging databases are out of scope.
- A frozen dataset supports real-time local inspection of newly shared files, not real-time discovery of newly emerging malware.

The Android application includes Kotlin Sharesheet receivers, system file picker and user-granted folder access, a Chaquopy Python engine, local scan history, offline CSV hash import and best-effort WorkManager scans. Android CI builds the debug APK and checks the no-network contract; physical-device QA, performance/battery testing, signing and store acceptance remain outstanding. See [Android File Guard architecture](docs/ANDROID_FILE_GUARD_ARCHITECTURE.md). The Streamlit page is a legacy development interface; uploaded bytes reach the Streamlit host, so do not use it for private files.

## Contents

- [1. Executive summary](#1-executive-summary)
- [2. The problem](#2-the-problem)
- [3. Our approach](#3-our-approach)
- [4. Legacy experience: FIRSTLIGHT Incident Command](#4-legacy-experience-firstlight-incident-command)
- [5. Supporting SATARK threat-analysis tools](#5-supporting-satark-threat-analysis-tools)
- [6. Example demonstration flow](#6-example-demonstration-flow)
- [7. What makes the approach different](#7-what-makes-the-approach-different)
- [8. System design and architecture](#8-system-design-and-architecture)
- [9. Technology stack](#9-technology-stack)
- [10. Run the project locally](#10-run-the-project-locally)
- [11. Local AI and data handling](#11-local-ai-and-data-handling)
- [12. Tests and engineering safeguards](#12-tests-and-engineering-safeguards)
- [13. Security, privacy, and current limitations](#13-security-privacy-and-current-limitations)
- [14. Roadmap](#14-roadmap)
- [15. Project structure](#15-project-structure)
- [16. Hackathon-ready project summary](#16-hackathon-ready-project-summary)
- [17. Contributing](#17-contributing)
- [18. Documentation](#18-documentation)

## 1. Executive summary

**SATARK Sentinel** is an Android-first, offline-first file security application. Its primary workflow receives a file shared from WhatsApp, Telegram, a browser or a file manager, then inspects the file locally with a Python engine. Users can also choose files or grant access to a folder tree through Android's system picker.

The mobile app uses SHA-256, bounded file-format signatures, extension consistency checks and exact local hash matching against an explicitly imported historical dataset. Kotlin handles Android OS integration; Python handles detection and SQLite persistence. No file is uploaded, no external API is called, and no chat/message database or document text is read. The Android manifest intentionally has no Internet permission.

FIRSTLIGHT, Next.js, Streamlit and the self-hosted web backend remain in the repository as legacy/supporting projects; they are not required for the Android scanner. The clean-state result is deliberately limited: **no known threat detected by enabled local checks** is not a guarantee that a file is safe.

## 2. The problem

People and small teams often encounter a mix of suspicious messages, links, QR codes, attachments, login alerts, and disconnected event records. The difficulty is not just detecting one suspicious item; it is understanding how separate signals relate, what is actually supported by evidence, and which response step is justified.

Common problems include:

- **Fragmented evidence:** clues arrive in different formats and at different times.
- **Over-trusting a score:** a risk number can look definitive even when evidence is incomplete.
- **Unclear reasoning:** users may not know which observable signal supports a finding.
- **Missing context:** a workflow may report a suspicious event without clearly showing what is still unknown.
- **Premature action:** a response can be initiated before a person has reviewed the available information.
- **Difficult learning:** security-awareness tools often teach isolated red flags rather than a structured investigation process.

SATARK Sentinel is designed as a prototype response to these workflow problems. It organizes evidence and review steps; it does not claim to replace security professionals, endpoint detection, or a production incident-response platform.

## 3. Our approach

The Android File Guard is the primary SATARK product. The older FIRSTLIGHT/web/Streamlit paths below are retained as legacy experiments and are not part of the Android app's offline scanning path. The Android product does not use hosted AI or any analysis API.

The legacy project follows an **evidence-first, human-reviewed workflow**:

1. **Collect** a synthetic incident scenario or a supported suspicious digital artifact.
2. **Validate and prepare** the input using format-specific limits and checks.
3. **Extract observable signals** with deterministic rules where applicable.
4. **Use AI as an assistant** for supported content-analysis workflows, not as the sole source of truth.
5. **Correlate and review** findings, timestamps, evidence references, and gaps.
6. **Decide with a human in the loop** using explicit approval/rejection controls in the FIRSTLIGHT simulation.
7. **Export or revisit** the resulting report or current-session history where supported.

The product keeps two modes clear: FIRSTLIGHT demonstrates an explainable, deterministic investigation workflow over synthetic data; the scanners help triage suspicious content with local deterministic checks and optional self-hosted Ollama inference. These are related parts of one security workflow, but they have different trust and data-handling boundaries.

## 4. Legacy experience: FIRSTLIGHT Incident Command

FIRSTLIGHT is a retained legacy investigation workspace and is not the primary SATARK mobile product. It loads a fictional account-compromise scenario so the investigation can be explored without requiring a live attack, real account access, or sensitive incident evidence.

### Capabilities

- **Repeatable synthetic scenario:** explore a consistent incident story and its supporting artifacts.
- **SHA-256 integrity verification:** calculate and check hashes for supported evidence artifacts.
- **Tampering challenge:** demonstrate how changing an artifact can affect an integrity check.
- **Deterministic investigation workflow:** apply explicit rules to the available event/evidence data rather than relying on a language model to invent an incident narrative.
- **Evidence-linked findings:** connect findings to the available evidence references so a reviewer can inspect the basis for a conclusion.
- **Chronological timeline:** put normalized incident events into time order to make sequences easier to understand.
- **Evidence-gap reporting:** call out unanswered questions and missing corroboration rather than implying the investigation is complete.
- **Human review controls:** approve or reject proposed response steps within the simulation.
- **Hash-chained in-session audit trail:** demonstrate how ordered review events can be linked together and checked for tampering during the current session.
- **JSON export:** export supported investigation output for inspection or downstream prototyping.

### What FIRSTLIGHT does not do

FIRSTLIGHT does **not** disable a real account, terminate a process, isolate an endpoint, contact an identity provider, or perform a real network response. The response controls are a prototype simulation. The current audit chain is held in session and is not a durable, independently anchored log or a certified forensic chain of custody. Evidence integrity checks establish whether bytes match a computed hash; they do not establish where evidence came from or whether it is truthful.

See [FIRSTLIGHT scope and safety boundaries](docs/FIRSTLIGHT.md).

## 5. Legacy threat-analysis tools (not part of Android File Guard)

The following older web/Streamlit scanners remain in the repository for reference and are not part of the offline Android File Guard product. They may process content and may use optional local AI or hosted web infrastructure. Do not use them as substitutes for the privacy contract described for the mobile app.

| Workflow | What it supports | Important boundary |
| --- | --- | --- |
| Text analysis | Reviews pasted messages and text for suspicious patterns and requests an AI-assisted assessment when configured. | Model interpretation can be wrong or incomplete. |
| URL analysis | Validates a URL, safely fetches eligible public-page text, and assesses available content. | URL-fetch protections are defense in depth, not a substitute for host-level egress controls. |
| Image analysis | Sends supported image content for AI-assisted inspection. | Image analysis does not execute files or prove that an image is benign. |
| QR analysis | Extracts/inspects QR content through the supported image workflow. | A decoded destination still needs independent verification. |
| PDF analysis | Extracts supported PDF text and analyses it. | This is not a malware sandbox or exhaustive file scan. |
| Video analysis | Samples representative frames; audio transcription may be available when FFmpeg and provider support are present. | Frame sampling and optional transcription can miss important content. |
| Deterministic signal ledger | Shows local pattern-based observations such as urgency, credential requests, payment language, URL/shortener patterns, and phone/UPI-like identifiers where applicable. | A pattern match is a review signal, not proof of fraud. |
| Evidence coverage review | Highlights when a broad AI assessment lacks independent local text-rule observations and treats visual workflows separately. | It is a coverage check, not claim-by-claim verification of the model's response. |
| PDF report | Produces a downloadable report for a supported analysis. | A generated report is not a certified forensic report. |
| Session history | Allows results to be revisited within the current app session. | History is not durable case storage and may not survive a session restart. |
| Security learning | Includes Scam Challenge, SATARK Academy, and Classroom Mode. | Learning content is for awareness and practice, not professional certification. |

### Input limits and optional tools

Input handling applies format-specific bounds before processing. The configured Streamlit upload ceiling is 50 MB; PDF and image processing use stricter per-format limits. Video frame extraction uses OpenCV. Audio extraction/transcription from video additionally depends on FFmpeg and the optional faster-whisper package plus local model weights. Exact behavior depends on input format and available hardware.

## 6. Example demonstration flow

This is a suggested product walkthrough, not a claim that a real incident was detected.

1. **Open FIRSTLIGHT.** Introduce the fictional account-compromise scenario and its evidence artifacts.
2. **Verify integrity.** Show the SHA-256 check, then use the controlled tampering challenge to illustrate why integrity checks matter.
3. **Run the investigation.** Walk through deterministic findings and the evidence references associated with them.
4. **Inspect the timeline.** Explain how event ordering supports or weakens a possible sequence of events.
5. **Review the gaps.** Show which questions remain unanswered and why a reviewer should avoid overstating the conclusion.
6. **Review a simulated response.** Approve or reject a proposed action and show the resulting in-session audit events.
7. **Export the result.** Demonstrate the supported JSON export.
8. **Connect the supporting scanner.** Submit a harmless sample message or public, non-sensitive URL to SATARK's triage workflow; compare local signals with the AI interpretation and explain why neither should be treated as a verdict.

**Demo safety:** use only the built-in synthetic scenario and harmless/public, non-sensitive examples. Do not demonstrate using real credentials, OTPs, private keys, confidential incident evidence, or unauthorized targets.

## 7. What makes the approach different

The project's intended differentiators are workflow and transparency, not a claim of superior detection accuracy.

- **Evidence before narrative:** FIRSTLIGHT starts from available artifacts and deterministic rules, rather than asking an AI model to invent the incident sequence.
- **Visible uncertainty:** evidence gaps are part of the result, not hidden behind a single score.
- **Human approval in the loop:** response steps are explicitly reviewed in the simulation.
- **Integrity as a demonstrable concept:** SHA-256 verification and a tampering challenge make artifact-integrity concepts tangible.
- **Separate local signals from AI interpretation:** pattern observations and model output are presented as different kinds of evidence.
- **Multiple input types:** supporting scanners provide a single entry point for several common suspicious-content formats.
- **Safety-aware design:** bounded inputs, URL destination validation, redirect checks, normalized model results, and regression tests reduce specific classes of avoidable failures.
- **Accessible learning path:** the learning features provide an entry point for people building basic scam-awareness skills.

These are implementation goals and demonstrated prototype behaviors. The repository does not yet establish detection precision/recall, reduced incident-response time, production-scale performance, or superiority to commercial security tools; those claims would require measured evaluation.

## 8. System design and architecture

### High-level architecture

~~~text
                       SATARK Sentinel
                              |
               +--------------+--------------+
               |                             |
     FIRSTLIGHT Incident Command      Threat-analysis tools
               |                             |
       Synthetic incident data        Text / URL / image /
               |                       QR / PDF / video
       Input + hash checks                    |
               |                      Bounded preparation
       Deterministic rules                    |
               |                  +-----------+-----------+
       Evidence-linked findings   |                       |
               |              Local signals          Ollama model
       Timeline + evidence gaps       |                       |
               |                      +-----------+-----------+
       Human-reviewed simulated                  |
       response and audit events          Normalized assessment
               |                                  |
        JSON export / UI                   Review UI / PDF report
               |                                  |
               +----------------+-----------------+
                                |
                    Streamlit interface/session
~~~

### Self-hosted application backend (Supabase-independent)

The web application's authenticated API now runs through a SATARK-owned FastAPI service. The service owns password hashing (Argon2id), opaque revocable HttpOnly sessions, workspace membership, cases, notes, evidence metadata and private evidence bytes, findings, reports, approvals, hash-chained audit events, and the durable FIRSTLIGHT job queue. SQLAlchemy provides the relational persistence layer; PostgreSQL is the intended multi-instance database and SQLite is supported for local development and single-host evaluation. Alembic owns schema changes. The browser talks to the service through same-origin Next.js API routes and never receives a database credential. The optional Wazuh ingestion worker writes source snapshots, evidence metadata, audit events, and checkpoints to this same backend and private volume; it no longer uses a hosted database or storage service.

The local Compose stack persists the database and evidence files in the `satark_data` volume. A clean local setup is:

~~~bash
cp .env.example .env
docker compose -f docker-compose.local.yml up --build
~~~

The web UI is served at `http://localhost:3000`. To enable the optional Wazuh ingestion worker, configure the `FIRSTLIGHT_WAZUH_*` target, read-only Indexer, and initial checkpoint values in `.env`, then run `docker compose -f docker-compose.local.yml --profile wazuh up --build`. For multi-instance deployments, set `SATARK_DATABASE_URL` to a dedicated PostgreSQL database and use a shared private durable evidence volume accessible to the API and workers. Back up the database and evidence volume together. Do not expose the database, evidence directory, or worker port publicly.

The Android File Guard does not use this web backend. The repository's application runtime is Supabase-independent: the obsolete Supabase CLI configuration and SQL migration directory have been removed, and CI checks that Supabase SDK/Auth/REST/Storage references are not reintroduced into runtime source. The optional web backend uses SATARK-owned SQLAlchemy/Alembic persistence; SQLite is the local/single-host default and PostgreSQL is optional for self-hosted multi-instance operation. Existing data in any former Supabase project is not automatically imported or deleted; export it separately only if it is needed. The Android app remains fully usable without this web backend.

### Main trust boundaries

1. **Android OS to SATARK:** shared URIs and Storage Access Framework grants are scoped capabilities; the app reads only the bytes the user explicitly shares or selects.
2. **Input to preprocessing:** uploaded and pasted content is subject to format-specific bounds and validation.
3. **Server to user-supplied URL:** URL retrieval is an SSRF-sensitive operation. The implementation validates eligible HTTP(S) destinations, checks DNS results, pins connections to validated IPs, revalidates redirects, blocks HTTPS-to-HTTP downgrade redirects, and limits response size/type.
4. **Application to local model:** prepared evidence is sent only to the operator-controlled Ollama endpoint when local model inference is configured; no hosted AI provider is used.
5. **Optional web workspace to self-hosted backend:** same-origin HttpOnly sessions are checked by SATARK-owned FastAPI; each case/evidence/report/job query is scoped through workspace membership. This legacy web path is separate from the offline Android scanner.

### Processing flow for a scanner

1. User selects a workflow and supplies input.
2. The relevant input processor validates and bounds the content.
3. Supported local deterministic signals are extracted where applicable.
4. If a local Ollama model is configured, prepared evidence is sent to that local model; otherwise the deterministic fallback is used.
5. The result is parsed and normalized before it is shown.
6. The UI presents the result, relevant signals, limitations, and suggested next steps; supported reports can be exported.

### Processing flow for FIRSTLIGHT

1. Load the built-in fictional incident and its artifacts.
2. Verify supported evidence hashes and optionally demonstrate tampering.
3. Normalize and evaluate the scenario using deterministic investigation rules.
4. Generate findings with evidence references, timeline context, and explicit gaps.
5. Record human approval/rejection choices as simulated events in the current session.
6. Export supported investigation output as JSON.

More detail is available in [Architecture and threat model](docs/ARCHITECTURE.md).

## 9. Technology stack

| Technology | Role |
| --- | --- |
| Python | Core application, input processing, rules, orchestration, and tests |
| Streamlit | Web interface, navigation, and session state |
| Ollama | Optional self-hosted text/vision inference without API keys |
| faster-whisper | Optional local video-audio transcription; model weights are downloaded/cached locally |
| pypdf | PDF text extraction |
| Pillow | Image loading and conversion |
| OpenCV | Video frame extraction |
| FFmpeg | Optional audio-track extraction for supported video transcription |
| ReportLab | PDF report generation |
| CSS | Responsive styling, visual hierarchy, subtle motion, and reduced-motion support |
| unittest | Automated unit and regression tests |
| GitHub Actions | CI checks and browser smoke/layout validation |
| CodeQL | Static security analysis workflow |

The application is primarily Python/Streamlit. Its styling uses a dedicated CSS layer and native Streamlit UI components rather than requiring a separate React application. Animations are restrained and support reduced-motion preferences.

Model availability depends on the Ollama service, installed local model weights, available memory, and model compatibility. No third-party AI API key or account is required.

## 10. Run the project locally

### Requirements

- Python 3.10 or newer
- Git
- Dependencies in requirements.txt
- Ollama is **optional**. Without it, deterministic analysis and FIRSTLIGHT still work; Ollama adds local model suggestions where supported.
- Optional vision model (for example qwen2.5vl:3b) for image analysis when using Ollama-backed vision features
- FFmpeg and optional faster-whisper for local video-audio transcription

### Install

~~~bash
git clone https://github.com/kaustubhdua/Satark.git
cd Satark
python -m venv .venv
~~~

Activate the environment:

**Windows PowerShell**

~~~powershell
.venv\Scripts\Activate.ps1
~~~

**macOS / Linux**

~~~bash
source .venv/bin/activate
~~~

Install dependencies and launch the app:

~~~bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
# Optional: install local speech-to-text support for video uploads
python -m pip install -r requirements-local-ai.txt
# Optional: install Ollama and pull the default local model (see below).
# Windows PowerShell:
.\\scripts\\setup-ollama.ps1
# macOS / Linux:
bash scripts/setup-ollama.sh
# Optional extra vision model, after Ollama is running:
ollama pull qwen2.5vl:3b
streamlit run satark.py
~~~

Streamlit prints the local URL in the terminal. Open that address in your browser. Ollama setup scripts are opt-in: they ask before installing from the official Ollama distribution, start/check the local service, and pull `qwen2.5:3b`. You can skip them entirely. If Ollama is absent or unavailable, deterministic FIRSTLIGHT and local-rule analysis still work without any model download or third-party AI credentials.

## 11. Legacy web/Streamlit data handling (separate from Android File Guard)

The Next.js analysis route runs local deterministic rules by default. It does not call Groq, URLhaus, AbuseIPDB, or another third-party analysis API. No third-party AI API key is required.

To enable optional model suggestions, run an Ollama instance you control. From the repository root, use `scripts/setup-ollama.ps1` in Windows PowerShell or `bash scripts/setup-ollama.sh` on macOS/Linux. The scripts ask permission before installing, use the official Ollama distribution, and pull `qwen2.5:3b` by default. You can choose another model with `SATARK_OLLAMA_MODEL`. The Next.js app uses `SATARK_OLLAMA_BASE_URL` and `SATARK_OLLAMA_MODEL`; the Python/Streamlit app uses `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434`) and the model names configured in `ai_provider.py`. The Compose example uses an internal `http://ollama:11434` service address. Initial model downloads need internet access and several GB of disk space, but no AI API key; inference runs locally after download.

**Important hosting boundary:** a browser or server hosted on Vercel cannot reach `127.0.0.1` on a user's laptop. These scripts enable Ollama for SATARK running on the same computer (or a private self-hosted environment configured to reach the Ollama host). On the hosted website, users still get deterministic analysis if no model is configured; installing Ollama on their computer does not automatically connect it to Vercel.

The Python/Streamlit app now uses the same local Ollama approach; the default requirements no longer include the Groq SDK. The self-hosted Compose image includes local faster-whisper for video-audio transcription. No third-party AI API key is required.

See [Local-only deployment](docs/LOCAL_ONLY_DEPLOYMENT.md) for setup and safety boundaries.

## 12. Tests and engineering safeguards

Run the repository's local checks:

~~~bash
python -m pip check
python -m compileall -q .
python -m unittest discover -s tests -v
cd web
npm ci
npm run test:ci
npm run evaluate:local-analysis
~~~

The test suite covers areas including:

- Local Ollama configuration and model selection
- Analysis normalization and stable finding behavior
- FIRSTLIGHT investigation and evidence-ingestion rules
- Input-processing boundaries and safe error handling
- URL validation, redirect handling, and SSRF-related edge cases
- Evidence-coverage review behavior
- PDF report generation
- Video-processing helpers
- UI contracts and Scam Challenge behavior

GitHub Actions also runs dependency/compile/test checks, browser smoke and layout checks, asset/style/whitespace validation, and a CodeQL workflow. Consult the [CI workflow](https://github.com/kaustubhdua/Satark/actions/workflows/ci.yml) and [CodeQL workflow](https://github.com/kaustubhdua/Satark/actions/workflows/codeql.yml) for current run status.

**A passing test suite is evidence of the checks that ran, not proof of production readiness.** Live provider behavior, host configuration, external data handling, deployment revision, and manual device testing require separate verification. See the [release-readiness runbook](docs/RELEASE_READINESS.md).

## 13. Security, privacy, and current limitations

### Current safeguards

- Input-processing paths use format-specific size and parsing limits.
- URL fetching rejects unsafe destinations, validates resolved addresses, pins connections, rechecks redirects, and restricts response types and size.
- AI results are normalized before display; the model is treated as an untrusted analyzer.
- User-facing error handling is designed not to expose raw provider payloads or secrets.
- API keys belong in environment variables or a host secret manager—not source control.
- CI and CodeQL provide repeatable checks for regressions.

### Known limitations and release gates

- **Release verification is still required:** the Next.js web workspace has authenticated persistence APIs and tenant-scoped database policies, but the latest `main` revision has not yet been verified on the production alias. Do not use the live deployment for confidential multi-user cases until the exact deployed SHA, production smoke tests, and isolated authorization tests pass.
- **Legacy Streamlit session state is temporary:** the older Streamlit experience is not a durable case-management database. The self-hosted FastAPI + SQLAlchemy backend is the replacement for the former self-hosted case/evidence/findings/reports workflow. Its migration branch still requires complete API compatibility, regression tests, and deployment acceptance before confidential use.
- **Evidence provenance is not independently anchored:** SHA-256 hashes support integrity comparison, but they do not by themselves prove original source, collection procedure, or independent chain of custody.
- **Audit boundaries differ by workflow:** FIRSTLIGHT's demo/session audit trail is not an enterprise audit service. The web database has persistent hash-chained audit records, but production policy consistency and end-to-end verification still require successful isolated and deployed tests.
- **Shared rate limiting must be verified:** Vercel analysis fails closed without a working Upstash Redis REST configuration. Process-local limits are for local development only and are not a distributed/global quota.
- **Hosting-level controls need verification:** request-body limits, concurrency, execution timeouts, egress restrictions, abuse controls, monitoring and cost ceilings must be verified at the deployment layer.
- **Local model checks need target-environment validation:** model success, timeout, missing weights, malformed output, and deterministic fallback must be tested on the actual hardware.
- **Detection quality remains uncalibrated:** a repeatable 12-case synthetic corpus now reports precision, recall, F1, latency and a limited evidence-grounding check. These metrics are regression diagnostics only, not representative real-world detection rates.
- **Local model privacy review remains necessary:** secure model logs, cache directories, uploaded evidence, retention/deletion behavior, and incident ownership before handling real user data.
- **Not a malware sandbox or certified forensic platform:** the app does not execute suspicious files in an isolated environment or guarantee exhaustive inspection.

### Recommended use right now

Use SATARK Sentinel for **hackathon demonstration, supervised exploration, and synthetic/non-sensitive test inputs**, after checking the exact deployed revision. Do not use it as the sole basis for security decisions or for confidential, regulated, or real incident evidence.

See [Security policy](SECURITY.md), [Analysis limitations](docs/ANALYSIS_LIMITATIONS.md), [Architecture](docs/ARCHITECTURE.md), and [Release readiness](docs/RELEASE_READINESS.md).

## 14. Roadmap

The following is a forward-looking roadmap, not a claim that every item is implemented.

### Near-term: demonstration quality and reliability
- [ ] Complete target-deployment smoke tests against the exact deployed commit.
- [ ] Test local Ollama success and failure modes with pinned model revisions on supported hardware.
- [ ] Expand adversarial tests for malformed/encrypted PDFs, image edge cases, video edge cases, and URL abuse cases.
- [ ] Keep the README, architecture notes, demo flow, and release sign-off aligned with the actual code.

### Next: stronger investigation workflow
- [ ] Complete end-to-end verification of the self-hosted case/evidence/findings/reports workflow, including retention/deletion behavior.
- [ ] Finish and pass cross-tenant authorization/storage regression tests, then verify the same policies on the deployed release before multi-user sensitive use.
- [ ] Design independently verifiable evidence manifests and durable audit records.
- [ ] Add clear case lifecycle, export validation, and audit verification UX.
- [ ] Measure investigation usefulness with a repeatable synthetic dataset and human-reviewed rubric.

### Later: operational readiness
- [ ] Add deployment-level global quotas, concurrency controls, cost limits, monitoring, and alerting.
- [ ] Verify restrictive egress policy in the actual hosting environment.
- [ ] Document incident response, backup/restore, rollback, and ownership.
- [ ] Establish evaluation metrics for accuracy, false positives, grounding, latency, and robustness.
- [ ] Complete local model privacy and data-retention review before permitting sensitive evidence.

## 15. Project structure

~~~text
.
├── .github/
│   └── workflows/              # CI and CodeQL workflows
├── .streamlit/
│   └── config.toml             # Streamlit runtime defaults
├── assets/
│   └── satark-banner.svg
├── docs/
│   ├── ANALYSIS_LIMITATIONS.md
│   ├── ARCHITECTURE.md
│   ├── FIRSTLIGHT.md
│   ├── RELEASE_READINESS.md
│   └── UI_DESIGN.md
├── tests/                       # Unit, regression, and smoke tests
├── ui/                          # Streamlit workspace modules
├── analysis_engine.py            # Analysis normalization and risk logic
├── ai_provider.py                # Local Ollama compatibility client
├── config.py                     # Runtime and processing limits
├── evidence_engine.py            # Deterministic signal extraction
├── findings.py                   # Finding normalization/contracts
├── firstlight_engine.py          # FIRSTLIGHT investigation workflow
├── firstlight_ingest.py          # Bounded event/artifact ingestion
├── input_processing.py           # Bounded text/PDF/image input processing
├── reports.py                    # PDF report generation
├── review_engine.py              # Evidence-coverage review
├── satark.py                     # Streamlit app entry point/orchestration
├── satark_utils.py               # Shared utility functions
├── url_security.py               # URL validation and safe public fetching
├── video_processing.py           # Video frame/audio helpers
├── styles.css                    # Responsive visual system
├── requirements.txt
├── SECURITY.md
├── CONTRIBUTING.md
└── README.md
~~~

## 16. Legacy hackathon project summary (not the Android File Guard description)

Use this section as a source for a pitch deck. Adapt it to the event's required format and only make claims the team can demonstrate.

### One-line description

**SATARK Sentinel is an evidence-first security investigation prototype that helps users structure a synthetic incident, inspect evidence-linked findings and gaps, and triage suspicious digital content with optional AI assistance.**

### Short abstract

Digital threats often arrive as disconnected messages, links, attachments, and event records. SATARK Sentinel combines FIRSTLIGHT Incident Command—a deterministic investigation workflow over a synthetic account-compromise scenario—with supporting AI-assisted scanners for suspicious text, URLs, images, QR codes, PDFs, and supported videos. It highlights observable signals, evidence references, timelines, and unanswered questions, while keeping human review central to simulated response decisions. The prototype is built with Python and Streamlit, uses self-hosted Ollama for supported AI workflows, and includes regression tests and automated CI checks. It is intended for awareness, demonstration, and triage—not as a replacement for professional incident response or a certified forensic system.

### Problem statement

Users need a clearer way to move from disconnected digital warning signs to an evidence-informed next step. A single risk score does not explain the evidence, its gaps, or the limits of a conclusion.

### Proposed solution

Provide a guided investigation workspace that links deterministic findings to available evidence, displays a timeline and evidence gaps, and lets a human review simulated response actions—alongside optional AI-assisted scanning of common suspicious-content formats.

### Key demo-able capabilities

- Synthetic account-compromise investigation in FIRSTLIGHT.
- SHA-256 evidence integrity check and controlled tampering demonstration.
- Deterministic evidence-linked findings and chronological timeline.
- Explicit evidence gaps and simulated human approval/rejection.
- In-session hash-chained audit demonstration and JSON export.
- Supporting text/URL/image/QR/PDF/video triage workflows.
- Local pattern signals separated from AI interpretation.
- PDF reporting, learning content, and automated regression checks.

### Target users and use cases

Potential audiences include students learning cyber safety, awareness trainers, hackathon evaluators, and teams exploring how to structure an initial triage workflow. Any real-world deployment would need appropriate access controls, data-handling review, operational safeguards, and validation first.

### Current status and honest claim boundary

The repository contains a working prototype and automated tests. The live application is available at the demo link above, but deployment revision and all local-model paths must be checked in the target environment before claiming a fully verified release. No measured detection benchmark, production multi-tenant security, durable evidence custody, or real response integration is claimed.

## 17. Contributing

Contributions are welcome, especially focused improvements to reliability, accessibility, investigation clarity, and tests.

1. Keep changes focused and explain the behavior being changed.
2. Add regression tests for bug fixes and new behavior.
3. Run the local checks and report exactly which checks passed.
4. Never commit API keys, tokens, private incident evidence, or other sensitive data.
5. Report suspected vulnerabilities through the process in [SECURITY.md](SECURITY.md), rather than posting sensitive details publicly.

## 18. Documentation

- [FIRSTLIGHT workflow and safety boundaries](docs/FIRSTLIGHT.md)
- [Architecture and threat model](docs/ARCHITECTURE.md)
- [Supabase-free runtime and persistence](docs/SUPABASE_FREE.md)
- [Local YARA rules and synthetic evaluation](docs/LOCAL_YARA_RULES.md)
- [Detection evaluation methodology and metrics](docs/DETECTION_EVALUATION.md)
- [Manual EMBER2024 snapshot workflow](.github/workflows/ember2024-snapshot.yml)
- [Analysis limitations](docs/ANALYSIS_LIMITATIONS.md)
- [UI design notes](docs/UI_DESIGN.md)
- [Web lazy-loading strategy](docs/WEB_LAZY_LOADING.md)
- [Local development and safe integration setup](docs/LOCAL_DEVELOPMENT.md)
- [Release readiness and deployment sign-off](docs/RELEASE_READINESS.md)
- [Self-hosted backend setup and migration guide](docs/SELF_HOSTED_BACKEND.md)
- [FIRSTLIGHT live-response adapter scope and prerequisites](docs/FIRSTLIGHT_LIVE_RESPONSE.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)

---

<div align="center">

**SATARK Sentinel — evidence first, AI assisted, human reviewed.**

</div>


## Release & acceptance

- [Track 1 release runbook](docs/TRACK_1_RELEASE_RUNBOOK.md) — real-provider acceptance, tenant isolation, migration safety and release gates.
- [Saathi live security catalog audit](docs/SAATHI_LIVE_SECURITY_CATALOG_2026-10-21.md) — read-only live RLS and approval-ACL evidence (not authenticated end-to-end proof).
- [Local/offline acceptance runbook](docs/LOCAL_OFFLINE_ACCEPTANCE.md) — self-hosted SATARK + Ollama setup and no-internet acceptance steps.
