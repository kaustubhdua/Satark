# SATARK local demo runbook

This guide is for a supervised classroom/hackathon demonstration using synthetic, non-sensitive inputs. It does not claim that every legacy capability is migrated into the web app or that the app is production-ready.

## Recommended presentation: Next.js web workspace

Prerequisites: Git, Node.js 20 or newer, and npm. Internet is needed for the initial dependency install.

### Start it

From the repository root:

```bash
cd web
npm ci
npm run dev
```

Open http://localhost:3000. Keep the terminal open while presenting. If port 3000 is occupied, stop the other local app or use the port printed by Next.js.

On Windows PowerShell, the commands are the same:

```powershell
Set-Location web
npm ci
npm run dev
```

No third-party AI key or database credential is required for the local deterministic investigation demo. Local development uses a process-local rate limiter. Do not set `VERCEL=1` locally unless you deliberately want to reproduce production's shared-limiter requirement.

### Suggested 5-minute demo

1. Open the home page and explain that the application is a triage aid, not an antivirus or a proof of safety.
2. Open **Investigate** and select **Try phishing example**. Click **Analyze content** and explain the observable urgency, credential-request and shortened-link signals.
3. Select **Try ordinary message** and analyze it. Compare signals instead of claiming the result proves the message is safe.
4. Select **Try ambiguous case** and analyze it. Explain why context and sender verification remain necessary.
5. Open **Image review** to show local metadata/hash inspection; do not call it a deepfake detector.
6. Open **FIRSTLIGHT** to demonstrate the synthetic incident, evidence/timeline and simulated response controls.
7. Open **Tools** to show the honest feature-status and migration directory.

The sample buttons submit synthetic text to the same local analysis endpoint as ordinary input. They do not insert pre-written results.

### Run the web checks

In another terminal, from `web/`:

```bash
npm run typecheck
npm test
npm run build
```

For a production-mode local smoke test, after a successful build:

```bash
npm run start
```

Then open the local URL printed by Next.js. Do not run `npm run dev` and `npm run start` on the same port simultaneously.

## Optional legacy Python/Streamlit demo

The repository also contains the original Python interface. From the repository root, create and activate a virtual environment, then run:

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# macOS/Linux instead:
# source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
streamlit run satark.py
```

Use the local URL printed by Streamlit. Optional Ollama model setup is not required to demonstrate the deterministic FIRSTLIGHT scenario and fallback checks. Do not spend presentation time downloading models unless they have already been installed and tested.

## What requires additional configuration

- Authenticated workspace, case, evidence and report persistence requires the appropriate Supabase configuration and verified database schema/RLS policies. Without it, storage APIs should report that storage is unavailable; do not claim persistence is working.
- Production deployment requires a shared rate limiter. The production API intentionally fails closed if it is missing or unavailable. Do not replace it with a process-local limiter in production.
- Optional Ollama analysis requires an Ollama server and a locally available model.
- Full PDF/video web workflows, cross-browser QR decoding and several parity items are not complete in the current Next.js workspace.

## Quick troubleshooting

- **`npm` is not recognized:** install Node.js 20+ and reopen the terminal.
- **Port 3000 is busy:** stop the other app or run `npm run dev -- --port 3001`, then open http://localhost:3001.
- **Missing `node_modules`:** run `npm ci` from `web/`.
- **Analysis says rate limiter unavailable:** confirm you are running the local Next.js dev server without `VERCEL=1`; do not weaken the production guard.
- **Workspace storage unavailable:** this is expected without configured Supabase Auth, schema and RLS. Demonstrate public local analysis/FIRSTLIGHT instead and do not claim database-backed saving.
- **A route is missing locally:** confirm the terminal is running from `web/`, stop and restart the dev server, then inspect the terminal error.

## Safety and presentation honesty

Use only the supplied synthetic samples or other non-sensitive text. Never paste passwords, OTPs, private keys, personal incident data or confidential files. Explain that a heuristic risk score is a prioritization signal, not a calibrated probability. A lack of detected signals is not evidence that content is safe.