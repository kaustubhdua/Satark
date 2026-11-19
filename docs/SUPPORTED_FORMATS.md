# Supported formats and limits

Limits below are the values in the code today. `web/tests/supported-formats-doc.test.mjs` fails if a number in this
file stops matching its source constant, so the page cannot silently drift. Anything not listed is **not supported**.
All web-app analysis runs in the browser or in deterministic server code; nothing here is a verdict, only triage signals.

| Input | Where | Accepted | Limits | Source |
|---|---|---|---|---|
| Text or message | `/investigate` | Plain text | 12,000 characters per request; 48 KiB request body | `web/src/app/api/analyze/route.ts` |
| URL | `/url` | One `http(s)` URL | 4,096 characters | `web/src/app/url/page.tsx` |
| QR code | `/qr` | JPEG, PNG, WebP image | 10 MiB, 12,000,000 pixels | `web/src/app/qr/page.tsx` |
| Image review | `/image-review` | JPEG, PNG, WebP, GIF | 10 MiB, 40,000,000 pixels | `web/src/app/image-review/page.tsx` |
| Document review | `/pdf-review` | PDF, TXT, MD, CSV, LOG | PDF 15 MiB and 50 pages; text files 2 MiB; 300,000 extracted characters | `web/src/app/pdf-review/page.tsx` |
| Video review | `/media-review` | MP4, WebM | 50 MiB, 120 seconds, up to 3840x2160, 6 sampled frames | `web/src/app/media-review/page.tsx` |
| Report notes | `/reports` | Plain text | 20,000 characters | `web/src/app/reports/page.tsx` |
| FIRSTLIGHT event import | `/firstlight` | JSON or CSV | 10,000 event records | `web/src/lib/firstlight-import.mjs` |
| Private evidence file | `/firstlight` (signed in) | Any file whose bytes match its declared type for PDF, PNG, JPEG, ZIP, text, JSON; other types stored as opaque downloads | 1 byte to 4 MiB | `satark_backend.py` (`MAX_UPLOAD`) |
| Legacy Streamlit PDF / image | `satark.py` | PDF; PNG, JPG, WebP | PDF 25 MiB; image 10 MiB and 25,000,000 pixels | `input_processing.py` |
| File Guard (desktop) | Streamlit | Any file or folder | 64 MiB per file; 5,000 files, 1 GiB total, depth 8 per folder | `file_guard/engine.py` |

## What is deliberately not promised
- No audio analysis and no executable sandboxing.
- Image and video review give triage signals only; they do not prove authenticity or detect every manipulation.
- A document or image that parses cleanly is not shown to be safe. A missing signal never proves content is safe.
