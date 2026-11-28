# SATARK model cards

SATARK ships five local learned models next to its deterministic rules. All models are **advisory**: they add a labelled
signal to an analysis, they never produce a verdict, and the rules and the analyst's judgment stay authoritative.
All five run entirely locally (in the browser or the web server's analysis route; no third-party API) as plain JSON weight tables.

Everything below is reproducible: `ml/train_url_model.py`, `ml/train_message_model.py`, `ml/train_email_model.py`,
`ml/train_pdf_model.py`, and `ml/train_image_model.py` regenerate the files in `ml/models/`;
`scripts/generate_model_parity_fixture.py` pins the Python reference scores that the JavaScript inference
must match to 1e-9 (CI enforces this).

## satark-url-host-v1 — hostname lexical risk

| | |
|---|---|
| Task | Does the **hostname text** of a URL resemble hosts seen in phishing lists? |
| Positives | 430,045 unique hosts from `mitchellkrogza/Phishing.Database` `phishing-links-ACTIVE.txt` (120,000 sampled) |
| Negatives | popularity-ranked domains from `zer0h/top-1000000-domains` (120,000 sampled) |
| Features | binary char 3–5-grams of the host plus structural tokens (length, label count, digit share, hyphens, TLD, IP) |
| Model | L2 logistic regression, 20,000 weighted tokens (346 KB) |
| Split | by registered domain, 80/10/10 (train / threshold / test) — no domain appears on both sides |
| Held-out result | ROC-AUC **0.949**; at the "high" threshold: recall **78.4 %**, false-positive rate **0.86 %** |
| Popular sites | 26 of 7,443 unseen top-10k domains (0.35 %) scored "high" |

## satark-message-v1 — short message & smishing wording

| | |
|---|---|
| Task | Does the **wording** of a short message (<300 chars) resemble spam, smishing, or phishing? |
| Data | SMS Spam Collection v.1 (UCI) + short messages (<400 chars) from `sahith002/phishing-email-dataset` `Phishing_Email.csv` |
| Features | binary word uni/bi-grams plus tokens for URL, long number, money, shouting, length |
| Model | L2 logistic regression, 6,000 weighted tokens (124 KB), class-balanced |
| Split | random 80/10/10 after exact-duplicate removal |
| Held-out result | ROC-AUC **0.994**; at "high": recall **81.7 %**, precision **99.5 %**, false-positive rate **0.15 %** (test set: 910 messages, 224 positive) |

## satark-email-v1 — email-length wording

| | |
|---|---|
| Task | Does the **wording** of a longer message (300+ characters; first 3,000 characters) resemble phishing or spam email? |
| Data | `sahith002/phishing-email-dataset` `Phishing_Email.csv` (17,105 unique multi-corpus emails) |
| Features / model | same binary word uni/bi-gram tokens as the message model; L2 logistic regression, 8,000 weighted tokens (168 KB), class-balanced |
| Split | grouped 80/10/10 after near-duplicate removal |
| Held-out result | ROC-AUC **0.998**; at "high": recall **97.1 %**, precision **98.4 %**, false-positive rate **0.94 %** (test: 1,694 emails, 628 phishing) |

## satark-pdf-v1 — PDF structural risk

| | |
|---|---|
| Task | Does the **internal object/action structure** of a PDF resemble malicious PDFs? |
| Data | CIC-Evasive-PDFMal2022 (`arcofiero/PDF_Malware_Detection` `PDFMalware2022.csv`) — 10,025 PDFs (5,557 malicious, 4,468 benign) |
| Features | binary structural tokens (`/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/AcroForm`, `/XFA`, `/RichMedia`, `/JBIG2Decode`, `/ObjStm`, `/Encrypt`, bucketed size, pages, obj/stream counts and mismatches) |
| Model | L2 logistic regression, 41 weighted tokens (1.7 KB), class-balanced |
| Split | random 80/10/10 after filename deduplication |
| Held-out result | ROC-AUC **0.995**; at "high": recall **95.7 %**, precision **97.5 %**, false-positive rate **3.33 %** (test: 1,003 PDFs, 582 malicious) |

## satark-image-v1 — image forensics & synthetic-image advisory

| | |
|---|---|
| Task | Do **Error Level Analysis (ELA)**, high-frequency noise, flatness, and dimension tokens resemble synthetic/AI-generated images? |
| Data | Balanced subset of `Hemg/AI-vs-Real-images` (HuggingFace) |
| Features | 128×128 JPEG q=90 ELA mean/std/high-ratio, 3×3 Laplacian edge/noise mean/std, adjacent-pixel flatness ratio, HSV saturation mean, power-of-2 / square / resolution tokens |
| Model | L2 logistic regression, 31 weighted tokens (1.5 KB), class-balanced |
| Split | random 80/10/10 |
| Held-out result | ROC-AUC **0.866**; at "high": recall **45.5 %**, precision **83.3 %**, false-positive rate **5.26 %** (test: 30 images) |

## Notes & remaining rule-based workflows

- **QR review**: decodes QR payloads in-browser via `BarcodeDetector` / `jsQR` and scores extracted URLs using `satark-url-host-v1` + URL rules.
- **Image review**: runs `satark-image-v1` + 10x ELA residual map + `jsQR` embedded QR scan in-browser.
- **Video/media review**: samples 6 frames in-browser and scores each frame with `satark-image-v1` alongside luminance metrics; it does not analyze audio or issue deepfake verdicts.
- **FIRSTLIGHT investigation**: 10 deterministic, explainable rules so analysts can audit every finding.

Retraining and any claim of improvement must keep the held-out split, record dataset hashes in the model JSON, and update this file.
