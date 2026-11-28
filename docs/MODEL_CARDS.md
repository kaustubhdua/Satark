# SATARK model cards

SATARK ships three small learned models next to its deterministic rules. Both are **advisory**: they add a labelled
signal to an analysis, they never produce a verdict, and the rules and the analyst's judgment stay authoritative.
Both run entirely locally (in the web server's analysis route; no third-party API) as plain JSON weight tables.

Everything below is reproducible: `ml/train_url_model.py` and `ml/train_message_model.py` regenerate the files in
`ml/models/`; `scripts/generate_model_parity_fixture.py` pins the Python reference scores that the JavaScript inference
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
| Held-out result | ROC-AUC **0.949**; at the "high" threshold: recall **78.5 %**, false-positive rate **0.85 %** |
| Popular sites | 27 of 7,443 unseen top-10k domains (0.4 %) scored "high" |

**Limits — read before trusting it.**
- It sees only the host name. It cannot see the page, certificate, age or reputation of a domain.
- Negatives are *popular* domains; real benign traffic includes many obscure sites the model has never seen, so the
  real-world false-positive rate is higher than the 0.85 % measured here.
- Benign hosts in the list are registered domains while many phishing hosts are subdomains of free hosting, so part
  of the signal is "looks like free-hosting abuse". That is a legitimate risk cue but not proof of anything.
- Phishing.Database is community-maintained; labels can be stale or wrong. The "balanced" 50/50 prior is artificial, so
  scores are not probabilities and no probability is displayed.
- It adds a *medium* (high band) or *low* (elevated band) evidence item to the analysis; it never sets a category on its own.

## satark-message-v1 — message wording

| | |
|---|---|
| Task | Does the **wording** of a message resemble spam/scam messages? |
| Data | SMS Spam Collection v.1 (Almeida & Hidalgo; UCI), mirrored at `justmarkham/pycon-2016-tutorial` — 5,169 unique messages after duplicate removal |
| Features | binary word uni/bi-grams plus tokens for URL, long number, money, shouting, length |
| Model | L2 logistic regression, 6,000 weighted tokens (124 KB), class-balanced |
| Split | random 80/10/10 after exact-duplicate removal |
| Held-out result | ROC-AUC **0.992**; at "high": recall **93.4 %**, false-positive rate **0.9 %** (test set: 516 messages, 76 spam) |

**Limits.**
- The test set is small (76 spam messages): treat the figures as indicative, with wide error bars.
- English SMS from about 2012. It knows prize, premium-rate and "call now" spam; it does **not** know modern bank
  impersonation, delivery scams, QR phishing or non-English text, and can miss them (e.g. "Your account is suspended.
  Verify your password now" scores only *elevated*).
- Random splits can leak near-duplicate campaigns; the real-world result is likely lower.

## satark-email-v1 — email-length wording

| | |
|---|---|
| Task | Does the wording of a longer message (300+ characters; subject + body, first 3,000 characters) resemble spam/phishing email? |
| Data | CEAS 2008 Live Spam Challenge corpus via GitHub `PHP4Life/Phishing-Email-Dataset` `CEAS_08.csv` — 35,370 unique emails after near-duplicate removal (52.8 % spam/phishing) |
| Features / model | same binary word uni/bi-gram tokens as the SMS model; L2 logistic regression, 8,000 weighted tokens (169 KB), class-balanced |
| Split | by sender domain, 80/10/10 — a sender never appears on both sides |
| Held-out result | ROC-AUC **0.998**; at "high": recall **87.0 %**, false-positive rate **0.65 %** (test: 2,845 emails, 1,773 spam) |

**Limits — the score is probably flattering.**
- One month (August 2008) from one collection: mostly bulk commercial spam (pharmacy, pills, stock pumps), not targeted phishing.
  Legitimate mail comes from a single research mailbox, so the model may partly learn that mailbox's style. A 0.998 AUC on a
  within-corpus split does not predict performance on today's mail.
- Because of this the product never rates this model's output above **low** severity, whatever the band.
- Redistribution terms of the CSV are not stated; only the derived weight table is shipped, never the emails.
- Routing: text under 300 characters is scored by the SMS model, longer text by this one.

## Tasks that have no trained model, and why

| Feature | Approach | Why |
|---|---|---|
| Image, PDF, media/video review | deterministic structure and metadata checks | no licensed, reachable training data for tamper/deepfake detection in this environment, and such models need far more data and evaluation than is honest to claim |
| QR review | decode + the same URL rules and URL-host model | the payload is a URL |
| FIRSTLIGHT investigation | 10 deterministic, explainable rules | analysts must be able to audit every finding; a learned scorer would reduce that |
| Android File Guard | offline hash lookup over an EMBER2024 APK subset (see README) | separate, already documented offline design |

Retraining and any claim of improvement must keep the held-out split, record dataset hashes in the model JSON, and
update this file.
