#!/usr/bin/env python3
"""Train SATARK's email-length wording model (same binary word n-gram + logistic regression design as the SMS model).

Data: CEAS 2008 Live Spam Challenge corpus as redistributed in GitHub repo PHP4Life/Phishing-Email-Dataset
(CEAS_08.csv; columns sender,receiver,date,subject,body,label,urls; label 1 = spam/phishing, 0 = legitimate).
It is a single month (Aug 2008) of one honeypot-style collection, so it is old, mostly bulk spam rather than
targeted phishing, and its legitimate mail comes from one research mailbox. Licence terms of the redistribution are
not stated; only the derived weight table is shipped, never the emails.
Split: by sender domain 80/10/10 so a spammer/campaign never straddles train and test.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, random, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.train_message_model import feature_tokens  # noqa: E402  (shared tokenizer, mirrored in JS)

SEED = 20261127
MAX_FEATURES = 8000
MAX_CHARS = 3000


def sender_domain(sender: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", sender or "")
    return (m.group(1).lower() if m else (sender or "unknown").lower())


def email_text(subject: str, body: str) -> str:
    return (subject.strip() + "\n" + body.strip())[:MAX_CHARS]


def main():
    import numpy as np
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    ap = argparse.ArgumentParser(); ap.add_argument("--data", required=True); ap.add_argument("--out", default="ml/models/email-v1.json")
    a = ap.parse_args()
    csv.field_size_limit(10**9)
    rows, seen = [], set()
    with open(a.data, encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or [])
        is_modern = "Email Text" in fields and "Email Type" in fields
        for i, r in enumerate(reader):
            if is_modern:
                etype = (r.get("Email Type") or "").strip()
                if etype not in ("Safe Email", "Phishing Email"):
                    continue
                text = (r.get("Email Text") or "").strip()[:MAX_CHARS]
                label = 1 if etype == "Phishing Email" else 0
                group = f"row_{i // 5}"  # group nearby rows when sender is absent
            else:
                if r.get("label") not in ("0", "1"): continue
                text = email_text(r.get("subject", ""), r.get("body", ""))
                label = int(r["label"])
                group = sender_domain(r.get("sender", ""))
            key = re.sub(r"\s+", " ", text.lower())[:400]
            if len(text) < 30 or key in seen: continue
            seen.add(key); rows.append((text, label, group))
    source_desc = "sahith002/phishing-email-dataset Phishing_Email.csv (multi-corpus Enron + Nazario + phishing)" if is_modern else "CEAS 2008 Live Spam Challenge corpus via PHP4Life/Phishing-Email-Dataset CEAS_08.csv"
    print("unique emails", len(rows), "spam share", sum(l for _, l, _ in rows) / len(rows))
    rng = random.Random(SEED)
    doms = sorted({d for *_, d in rows}); rng.shuffle(doms)
    part_of = {d: (0 if i % 10 < 8 else 1 if i % 10 == 8 else 2) for i, d in enumerate(doms)}
    parts = {k: [r for r in rows if part_of[r[2]] == i] for k, i in (("train", 0), ("val", 1), ("test", 2))}
    cv = CountVectorizer(analyzer=feature_tokens, binary=True, max_features=MAX_FEATURES, min_df=5)
    cv.fit([t for t, _, _ in parts["train"]])
    X = {k: cv.transform([t for t, _, _ in v]) for k, v in parts.items()}
    y = {k: np.array([l for _, l, _ in v]) for k, v in parts.items()}
    clf = LogisticRegression(C=1.0, max_iter=800, solver="liblinear", class_weight="balanced").fit(X["train"], y["train"])
    vs = clf.decision_function(X["val"]); ham = np.sort(vs[y["val"] == 0])
    thr_high = float(ham[int(0.99 * len(ham))]); thr_elev = float(ham[int(0.95 * len(ham))])
    ts, ty = clf.decision_function(X["test"]), y["test"]
    def rate(thr):
        p = ts >= thr; tp = int((p & (ty == 1)).sum()); fp = int((p & (ty == 0)).sum()); fn = int((~p & (ty == 1)).sum()); tn = int((~p & (ty == 0)).sum())
        return {"threshold": thr, "recall": tp / max(tp + fn, 1), "false_positive_rate": fp / max(fp + tn, 1), "precision": tp / max(tp + fp, 1), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
    metrics = {"test_roc_auc": float(roc_auc_score(ty, ts)), "test_examples": int(len(ty)), "test_spam": int(ty.sum()), "at_high_threshold": rate(thr_high), "at_elevated_threshold": rate(thr_elev)}
    inv = {i: t for t, i in cv.vocabulary_.items()}
    weights = {inv[int(i)]: round(float(clf.coef_[0][i]), 6) for i in np.nonzero(clf.coef_[0])[0]}
    model = {"name": "satark-email-v1", "kind": "binary-token-logistic-regression", "bias": round(float(clf.intercept_[0]), 6),
             "thresholds": {"elevated": round(thr_elev, 6), "high": round(thr_high, 6)}, "weights": weights, "max_chars": MAX_CHARS,
             "training": {"source": source_desc, "examples": len(rows), "seed": SEED,
                          "split": "80/10/10 after near-duplicate removal", "file_sha256": hashlib.sha256(open(a.data, "rb").read()).hexdigest()},
             "metrics": metrics}
    json.dump(model, open(a.out, "w"), separators=(",", ":"), sort_keys=True)
    print(json.dumps(metrics, indent=1)); print("features", len(weights))


if __name__ == "__main__":
    main()
