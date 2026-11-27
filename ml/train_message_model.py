#!/usr/bin/env python3
"""Train SATARK's scam/spam message model (binary word n-grams -> L2 logistic regression, exported as JSON).

Data: SMS Spam Collection (Almeida & Hidalgo, UCI), mirrored at justmarkham/pycon-2016-tutorial data/sms.tsv.
It is English SMS from ~2012: it teaches prize/premium-rate/urgent-call-to-action patterns, NOT modern
bank-impersonation or QR phishing. The model is therefore advisory and labelled as such in the product.
"""
from __future__ import annotations
import argparse, hashlib, json, random, re

SEED = 20261127
MAX_FEATURES = 6000


def feature_tokens(text: str):
    t = text.lower()
    out = set()
    words = re.findall(r"[a-z0-9']+", re.sub(r"https?://\S+|www\.\S+", " ", t))
    for i, w in enumerate(words):
        out.add("w" + w)
        if i + 1 < len(words):
            out.add("b" + w + " " + words[i + 1])
    if re.search(r"https?://|www\.", t): out.add("@url")
    if re.search(r"\b\d{5,}\b", t): out.add("@longnum")
    if re.search(r"[£$€]\s?\d|\d\s?(?:p|usd|gbp|eur)\b", t): out.add("@money")
    letters = [c for c in text if c.isalpha()]
    if letters and sum(c.isupper() for c in letters) / len(letters) > 0.3: out.add("@shouty")
    out.add("@len%d" % min(len(text) // 40, 6))
    return out


def main():
    import numpy as np  # heavy deps only needed for training, not for scoring/parity
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default="ml/models/message-v1.json")
    a = ap.parse_args()
    rows, seen = [], set()
    for line in open(a.data, encoding="utf-8", errors="ignore"):
        lab, _, msg = line.rstrip("\n").partition("\t")
        key = msg.strip().lower()
        if lab in ("ham", "spam") and msg and key not in seen:  # drop exact duplicates so they cannot straddle the split
            seen.add(key); rows.append((msg, 1 if lab == "spam" else 0))
    rng = random.Random(SEED); rng.shuffle(rows)
    n = len(rows); tr, va = int(.8 * n), int(.9 * n)
    parts = {"train": rows[:tr], "val": rows[tr:va], "test": rows[va:]}
    cv = CountVectorizer(analyzer=feature_tokens, binary=True, max_features=MAX_FEATURES, min_df=2)
    cv.fit([m for m, _ in parts["train"]])
    X = {k: cv.transform([m for m, _ in v]) for k, v in parts.items()}
    y = {k: np.array([l for _, l in v]) for k, v in parts.items()}
    clf = LogisticRegression(C=2.0, max_iter=600, solver="liblinear", class_weight="balanced").fit(X["train"], y["train"])
    vs = clf.decision_function(X["val"]); ham = np.sort(vs[y["val"] == 0])
    thr_high = float(ham[int(0.99 * len(ham))]); thr_elev = float(ham[int(0.95 * len(ham))])
    ts = clf.decision_function(X["test"]); ty = y["test"]
    def rate(thr):
        p = ts >= thr; tp = int((p & (ty == 1)).sum()); fp = int((p & (ty == 0)).sum()); fn = int((~p & (ty == 1)).sum()); tn = int((~p & (ty == 0)).sum())
        return {"threshold": thr, "recall": tp / max(tp + fn, 1), "false_positive_rate": fp / max(fp + tn, 1), "precision": tp / max(tp + fp, 1), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
    metrics = {"test_roc_auc": float(roc_auc_score(ty, ts)), "test_examples": int(len(ty)), "test_spam": int(ty.sum()),
               "at_high_threshold": rate(thr_high), "at_elevated_threshold": rate(thr_elev)}
    inv = {i: t for t, i in cv.vocabulary_.items()}
    weights = {inv[int(i)]: round(float(clf.coef_[0][i]), 6) for i in np.nonzero(clf.coef_[0])[0]}
    model = {"name": "satark-message-v1", "kind": "binary-token-logistic-regression", "bias": round(float(clf.intercept_[0]), 6),
             "thresholds": {"elevated": round(thr_elev, 6), "high": round(thr_high, 6)}, "weights": weights,
             "training": {"source": "SMS Spam Collection v.1 (UCI; mirror justmarkham/pycon-2016-tutorial)", "examples": n, "seed": SEED,
                          "split": "random 80/10/10 after exact-duplicate removal", "file_sha256": hashlib.sha256(open(a.data, "rb").read()).hexdigest()},
             "metrics": metrics}
    json.dump(model, open(a.out, "w"), separators=(",", ":"), sort_keys=True)
    print(json.dumps(metrics, indent=1)); print("features", len(weights))


if __name__ == "__main__":
    main()
