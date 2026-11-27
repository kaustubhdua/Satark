#!/usr/bin/env python3
"""Train SATARK's lexical URL-host risk model.

Data (downloaded at train time, never committed):
  phishing: mitchellkrogza/Phishing.Database  phishing-links-ACTIVE.txt  (MIT)
  benign:   zer0h/top-1000000-domains          popularity-ranked domains
Model: binary character n-grams + structural tokens of the URL *host only* -> L2 logistic regression.
Exported as plain JSON (token -> weight) so the browser and Python score identically.
Split by registered domain so no domain appears in both train and test.
Run:  python ml/train_url_model.py --phish PATH --benign PATH [--out ml/models/url-host-v1.json]
"""
from __future__ import annotations
import argparse, hashlib, json, math, random, re
from urllib.parse import urlsplit

NGRAM = (3, 5)
MAX_FEATURES = 20000
SEED = 20261127


def host_of(raw: str):
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        h = (urlsplit(raw).hostname or "").lower().strip(".")
    except ValueError:
        return None
    if not h or len(h) > 253 or not re.fullmatch(r"[a-z0-9.\-_]+", h):
        return None
    return h[4:] if h.startswith("www.") else h


def registered_domain(h: str) -> str:
    parts = h.split(".")
    if len(parts) >= 3 and (len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"}):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def bucket(n, edges):
    for i, e in enumerate(edges):
        if n <= e:
            return i
    return len(edges)


def doc(h: str) -> str:
    """Token string: char n-grams come from the analyzer; structural tokens are appended as words."""
    labels = h.split(".")
    digits = sum(c.isdigit() for c in h)
    toks = [
        f"@len{bucket(len(h), [8, 12, 16, 20, 25, 32, 45])}",
        f"@labels{min(len(labels), 6)}",
        f"@digits{bucket(digits / max(len(h), 1), [0, .1, .25, .5])}",
        f"@hyph{min(h.count('-'), 4)}",
        f"@tld_{labels[-1]}",
        "@ip" if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h) else "@noip",
    ]
    return "^" + h + "$ " + " ".join(toks)


def tokens(d: str, vocab: dict):
    """Pure-python tokenizer that mirrors the vectorizer so the JS port can be exact."""
    return {t for t in feature_tokens(d) if t in vocab}


def feature_tokens(d: str):
    main, _, rest = d.partition(" ")
    out = set()
    for n in range(NGRAM[0], NGRAM[1] + 1):
        for i in range(len(main) - n + 1):
            out.add("c" + main[i:i + n])
    for w in rest.split(" "):
        if w:
            out.add(w)
    return out


def load(path, limit=None):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            h = host_of(line)
            if h:
                out.append(h)
            if limit and len(out) >= limit:
                break
    return out


def main():
    import numpy as np  # heavy deps only needed for training, not for scoring/parity
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", required=True)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--out", default="ml/models/url-host-v1.json")
    ap.add_argument("--per-class", type=int, default=120000)
    a = ap.parse_args()
    rng = random.Random(SEED)

    phish = sorted(set(load(a.phish)))
    benign_ranked = load(a.benign, 400000)  # popularity ranked: keep order for the top-k false-positive check
    benign_ranked = list(dict.fromkeys(benign_ranked))
    phish_set = set(phish)
    benign_ranked = [h for h in benign_ranked if h not in phish_set]
    print(f"phishing hosts: {len(phish)}  benign hosts: {len(benign_ranked)}")

    def sample(hosts, k):
        hosts = list(hosts)
        rng.shuffle(hosts)
        return hosts[:k]

    P = sample(phish, a.per_class)
    B = sample(benign_ranked, a.per_class)
    hosts = P + B
    y = np.array([1] * len(P) + [0] * len(B))
    groups = [registered_domain(h) for h in hosts]
    # split by registered domain: 80 train / 10 val (threshold) / 10 test
    uniq = sorted(set(groups))
    rng.shuffle(uniq)
    bucket_of = {g: (0 if i % 10 < 8 else 1 if i % 10 == 8 else 2) for i, g in enumerate(uniq)}
    part = np.array([bucket_of[g] for g in groups])
    docs = [doc(h) for h in hosts]

    cv = CountVectorizer(analyzer=feature_tokens, binary=True, max_features=MAX_FEATURES, min_df=5)
    Xtr_docs = [d for d, p in zip(docs, part) if p == 0]
    cv.fit(Xtr_docs)
    vocab = cv.vocabulary_
    X = cv.transform(docs)
    clf = LogisticRegression(C=0.5, max_iter=400, solver="liblinear")
    clf.fit(X[part == 0], y[part == 0])

    def scores(mask):
        return clf.decision_function(X[mask])

    val_s, val_y = scores(part == 1), y[part == 1]
    # threshold: highest recall subject to <=1% false positives on VALIDATION benign
    benign_val = np.sort(val_s[val_y == 0])
    thr_high = float(benign_val[int(0.99 * len(benign_val))])
    thr_elev = float(benign_val[int(0.95 * len(benign_val))])
    test_s, test_y = scores(part == 2), y[part == 2]
    auc = float(roc_auc_score(test_y, test_s))
    def rate(s, yy, thr):
        pred = s >= thr
        tp = int((pred & (yy == 1)).sum()); fp = int((pred & (yy == 0)).sum())
        fn = int((~pred & (yy == 1)).sum()); tn = int((~pred & (yy == 0)).sum())
        return {"threshold": thr, "recall": tp / max(tp + fn, 1), "false_positive_rate": fp / max(fp + tn, 1),
                "precision_at_balanced_prior": tp / max(tp + fp, 1), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
    metrics = {"test_roc_auc": auc, "at_high_threshold": rate(test_s, test_y, thr_high), "at_elevated_threshold": rate(test_s, test_y, thr_elev)}

    # False positives on very popular sites (the thing users feel): top-10k benign never used as a negative in training?
    top = benign_ranked[:10000]
    top_docs = [doc(h) for h in top]
    top_s = clf.decision_function(cv.transform(top_docs))
    in_train_domains = {g for g, p in zip(groups, part) if p == 0}
    held = [s for h, s in zip(top, top_s) if registered_domain(h) not in in_train_domains]
    metrics["top10k_popular_domains_flagged_high"] = {"evaluated": len(held), "flagged": int(sum(s >= thr_high for s in held)),
                                                     "note": "only domains whose registered domain was not in training"}

    weights = {}
    coef = clf.coef_[0]
    inv = {i: t for t, i in vocab.items()}
    for i in np.nonzero(coef)[0]:
        weights[inv[int(i)]] = round(float(coef[i]), 6)
    model = {
        "name": "satark-url-host-v1", "kind": "binary-token-logistic-regression", "ngram": list(NGRAM),
        "bias": round(float(clf.intercept_[0]), 6), "thresholds": {"elevated": round(thr_elev, 6), "high": round(thr_high, 6)},
        "weights": weights,
        "training": {"phishing_source": "mitchellkrogza/Phishing.Database phishing-links-ACTIVE.txt",
                     "benign_source": "zer0h/top-1000000-domains", "per_class": a.per_class, "seed": SEED,
                     "split": "by registered domain 80/10/10 (train/threshold/test)",
                     "phish_file_sha256": hashlib.sha256(open(a.phish, "rb").read()).hexdigest(),
                     "benign_file_sha256": hashlib.sha256(open(a.benign, "rb").read()).hexdigest()},
        "metrics": metrics,
    }
    with open(a.out, "w") as f:
        json.dump(model, f, separators=(",", ":"), sort_keys=True)
    print(json.dumps(metrics, indent=1)); print("features:", len(weights))


def score_host(model, h):
    toks = feature_tokens(doc(h))
    return model["bias"] + sum(model["weights"].get(t, 0.0) for t in toks)


if __name__ == "__main__":
    main()
