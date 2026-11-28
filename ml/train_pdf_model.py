#!/usr/bin/env python3
"""Train SATARK's PDF structural risk model (binary structural tokens -> L2 logistic regression, exported as JSON).

Data: CIC-Evasive-PDFMal2022 (University of New Brunswick Canadian Institute for Cybersecurity,
mirrored at arcofiero/PDF_Malware_Detection PDFMalware2022.csv) — 10,025 PDFs (5,557 malicious, 4,468 benign).
All features are structural tokens extractable directly from raw PDF bytes in the browser with zero network calls.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, random

SEED = 20261127


def _num(val) -> float:
    try:
        s = str(val).strip()
        if not s or s.lower() in ("nan", "none", "-1"):
            return -1.0
        # Handle values like "1(1)" or "2(0)" in CIC dataset
        if "(" in s:
            s = s.split("(", 1)[0].strip()
        return float(s)
    except Exception:
        return -1.0


def _bucket(n: float, edges: list[float]) -> int:
    for i, e in enumerate(edges):
        if n <= e:
            return i
    return len(edges)


def pdf_tokens_from_features(
    pdfsize_kb: float,
    pages: float,
    is_encrypted: float,
    obj: float,
    endobj: float,
    stream: float,
    endstream: float,
    xref: float,
    trailer: float,
    startxref: float,
    objstm: float,
    js: float,
    javascript: float,
    aa: float,
    openaction: float,
    acroform: float,
    jbig2: float,
    richmedia: float,
    launch: float,
    embeddedfile: float,
    xfa: float,
) -> set[str]:
    toks: set[str] = set()
    if pdfsize_kb >= 0:
        toks.add(f"@size{_bucket(pdfsize_kb, [10, 30, 80, 250, 1000])}")
    if pages >= 0:
        toks.add(f"@pages{_bucket(pages, [0, 1, 2, 5, 15])}")
    if is_encrypted > 0:
        toks.add("@encrypted")
    if obj >= 0:
        toks.add(f"@obj{_bucket(obj, [10, 25, 60, 150, 500])}")
    if stream >= 0:
        toks.add(f"@stream{_bucket(stream, [2, 6, 15, 40, 150])}")
    if obj >= 0 and endobj >= 0 and abs(obj - endobj) > 1:
        toks.add("@obj_mismatch")
    if stream >= 0 and endstream >= 0 and abs(stream - endstream) > 1:
        toks.add("@stream_mismatch")
    if xref == 0:
        toks.add("@no_xref")
    if trailer == 0:
        toks.add("@no_trailer")
    if startxref == 0:
        toks.add("@no_startxref")
    if objstm > 0:
        toks.add("@objstm")
    if js > 0 or javascript > 0:
        toks.add("@js")
    if (js + max(javascript, 0.0)) > 1:
        toks.add("@js_multi")
    if aa > 0:
        toks.add("@aa")
    if openaction > 0:
        toks.add("@openaction")
    if acroform > 0:
        toks.add("@acroform")
    if jbig2 > 0:
        toks.add("@jbig2")
    if richmedia > 0:
        toks.add("@richmedia")
    if launch > 0:
        toks.add("@launch")
    if embeddedfile > 0:
        toks.add("@embedded")
    if xfa > 0:
        toks.add("@xfa")
    return toks


def row_to_tokens(r: dict[str, str]) -> set[str]:
    return pdf_tokens_from_features(
        pdfsize_kb=_num(r.get("pdfsize", -1)),
        pages=_num(r.get("pages", -1)),
        is_encrypted=_num(r.get("isEncrypted", 0)),
        obj=_num(r.get("obj", -1)),
        endobj=_num(r.get("endobj", -1)),
        stream=_num(r.get("stream", -1)),
        endstream=_num(r.get("endstream", -1)),
        xref=_num(r.get("xref", -1)),
        trailer=_num(r.get("trailer", -1)),
        startxref=_num(r.get("startxref", -1)),
        objstm=_num(r.get("ObjStm", 0)),
        js=_num(r.get("JS", 0)),
        javascript=_num(r.get("Javascript", 0)),
        aa=_num(r.get("AA", 0)),
        openaction=_num(r.get("OpenAction", 0)),
        acroform=_num(r.get("Acroform", 0)),
        jbig2=_num(r.get("JBIG2Decode", 0)),
        richmedia=_num(r.get("RichMedia", 0)),
        launch=_num(r.get("launch", 0)),
        embeddedfile=_num(r.get("EmbeddedFile", 0)),
        xfa=_num(r.get("XFA", 0)),
    )


def main():
    import numpy as np
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score

    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default="ml/models/pdf-v1.json")
    a = ap.parse_args()

    rows, seen = [], set()
    with open(a.data, encoding="utf-8", errors="ignore", newline="") as f:
        for r in csv.DictReader(f):
            cls = (r.get("Class") or "").strip()
            if cls not in ("Malicious", "Benign"):
                continue
            fname = (r.get("File name") or "").strip()
            if fname and fname in seen:
                continue
            if fname:
                seen.add(fname)
            toks = sorted(row_to_tokens(r))
            if not toks:
                continue
            rows.append((" ".join(toks), 1 if cls == "Malicious" else 0))

    rng = random.Random(SEED)
    rng.shuffle(rows)
    n = len(rows)
    tr, va = int(0.8 * n), int(0.9 * n)
    parts = {"train": rows[:tr], "val": rows[tr:va], "test": rows[va:]}

    cv = CountVectorizer(analyzer=lambda s: s.split(), binary=True, min_df=2)
    cv.fit([t for t, _ in parts["train"]])
    X = {k: cv.transform([t for t, _ in v]) for k, v in parts.items()}
    y = {k: np.array([l for _, l in v]) for k, v in parts.items()}

    clf = LogisticRegression(C=1.0, max_iter=800, solver="liblinear", class_weight="balanced").fit(X["train"], y["train"])
    vs = clf.decision_function(X["val"])
    benign = np.sort(vs[y["val"] == 0])
    thr_high = float(benign[min(int(0.99 * len(benign)), len(benign) - 1)])
    thr_elev = float(benign[min(int(0.95 * len(benign)), len(benign) - 1)])

    ts, ty = clf.decision_function(X["test"]), y["test"]

    def rate(thr):
        p = ts >= thr
        tp = int((p & (ty == 1)).sum())
        fp = int((p & (ty == 0)).sum())
        fn = int((~p & (ty == 1)).sum())
        tn = int((~p & (ty == 0)).sum())
        return {
            "threshold": thr,
            "recall": tp / max(tp + fn, 1),
            "false_positive_rate": fp / max(fp + tn, 1),
            "precision": tp / max(tp + fp, 1),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        }

    metrics = {
        "test_roc_auc": float(roc_auc_score(ty, ts)),
        "test_examples": int(len(ty)),
        "test_malicious": int(ty.sum()),
        "at_high_threshold": rate(thr_high),
        "at_elevated_threshold": rate(thr_elev),
    }
    inv = {i: t for t, i in cv.vocabulary_.items()}
    weights = {inv[int(i)]: round(float(clf.coef_[0][i]), 6) for i in np.nonzero(clf.coef_[0])[0]}
    model = {
        "name": "satark-pdf-v1",
        "kind": "binary-token-logistic-regression",
        "bias": round(float(clf.intercept_[0]), 6),
        "thresholds": {"elevated": round(thr_elev, 6), "high": round(thr_high, 6)},
        "weights": weights,
        "training": {
            "source": "CIC-Evasive-PDFMal2022 (UNB CIC; mirror arcofiero/PDF_Malware_Detection PDFMalware2022.csv)",
            "examples": n,
            "seed": SEED,
            "split": "random 80/10/10 after filename deduplication",
            "file_sha256": hashlib.sha256(open(a.data, "rb").read()).hexdigest(),
        },
        "metrics": metrics,
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(model, f, separators=(",", ":"), sort_keys=True)
    print(json.dumps(metrics, indent=1))
    print("features", len(weights))


if __name__ == "__main__":
    main()
