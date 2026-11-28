#!/usr/bin/env python3
"""Train SATARK's image forensics / synthetic-image advisory model (pixel & ELA tokens -> L2 logistic regression).

Data: Open-source Hemg/AI-vs-Real-images via HuggingFace Datasets Server API (sampled balanced subset).
Features are computed on a 128x128 RGB grid so the browser's HTML5 Canvas in /image-review can extract
the exact same bucketed forensic tokens locally with zero network calls.
"""
from __future__ import annotations
import argparse, csv, hashlib, io, json, random
from pathlib import Path


SEED = 20261127
DATASET_URL = "https://datasets-server.huggingface.co/rows"


def _bucket(val: float, edges: list[float]) -> int:
    for i, e in enumerate(edges):
        if val <= e:
            return i
    return len(edges)


def extract_image_tokens(
    width: int,
    height: int,
    ela_mean: float,
    ela_std: float,
    ela_high_ratio: float,
    lap_mean: float,
    lap_std: float,
    flat_ratio: float,
    sat_mean: float,
) -> set[str]:
    toks: set[str] = set()
    toks.add(f"@ela_m{_bucket(ela_mean, [2.0, 4.5, 8.0, 14.0])}")
    toks.add(f"@ela_s{_bucket(ela_std, [2.5, 5.0, 9.0, 15.0])}")
    toks.add(f"@ela_h{_bucket(ela_high_ratio, [0.01, 0.05, 0.15, 0.35])}")
    toks.add(f"@lap_m{_bucket(lap_mean, [6.0, 14.0, 26.0, 45.0])}")
    toks.add(f"@lap_s{_bucket(lap_std, [8.0, 18.0, 32.0, 55.0])}")
    toks.add(f"@flat{_bucket(flat_ratio, [0.05, 0.18, 0.40, 0.70])}")
    toks.add(f"@sat{_bucket(sat_mean, [0.15, 0.30, 0.50, 0.72])}")
    if width == height:
        toks.add("@square")
    if width in (512, 768, 1024, 1536, 2048) or height in (512, 768, 1024, 1536, 2048):
        toks.add("@pow2_dim")
    if max(width, height) >= 1600:
        toks.add("@high_res")
    elif max(width, height) <= 600:
        toks.add("@low_res")
    return toks


def compute_features_from_pil(img) -> dict[str, float]:
    import numpy as np
    from PIL import Image

    w, h = img.size
    rgb = img.convert("RGB").resize((128, 128), Image.Resampling.BILINEAR)
    arr = np.asarray(rgb, dtype=np.float32)

    # Error Level Analysis (JPEG q=90 re-compression residual)
    buf = io.BytesIO()
    rgb.save(buf, format="JPEG", quality=90)
    buf.seek(0)
    recomp = np.asarray(Image.open(buf).convert("RGB"), dtype=np.float32)
    diff = np.abs(arr - recomp)
    ela_mean = float(diff.mean())
    ela_std = float(diff.std())
    ela_high_ratio = float((diff.mean(axis=2) > 12.0).mean())

    # Luminance Laplacian high-frequency residual
    lum = 0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]
    center = lum[1:-1, 1:-1]
    lap = np.abs(
        4.0 * center
        - lum[:-2, 1:-1]
        - lum[2:, 1:-1]
        - lum[1:-1, :-2]
        - lum[1:-1, 2:]
    )
    lap_mean = float(lap.mean())
    lap_std = float(lap.std())

    # Flatness (adjacent pixel difference < 2.0)
    dx = np.abs(lum[:, 1:] - lum[:, :-1])
    flat_ratio = float((dx < 2.0).mean())

    # Saturation mean (HSV-like chroma / max)
    cmax = arr.max(axis=2)
    cmin = arr.min(axis=2)
    sat = np.where(cmax > 0, (cmax - cmin) / np.maximum(cmax, 1.0), 0.0)
    sat_mean = float(sat.mean())

    return {
        "width": float(w),
        "height": float(h),
        "ela_mean": ela_mean,
        "ela_std": ela_std,
        "ela_high_ratio": ela_high_ratio,
        "lap_mean": lap_mean,
        "lap_std": lap_std,
        "flat_ratio": flat_ratio,
        "sat_mean": sat_mean,
    }


def fetch_hf_subset(cache_csv: Path, target_per_class: int = 200) -> list[tuple[dict[str, float], int]]:
    import requests
    from PIL import Image

    if cache_csv.exists():
        rows = []
        with open(cache_csv, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                label = int(r["label"])
                feats = {k: float(v) for k, v in r.items() if k != "label"}
                rows.append((feats, label))
        c0 = sum(1 for _, l in rows if l == 0)
        c1 = sum(1 for _, l in rows if l == 1)
        if c0 >= target_per_class and c1 >= target_per_class:
            return rows
    else:
        rows = []

    counts = {0: sum(1 for _, l in rows if l == 0), 1: sum(1 for _, l in rows if l == 1)}
    for target_label, base_off in ((0, 0), (1, 100000)):
        if counts[target_label] >= target_per_class:
            continue
        for off in range(base_off, base_off + 2000, 50):
            if counts[target_label] >= target_per_class:
                break
            try:
                resp = requests.get(
                    DATASET_URL,
                    params={
                        "dataset": "Hemg/AI-vs-Real-images",
                        "config": "default",
                        "split": "train",
                        "offset": off,
                        "length": 50,
                    },
                    timeout=20,
                )
                if resp.status_code != 200:
                    continue
                for item in resp.json().get("rows", []):
                    row = item.get("row", {})
                    label = row.get("label")
                    if label != target_label or counts[target_label] >= target_per_class:
                        continue
                    src = (row.get("image") or {}).get("src")
                    if not src:
                        continue
                    img_resp = requests.get(src, timeout=15)
                    if img_resp.status_code != 200:
                        continue
                    img = Image.open(io.BytesIO(img_resp.content))
                    feats = compute_features_from_pil(img)
                    rows.append((feats, int(label)))
                    counts[target_label] += 1
                    if counts[target_label] >= target_per_class:
                        break
            except Exception:
                continue

    cache_csv.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        fieldnames = list(rows[0][0].keys()) + ["label"]
        with open(cache_csv, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for feats, label in rows:
                w.writerow({**feats, "label": label})
    return rows


def main():
    import numpy as np
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score

    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default="ml/.datasets/image_forensics_hf.csv")
    ap.add_argument("--per-class", type=int, default=180)
    ap.add_argument("--out", default="ml/models/image-v1.json")
    a = ap.parse_args()

    raw_rows = fetch_hf_subset(Path(a.cache), target_per_class=a.per_class)
    if len(raw_rows) < 100:
        raise SystemExit(f"Insufficient image rows collected: {len(raw_rows)}")

    rows = []
    for feats, label in raw_rows:
        toks = sorted(
            extract_image_tokens(
                width=int(feats["width"]),
                height=int(feats["height"]),
                ela_mean=feats["ela_mean"],
                ela_std=feats["ela_std"],
                ela_high_ratio=feats["ela_high_ratio"],
                lap_mean=feats["lap_mean"],
                lap_std=feats["lap_std"],
                flat_ratio=feats["flat_ratio"],
                sat_mean=feats["sat_mean"],
            )
        )
        rows.append((" ".join(toks), label))

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
    real_scores = np.sort(vs[y["val"] == 0])
    thr_high = float(real_scores[min(int(0.95 * len(real_scores)), len(real_scores) - 1)])
    thr_elev = float(real_scores[min(int(0.85 * len(real_scores)), len(real_scores) - 1)])

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
        "test_ai_or_synthetic": int(ty.sum()),
        "at_high_threshold": rate(thr_high),
        "at_elevated_threshold": rate(thr_elev),
    }
    inv = {i: t for t, i in cv.vocabulary_.items()}
    weights = {inv[int(i)]: round(float(clf.coef_[0][i]), 6) for i in np.nonzero(clf.coef_[0])[0]}
    model = {
        "name": "satark-image-v1",
        "kind": "binary-token-logistic-regression",
        "bias": round(float(clf.intercept_[0]), 6),
        "thresholds": {"elevated": round(thr_elev, 6), "high": round(thr_high, 6)},
        "weights": weights,
        "training": {
            "source": "Hemg/AI-vs-Real-images (HuggingFace open-source subset, ELA + Laplacian + flatness + dimensions)",
            "examples": n,
            "seed": SEED,
            "split": "random 80/10/10",
            "file_sha256": hashlib.sha256(Path(a.cache).read_bytes()).hexdigest(),
        },
        "metrics": metrics,
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(model, f, separators=(",", ":"), sort_keys=True)
    print(json.dumps(metrics, indent=1))
    print("features", len(weights))


if __name__ == "__main__":
    main()
