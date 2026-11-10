# Detection evaluation methodology

SATARK includes a repeatable evaluator for an independently labelled local file corpus. This is how the project should measure false positives, false negatives and detection coverage instead of relying on anecdotes or a few hand-crafted examples.

## Ground-truth CSV

Create a CSV with two columns:

```csv
path,label
benign/report.pdf,benign
malicious/sample.apk,malicious
```

Paths must be relative to the sample root. Symlinks and paths outside that root are rejected. Use legally acquired samples and a documented source/license. Keep the test set separate from the training hash snapshot.

## Run

```bash
python scripts/evaluate_file_guard.py \
  --samples /path/to/labelled-files \
  --labels /path/to/ground-truth.csv \
  --database /tmp/satark-eval.sqlite3 \
  --intelligence-csv /path/to/training-hashes.csv \
  --source-id EMBER2024-training-snapshot \
  --yara-rules rules/local_file_signatures.yar \
  --output-json /tmp/satark-evaluation.json \
  --output-csv /tmp/satark-evaluation.csv
```

Omit `--intelligence-csv` or `--yara-rules` to measure only the other enabled checks. The evaluator performs no network calls, content extraction, unpacking or execution. It writes per-file SHA-256, verdict, detected type, signal codes and YARA rule names.

## Metrics

The JSON report includes:
- True/false positives and true/false negatives.
- Precision, recall, specificity, false-positive rate, false-negative rate and accuracy.
- Metrics grouped by detected file type.
- Files that could not be scanned, reported separately rather than silently counted as benign.

An alert verdict means triage/review is required; it is not proof of malware. A no-alert verdict is not proof of safety.

## Dataset limitations

EMBER2024 supplies hashes, features and labels for six file types, but not the original malware binaries in its metadata archives. Its test split can evaluate research models trained on the feature vectors, but it cannot by itself provide real file bytes for validating SATARK's YARA rules or byte-signature scanner. To measure the file scanner honestly, obtain an independently labelled, legally usable binary corpus under the appropriate access controls.

The YARA CI corpus is synthetic and deliberately small. Its precision/recall/FPR values are regression checks only and must not be represented as production detection metrics. For credible estimates, use a large representative benign set, malicious set, time-separated holdout, family-aware deduplication, per-format reporting and human review of false positives.

## Recommended release report

Record corpus provenance/license, sample counts, file-type mix, time period, train/test split, scanner version, ruleset SHA-256, imported intelligence snapshot SHA-256, per-class metrics, unscanned files, and a reviewed false-positive table. Never publish malware binaries or sensitive samples without authorization.
