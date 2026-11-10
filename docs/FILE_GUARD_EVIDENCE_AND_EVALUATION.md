# SATARK File Guard — evidence reports and evaluation

## Evidence report contract

```json
{
  "report_schema": "satark.file-guard.evidence/v1",
  "scanned_at": "ISO-8601 UTC timestamp",
  "file": { "filename": "example.pdf", "size_bytes": 42, "sha256": "..." },
  "assessment": { "verdict": "No known threat detected", "risk_level": "low" },
  "evidence": { "signals": [], "intelligence_match": {}, "yara": {}, "agent_trace": [] },
  "processing": {
    "raw_bytes_processed_for_hash_and_signatures": true,
    "semantic_content_extracted": false,
    "ocr_performed": false,
    "file_executed": false,
    "network_used": false,
    "original_file_modified": false
  },
  "report_sha256": "..."
}
```

The report includes only metadata and bounded detection evidence. It never includes original file bytes or extracted text. The canonical report digest detects changes after export, but it is not a digital signature and does not prove collection identity, time, source or chain of custody.

## Measuring detection quality

The repository cannot honestly claim false-positive rate, recall or coverage from the EMBER hash metadata alone: the feature dataset is not a representative corpus of the original binaries. Use a separately labelled, legally obtained test corpus and record the tool version, dataset snapshot, file-type mix and expected labels.

Create a CSV with:

```csv
expected,predicted
malicious,malicious
benign,benign
malicious,unknown
```

Allowed labels are `benign`, `malicious`, and `unknown` for predictions. Unknown predictions are counted as abstentions and reduce coverage; they are not silently treated as benign.

Run:

```bash
python scripts/evaluate_file_guard.py evaluation.csv --output evaluation-report.json
```

The report includes confusion counts, precision, recall, specificity, F1, accuracy on classified samples, coverage and conservative recall/FNR that count abstained malicious samples as misses. Metrics apply only to the supplied labelled corpus.

## YARA policy

The current Android release does not include a native YARA runtime or a curated mobile rule pack. Do not label YARA as an enabled Android capability. The desktop Python engine may optionally use `yara-python` with a local rules file, but any rule pack must be reviewed for provenance, license, false positives, timeouts and file-type applicability before distribution. A native Android integration requires ABI-specific build, offline, memory, battery and regression tests; it is not safe to assume that desktop `yara-python` runs under Chaquopy.

## Supabase-free runtime

The Android application has no network permission and uses app-private SQLite. The web workspace is not required for file scanning. The CI guard rejects Supabase SDK/API/runtime references in application source, and the unused Supabase CLI project configuration has been removed. Historical `supabase/migrations` and `supabase/tests` files remain as an archive for the retired web/FIRSTLIGHT persistence path; they are not loaded or used by Android File Guard. Removing that archive completely would require a separate decommission of the legacy database workflows and their tests.
