#!/usr/bin/env python3
"""Convert locally downloaded EMBER2024 JSONL metadata into File Guard CSV snapshots.

This script performs no downloads and never opens malware binaries. It reads only
the metadata JSONL files produced by the official thrember dataset downloader.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Iterator

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
UPSTREAM_REVISION = "8cc201a3d2a1cb2957123eb5ad996d5a3178bbcc"
FILE_TYPES = {"Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF"}

def normalize_label(value):
    if value in (0, "0", "benign", "BENIGN"):
        return "benign"
    if value in (1, "1", "malicious", "malware", "MALICIOUS"):
        return "malicious"
    if value in (-1, "-1", None, ""):
        return None
    return "invalid"

def normalize_date(record):
    value = record.get("first_submission_date") or record.get("dataset_date") or record.get("date")
    if value in (None, ""):
        value = record.get("last_analysis_date")
    if value in (None, ""):
        return ""
    try:
        timestamp = int(value)
        if timestamp > 0:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).date().isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        pass
    return str(value)[:40]

def select_files(input_dir: Path, split: str, file_type: str) -> list[Path]:
    paths = sorted(input_dir.glob("*.jsonl"))
    if split != "all":
        paths = [path for path in paths if split.lower() in path.name.lower()]
    if file_type == "PE":
        tokens = ("win32", "win64", "dot_net", "dotnet")
        paths = [path for path in paths if any(token in path.name.lower() for token in tokens)]
    elif file_type != "all":
        paths = [path for path in paths if file_type.lower() in path.name.lower()]
    return paths

def iter_rows(paths: list[Path], counters: dict) -> Iterator[dict]:
    for path in paths:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                counters["rows_seen"] += 1
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    counters["invalid_rows"] += 1
                    continue
                digest = str(record.get("sha256", "")).lower()
                if not SHA256_RE.fullmatch(digest):
                    counters["invalid_rows"] += 1
                    continue
                label = normalize_label(record.get("label"))
                if label is None:
                    counters["unlabeled_rows"] += 1
                    continue
                if label == "invalid":
                    counters["invalid_rows"] += 1
                    continue
                file_type = str(record.get("file_type") or record.get("filetype") or "").strip()
                if not file_type:
                    file_type = next((kind for kind in FILE_TYPES if kind.lower() in path.name.lower()), "unknown")
                counters["exported_rows"] += 1
                yield {
                    "sha256": digest,
                    "label": label,
                    "family": str(record.get("family") or "")[:120],
                    "dataset_date": normalize_date(record),
                    "file_type": file_type[:40],
                }

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def convert(input_dir: Path, output_dir: Path, *, split="all", file_type="all",
            rows_per_part=25_000, max_records=None):
    if not input_dir.is_dir():
        raise ValueError("Input directory does not exist.")
    if rows_per_part < 1:
        raise ValueError("rows_per_part must be positive.")
    paths = select_files(input_dir, split, file_type)
    if not paths:
        raise ValueError("No JSONL files matched the selected split/file type.")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_split = re.sub(r"[^a-z0-9_-]+", "-", split.lower())
    safe_type = re.sub(r"[^a-z0-9_-]+", "-", file_type.lower())
    for stale in output_dir.glob(f"ember2024_{safe_split}_{safe_type}_*.csv"):
        stale.unlink()
    stale_manifest = output_dir / f"ember2024_{safe_split}_{safe_type}_manifest.json"
    if stale_manifest.exists():
        stale_manifest.unlink()
    counters = {"rows_seen": 0, "exported_rows": 0, "unlabeled_rows": 0, "invalid_rows": 0}
    parts = []
    writer = None
    stream = None
    part_rows = 0
    part_number = 0

    def close_part():
        nonlocal stream, writer, part_rows
        if stream is not None:
            stream.close()
            parts[-1]["sha256"] = sha256_file(output_dir / parts[-1]["file"])
            parts[-1]["rows"] = part_rows
            stream = None
            writer = None
            part_rows = 0

    try:
        for row in iter_rows(paths, counters):
            if max_records is not None and counters["exported_rows"] > max_records:
                counters["exported_rows"] -= 1
                break
            if writer is None:
                part_number += 1
                filename = f"ember2024_{safe_split}_{safe_type}_{part_number:04d}.csv"
                stream = (output_dir / filename).open("w", newline="", encoding="utf-8")
                writer = csv.DictWriter(stream, fieldnames=[
                    "sha256", "label", "family", "dataset_date", "file_type"
                ])
                writer.writeheader()
                parts.append({"file": filename})
            writer.writerow(row)
            part_rows += 1
            if part_rows >= rows_per_part:
                close_part()
        close_part()
    finally:
        if stream is not None:
            stream.close()

    manifest = {
        "dataset": "EMBER2024",
        "upstream": "https://github.com/FutureComputing4AI/EMBER2024",
        "dataset_mirror": "https://huggingface.co/datasets/joyce8/EMBER2024",
        "upstream_revision": UPSTREAM_REVISION,
        "dataset_repository_license": "Apache-2.0",
        "collection_window": "2023-09-24 through 2024-12-14",
        "input_split": split,
        "input_file_type": file_type,
        "source_files": [path.name for path in paths],
        "rows": counters,
        "parts": parts,
        "label_mapping": {"0": "benign", "1": "malicious", "-1": "excluded as unlabeled"},
        "notes": [
            "Metadata/hash conversion only; no malware binaries are read or copied.",
            "No network access is performed by this script.",
            "Repeated hashes are left for the SQLite importer to deduplicate; conflicting labels fail closed.",
            "The output is historical exact-hash intelligence, not a detector for unseen or modified malware.",
        ],
    }
    manifest_path = output_dir / f"ember2024_{safe_split}_{safe_type}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True,
                        help="Directory containing locally downloaded EMBER2024 JSONL metadata files")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--split", choices=["all", "train", "test", "challenge"], default="train")
    parser.add_argument("--file-type", choices=["all", "PE", "Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF"], default="all")
    parser.add_argument("--rows-per-part", type=int, default=25_000,
                        help="Keep each CSV small enough for mobile import (default: 25,000)")
    parser.add_argument("--max-records", type=int, default=None,
                        help="Optional cap for a small pilot snapshot; omitted means all matching labelled rows")
    args = parser.parse_args()
    manifest = convert(args.input_dir, args.output_dir, split=args.split,
                       file_type=args.file_type, rows_per_part=args.rows_per_part,
                       max_records=args.max_records)
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
