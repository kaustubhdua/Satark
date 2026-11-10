#!/usr/bin/env python3
"""Build a compact, metadata-only SQLite starter database from verified EMBER2024 CSV parts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3

from file_guard.intelligence import ThreatIntelligenceStore
from scripts.import_ember2024 import UPSTREAM_REVISION, sha256_file, verify_source_manifest


def build(input_dir: Path, csv_dir: Path, output_db: Path, *, split="train", file_type="APK") -> dict:
    if not input_dir.is_dir() or not csv_dir.is_dir():
        raise ValueError("Input JSONL and converted CSV directories must exist.")
    converter_manifest_path = csv_dir / f"ember2024_{split.lower()}_{file_type.lower()}_manifest.json"
    if converter_manifest_path.is_symlink() or not converter_manifest_path.is_file():
        raise ValueError("Converted EMBER2024 manifest is missing.")
    converter_manifest = json.loads(converter_manifest_path.read_text(encoding="utf-8"))
    if (converter_manifest.get("dataset") != "EMBER2024" or
        converter_manifest.get("upstream_revision") != UPSTREAM_REVISION or
        converter_manifest.get("input_split") != split or
        str(converter_manifest.get("input_file_type", "")).lower() != file_type.lower()):
        raise ValueError("Converted manifest does not match the pinned EMBER2024 request.")

    source_manifest = verify_source_manifest(input_dir, split, file_type)
    if not source_manifest or source_manifest != converter_manifest.get("source_manifest"):
        raise ValueError("Converted manifest is not bound to a verified upstream archive manifest.")
    source_doc_path = input_dir / source_manifest["file"]
    if sha256_file(source_doc_path) != source_manifest["sha256"]:
        raise ValueError("Upstream download manifest digest mismatch.")

    parts = converter_manifest.get("parts")
    if not isinstance(parts, list) or not parts:
        raise ValueError("Converted manifest contains no CSV parts.")
    declared_rows = int(converter_manifest.get("rows", {}).get("exported_rows", 0))
    if declared_rows <= 0 or sum(int(item.get("rows", 0)) for item in parts) != declared_rows:
        raise ValueError("Converted manifest total row count does not match its CSV parts.")
    output_db.parent.mkdir(parents=True, exist_ok=True)
    output_db.unlink(missing_ok=True)
    metadata_path = output_db.with_suffix(".json")
    metadata_path.unlink(missing_ok=True)

    source_id = f"EMBER2024-2024-12-14-{split}-{file_type}"
    store = ThreatIntelligenceStore(output_db)
    imported_rows = skipped_rows = rejected_rows = 0
    part_records = []
    try:
        for item in parts:
            filename = str(item.get("file", ""))
            expected = str(item.get("sha256", "")).lower()
            expected_rows = int(item.get("rows", 0))
            if not filename or Path(filename).name != filename or len(expected) != 64 or expected_rows <= 0:
                raise ValueError("Converted manifest contains an invalid CSV part record.")
            csv_path = csv_dir / filename
            if csv_path.is_symlink() or not csv_path.is_file() or sha256_file(csv_path) != expected:
                raise ValueError(f"CSV part checksum mismatch: {filename}")
            with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
                outcome = store.import_csv(stream, f"{source_id}:{filename}", max_rows=2_000_000)
            accepted = outcome["inserted"] + outcome["skipped"]
            if outcome["rejected"] or accepted != expected_rows:
                raise ValueError(f"CSV part row-count or label validation failed: {filename}")
            imported_rows += outcome["inserted"]
            skipped_rows += outcome["skipped"]
            rejected_rows += outcome["rejected"]
            part_records.append({
                "file": filename,
                "sha256": expected,
                "rows": expected_rows,
                "inserted": outcome["inserted"],
                "skipped": outcome["skipped"],
            })

        stats = store.stats()
        if stats["total"] == 0 or stats["total"] != imported_rows:
            raise ValueError("Built starter database has inconsistent indicator counts.")
        with sqlite3.connect(output_db) as db:
            db.execute("PRAGMA journal_mode=DELETE")
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise ValueError("Generated SQLite starter database failed integrity_check.")
            db.execute("VACUUM")

        metadata = {
            "dataset": "EMBER2024",
            "dataset_revision": UPSTREAM_REVISION,
            "collection_window": "2023-09-24 through 2024-12-14",
            "license": "Apache-2.0",
            "source_id": source_id,
            "split": split,
            "file_type": file_type,
            "source_manifest": source_manifest,
            "source_manifest_sha256": source_manifest["sha256"],
            "converter_manifest": converter_manifest_path.name,
            "converter_manifest_sha256": sha256_file(converter_manifest_path),
            "parts": part_records,
            "rows": {
                "unique_hashes": stats["total"],
                "malicious": stats["malicious"],
                "benign": stats["benign"],
                "inserted": imported_rows,
                "duplicate_same_label": skipped_rows,
                "rejected": rejected_rows,
            },
            "database_bytes": output_db.stat().st_size,
            "database_sha256": sha256_file(output_db),
            "contains_file_binaries": False,
            "contains_only_sha256_labels_and_metadata": True,
            "runtime_network_required": False,
        }
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        return metadata
    except Exception:
        output_db.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--csv-dir", type=Path, required=True)
    parser.add_argument("--output-db", type=Path, required=True)
    parser.add_argument("--split", choices=["train", "test", "all"], default="train")
    parser.add_argument("--file-type", choices=["all", "PE", "Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF"], default="APK")
    args = parser.parse_args()
    print(json.dumps(build(args.input_dir, args.csv_dir, args.output_db,
                           split=args.split, file_type=args.file_type), indent=2))


if __name__ == "__main__":
    main()
