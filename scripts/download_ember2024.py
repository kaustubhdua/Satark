#!/usr/bin/env python3
"""Download and safely extract public EMBER2024 metadata archives (no API key).

This is an explicit one-time operator action. SATARK itself has no Internet
permission and never calls this downloader while scanning.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
from urllib.request import Request, urlopen
import zipfile

DATASET_BASE = "https://huggingface.co/datasets/joyce8/EMBER2024/resolve/main/"
FILE_TYPES = ("Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF")

def archive_url(filename: str) -> str:
    return DATASET_BASE + filename

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def download_archive(filename: str, archive_dir: Path, max_download_bytes: int) -> Path:
    archive_dir.mkdir(parents=True, exist_ok=True)
    target = archive_dir / filename
    if target.exists() and zipfile.is_zipfile(target):
        return target
    request = Request(archive_url(filename), headers={"User-Agent": "SATARK-FileGuard-Dataset-Importer/1.0"})
    with urlopen(request, timeout=90) as response:
        length = response.headers.get("Content-Length")
        if length and int(length) > max_download_bytes:
            raise ValueError("Archive exceeds configured download limit.")
        with tempfile.NamedTemporaryFile(dir=archive_dir, suffix=".download", delete=False) as tmp:
            temp_path = Path(tmp.name)
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_download_bytes:
                    raise ValueError("Archive exceeded configured download limit while streaming.")
                tmp.write(chunk)
    if not zipfile.is_zipfile(temp_path):
        temp_path.unlink(missing_ok=True)
        raise ValueError("Downloaded payload is not a valid ZIP archive.")
    temp_path.replace(target)
    return target

def safe_extract_zip(archive: Path, destination: Path, max_extracted_bytes: int = 20 * 1024**3,
                     max_files: int = 1_000_000) -> list[str]:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    extracted = []
    total_size = 0
    with zipfile.ZipFile(archive, "r") as bundle:
        entries = bundle.infolist()
        if len(entries) > max_files:
            raise ValueError("ZIP contains too many entries.")
        for info in entries:
            name = PurePosixPath(info.filename)
            if name.is_absolute() or ".." in name.parts or not name.parts:
                raise ValueError("ZIP contains an unsafe path.")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("ZIP symlinks are not accepted.")
            target = (root / Path(*name.parts)).resolve()
            if not target.is_relative_to(root):
                raise ValueError("ZIP entry escapes the extraction directory.")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total_size += info.file_size
            if total_size > max_extracted_bytes:
                raise ValueError("ZIP exceeds configured extracted-size limit.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            extracted.append(str(target.relative_to(root)))
    return extracted

def selected_archives(split: str, file_type: str) -> list[str]:
    splits = ["train", "test", "challenge"] if split == "all" else [split]
    types = list(FILE_TYPES) if file_type == "all" else (
        ["Win32", "Win64", "Dot_Net"] if file_type == "PE" else [file_type]
    )
    names = []
    for part in splits:
        if part == "challenge":
            names.append("challenge.zip")
        else:
            names.extend(f"{kind}_{part}.zip" for kind in types)
    return names

def download_and_extract(output_dir: Path, split="train", file_type="APK",
                         max_download_bytes=20 * 1024**3,
                         max_extracted_bytes=20 * 1024**3):
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_dir = output_dir / ".archives"
    manifest = {
        "dataset": "EMBER2024",
        "upstream": "https://github.com/FutureComputing4AI/EMBER2024",
        "download_source": DATASET_BASE,
        "split": split,
        "file_type": file_type,
        "archives": [],
        "extracted_jsonl_files": [],
        "network_used": True,
        "api_key_required": False,
    }
    for filename in selected_archives(split, file_type):
        archive = download_archive(filename, archive_dir, max_download_bytes)
        files = safe_extract_zip(archive, output_dir, max_extracted_bytes)
        manifest["archives"].append({
            "file": filename,
            "sha256": sha256_file(archive),
            "bytes": archive.stat().st_size,
        })
        manifest["extracted_jsonl_files"].extend(
            item for item in files if item.lower().endswith(".jsonl")
        )
    manifest_path = output_dir / f"ember2024_download_{split}_{file_type.lower()}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--split", choices=["train", "test", "challenge", "all"], default="train")
    parser.add_argument("--file-type", choices=["all", "PE", *FILE_TYPES], default="APK")
    parser.add_argument("--max-download-gb", type=float, default=20)
    parser.add_argument("--max-extracted-gb", type=float, default=20)
    args = parser.parse_args()
    manifest = download_and_extract(
        args.output_dir, args.split, args.file_type,
        int(args.max_download_gb * 1024**3), int(args.max_extracted_gb * 1024**3)
    )
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
