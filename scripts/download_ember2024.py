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

# Immutable Hugging Face dataset revision. Never follow the mutable "main" branch.
DATASET_REVISION = "8cc201a3d2a1cb2957123eb5ad996d5a3178bbcc"
DATASET_BASE = f"https://huggingface.co/datasets/joyce8/EMBER2024/resolve/{DATASET_REVISION}/"
DATASET_LICENSE = "Apache-2.0"
FILE_TYPES = ("Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF")

# Git LFS object SHA-256 and byte size recorded in the verified upstream commit.
ARCHIVE_INTEGRITY = {
    "APK_test.zip": ("058d255e80f8390ce2b87c43a918f2ca9fdd2a114cc2162df54b9d002af1998d", 81122668),
    "APK_train.zip": ("95f222aae5c2f68216952e12f837367bdb4e7fc206e4ddd9319d45b14e031960", 357950829),
    "Dot_Net_test.zip": ("bc31b48cc9f4317e56620fed2f1084384292a8b50603066a88ab532cbf9f19ff", 85518369),
    "Dot_Net_train.zip": ("ed9d17040135da955bd5667075eb4b499a5ab97e74d7e763dd11d6879b6d8fcf", 368639403),
    "ELF_test.zip": ("f7449414e4993df34604b4efb64ae92c6844daafd607cb5002fb98e612bed002", 7350991),
    "ELF_train.zip": ("3385e7c5089f04c46d42ecac8361c6d5141d4b76ba8343c06282430b21e2b06f", 30514963),
    "PDF_test.zip": ("8667c85dfff1986a858839ffe3dc41b4cf0e9651c29302e00fdeab9c9cf655d0", 13225216),
    "PDF_train.zip": ("14decb6bb1a7bd037cad92082205ecbda5514a3295786974d330a91ca869b60e", 56115817),
    "Win32_test.zip": ("3ff3b81c0a2427e68ad5349fa8e3a6151fa99a2c7404a62774301211d6a724a8", 1100969426),
    "Win32_train.zip": ("9be451a9cf77ace2d3c6afd332d77da884fb17fc66e5cf6db36254051d1e75c5", 5252835952),
    "Win64_test.zip": ("ba5e5df3a01f232fefeec3aca156781b07a9fabcc6d5627ce75cf9fa61e0f9e4", 516091625),
    "Win64_train.zip": ("0cccc711b77bbe6c676fbc23f1b11f5bd970136362d4914333b4e6c0da29c8dd", 2592795813),
}

def archive_url(filename: str) -> str:
    return DATASET_BASE + filename

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def download_archive(filename: str, archive_dir: Path, max_download_bytes: int) -> Path:
    expected = ARCHIVE_INTEGRITY.get(filename)
    if expected is None:
        raise ValueError("Archive is not part of the pinned EMBER2024 snapshot.")
    expected_sha256, expected_size = expected
    if expected_size > max_download_bytes:
        raise ValueError("Pinned archive exceeds configured download limit.")
    archive_dir.mkdir(parents=True, exist_ok=True)
    target = archive_dir / filename
    if target.exists():
        if target.is_file() and not target.is_symlink() and target.stat().st_size == expected_size:
            if sha256_file(target) == expected_sha256 and zipfile.is_zipfile(target):
                return target
        target.unlink(missing_ok=True)

    request = Request(archive_url(filename), headers={"User-Agent": "SATARK-FileGuard-Dataset-Importer/1.0"})
    temp_path = None
    digest = hashlib.sha256()
    total = 0
    try:
        with urlopen(request, timeout=90) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) != expected_size:
                raise ValueError("Archive Content-Length differs from the pinned upstream size.")
            with tempfile.NamedTemporaryFile(dir=archive_dir, suffix=".download", delete=False) as tmp:
                temp_path = Path(tmp.name)
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > min(max_download_bytes, expected_size):
                        raise ValueError("Archive exceeded its pinned size while streaming.")
                    digest.update(chunk)
                    tmp.write(chunk)
        if total != expected_size or digest.hexdigest() != expected_sha256:
            raise ValueError("Downloaded archive does not match the pinned EMBER2024 SHA-256 and size.")
        if temp_path is None or not zipfile.is_zipfile(temp_path):
            raise ValueError("Downloaded payload is not a valid ZIP archive.")
        temp_path.replace(target)
        return target
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise

def safe_extract_zip(archive: Path, destination: Path, max_extracted_bytes: int = 20 * 1024**3,
                     max_files: int = 1_000_000) -> list[str]:
    if destination.is_symlink():
        raise ValueError("Extraction destination cannot be a symlink.")
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
            if name.is_absolute() or ".." in name.parts or not name.parts or "\\" in info.filename or ":" in name.parts[0]:
                raise ValueError("ZIP contains an unsafe path.")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("ZIP symlinks are not accepted.")
            candidate = root / Path(*name.parts)
            cursor = candidate
            while cursor != root:
                if cursor.is_symlink():
                    raise ValueError("ZIP entry would overwrite a symlink.")
                cursor = cursor.parent
            target = candidate.resolve()
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
    if split == "challenge":
        raise ValueError("The challenge archive's upstream LFS digest could not be independently verified; import it only after separate verification.")
    splits = ["train", "test"] if split == "all" else [split]
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
        "dataset_mirror": "https://huggingface.co/datasets/joyce8/EMBER2024",
        "dataset_revision": DATASET_REVISION,
        "dataset_license": DATASET_LICENSE,
        "collection_window": "2023-09-24 through 2024-12-14",
        "download_source": DATASET_BASE,
        "split": split,
        "file_type": file_type,
        "archives": [],
        "extracted_jsonl_files": [],
        "network_used": True,
        "api_key_required": False,
    }
    total_uncompressed = 0
    for filename in selected_archives(split, file_type):
        archive = download_archive(filename, archive_dir, max_download_bytes)
        with zipfile.ZipFile(archive, "r") as bundle:
            declared_uncompressed = sum(item.file_size for item in bundle.infolist())
        total_uncompressed += declared_uncompressed
        if total_uncompressed > max_extracted_bytes:
            raise ValueError("Selected dataset archives exceed the total extracted-size limit.")
        files = safe_extract_zip(archive, output_dir, max_extracted_bytes - (total_uncompressed - declared_uncompressed))
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
    parser.add_argument("--split", choices=["train", "test", "all"], default="train")
    parser.add_argument("--file-type", choices=["all", "PE", *FILE_TYPES], default="APK")
    parser.add_argument("--max-download-gb", type=float, default=20)
    parser.add_argument("--max-extracted-gb", type=float, default=20)
    args = parser.parse_args()
    if args.max_download_gb <= 0 or args.max_extracted_gb <= 0:
        parser.error("download and extracted size limits must be positive")
    manifest = download_and_extract(
        args.output_dir, args.split, args.file_type,
        int(args.max_download_gb * 1024**3), int(args.max_extracted_gb * 1024**3)
    )
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
