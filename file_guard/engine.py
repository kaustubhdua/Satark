"""Bounded static file inspection. No text extraction, rendering, unpacking or execution."""
from dataclasses import asdict, dataclass, field
import hashlib
import os
from pathlib import Path
import stat

from .agents import route_file, inspect_filename, inspect_hash, inspect_yara, fuse_evidence

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_FILES = 5000
MAX_DIRECTORY_BYTES = 1024 * 1024 * 1024
MAX_DIRECTORY_DEPTH = 8
MAGIC = [
    (b"%PDF-", "PDF", {".pdf"}),
    (b"MZ", "Windows executable", {".exe", ".dll", ".scr", ".com"}),
    (b"\x7fELF", "ELF executable", {".elf", ".so", ".bin"}),
    (b"PK\x03\x04", "ZIP container", {".zip", ".apk", ".docx", ".xlsx", ".pptx", ".jar"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"GIF87a", "GIF image", {".gif"}),
    (b"GIF89a", "GIF image", {".gif"}),
    (b"Rar!\x1a\x07", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE document", {".doc", ".xls", ".ppt", ".msg"}),
    (b"dex\n", "Android DEX", {".dex"}),
    (b"BM", "BMP image", {".bmp"}),
    (b"II*\x00", "TIFF image", {".tif", ".tiff"}),
    (b"MM\x00*", "TIFF image", {".tif", ".tiff"}),
    (b"fLaC", "FLAC audio", {".flac"}),
    (b"OggS", "OGG container", {".ogg", ".oga", ".ogv"}),
    (b"\x1f\x8b", "GZIP archive", {".gz", ".tgz"}),
    (b"BZh", "BZIP2 archive", {".bz2"}),
    (b"\xfd7zXZ\x00", "XZ archive", {".xz"}),
    (b"\x28\xb5\x2f\xfd", "Zstandard archive", {".zst"}),
    (b"SQLite format 3\x00", "SQLite database", {".sqlite", ".sqlite3", ".db"}),
    (b"ID3", "MP3 audio", {".mp3"}),
    (b"MSCF", "Microsoft cabinet archive", {".cab"}),
]

@dataclass
class FileScanResult:
    filename: str
    size_bytes: int
    sha256: str
    detected_type: str
    extension: str
    verdict: str
    risk_level: str
    score: int
    signals: list = field(default_factory=list)
    intelligence_match: dict | None = None
    yara_available: bool = False
    yara_matches: list = field(default_factory=list)
    yara_error: str | None = None
    agent_trace: list = field(default_factory=list)
    content_extracted: bool = False
    executed: bool = False
    def to_dict(self):
        return asdict(self)

def _type(header):
    # RIFF-based formats share a container signature; inspect only the fixed
    # four-byte form identifier, never parse or extract the payload.
    if header.startswith(b"RIFF") and len(header) >= 12:
        form = header[8:12]
        if form == b"WEBP":
            return "WebP image", {".webp"}
        if form == b"WAVE":
            return "WAV audio", {".wav"}
        if form == b"AVI ":
            return "AVI video", {".avi"}
    # ISO base media files (including MP4) carry the ftyp box at byte offset 4.
    if len(header) >= 8 and header[4:8] == b"ftyp":
        return "ISO base media / MP4", {".mp4", ".m4v", ".mov"}
    # RAR 5.0 has a longer signature than the legacy RAR 4.x marker.
    if header.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "RAR archive", {".rar"}
    for signature, label, extensions in MAGIC:
        if header.startswith(signature):
            return label, extensions
    return ("Empty file" if not header else "Unknown / unrecognized"), set()

def scan_bytes(data, filename, *, intelligence=None, yara_rules_path=None, max_bytes=MAX_FILE_BYTES):
    if not isinstance(data, bytes):
        raise TypeError("File data must be bytes.")
    if len(data) > max_bytes:
        raise ValueError("File exceeds the configured scan size limit.")
    name = Path(filename or "unnamed").name[:255]
    ext = Path(name).suffix.lower()
    digest = hashlib.sha256(data).hexdigest()
    detected, allowed_exts = _type(data[:4096])
    signals = []
    if detected == "Unknown / unrecognized":
        signals.append({"code":"UNKNOWN_SIGNATURE","severity":"low","detail":"No supported file signature recognized."})
    if allowed_exts and ext not in allowed_exts:
        signals.append({"code":"EXTENSION_SIGNATURE_MISMATCH","severity":"high","detail":f"{ext or '(none)'} extension conflicts with {detected} signature."})

    router = route_file(name, detected, yara_configured=bool(yara_rules_path))
    metadata = inspect_filename(name)
    hash_report = inspect_hash(digest, intelligence)
    yara_report = inspect_yara(data, yara_rules_path)
    signals.extend(metadata["signals"])
    signals.extend(hash_report["signals"])
    signals.extend(yara_report["signals"])
    fusion = fuse_evidence(signals, hash_report["match"], yara_report["matches"])

    trace = [
        router,
        {"agent":"magic_signature","status":"complete","detected_type":detected,
         "extension_compatible": (not allowed_exts or ext in allowed_exts)},
        metadata,
        hash_report,
        yara_report,
        fusion,
    ]
    return FileScanResult(
        name, len(data), digest, detected, ext, fusion["verdict"], fusion["risk_level"],
        fusion["score"], signals, hash_report["match"], yara_report["available"],
        yara_report["matches"], yara_report["error"], trace
    )

def scan_stream(stream, filename, *, intelligence=None, yara_rules_path=None, max_bytes=MAX_FILE_BYTES):
    """Hash and identify a stream incrementally; buffer full bytes only for optional YARA."""
    digest = hashlib.sha256()
    header = bytearray()
    yara_data = bytearray() if yara_rules_path else None
    total = 0
    while True:
        chunk = stream.read(min(1024 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("File exceeds the configured scan size limit.")
        digest.update(chunk)
        if len(header) < 4096:
            header.extend(chunk[:4096 - len(header)])
        if yara_data is not None:
            yara_data.extend(chunk)

    name = Path(filename or "unnamed").name[:255]
    ext = Path(name).suffix.lower()
    sha256 = digest.hexdigest()
    detected, allowed_exts = _type(bytes(header))
    signals = []
    if detected == "Unknown / unrecognized":
        signals.append({"code": "UNKNOWN_SIGNATURE", "severity": "low",
                        "detail": "No supported file signature recognized."})
    if allowed_exts and ext not in allowed_exts:
        signals.append({"code": "EXTENSION_SIGNATURE_MISMATCH", "severity": "high",
                        "detail": f"{ext or '(none)'} extension conflicts with {detected} signature."})

    router = route_file(name, detected, yara_configured=bool(yara_rules_path))
    metadata = inspect_filename(name)
    hash_report = inspect_hash(sha256, intelligence)
    yara_report = inspect_yara(bytes(yara_data) if yara_data is not None else b"", yara_rules_path)
    signals.extend(metadata["signals"])
    signals.extend(hash_report["signals"])
    signals.extend(yara_report["signals"])
    fusion = fuse_evidence(signals, hash_report["match"], yara_report["matches"])
    trace = [
        router,
        {"agent": "magic_signature", "status": "complete", "detected_type": detected,
         "extension_compatible": (not allowed_exts or ext in allowed_exts)},
        metadata,
        hash_report,
        yara_report,
        fusion,
    ]
    return FileScanResult(
        name, total, sha256, detected, ext, fusion["verdict"], fusion["risk_level"],
        fusion["score"], signals, hash_report["match"], yara_report["available"],
        yara_report["matches"], yara_report["error"], trace
    )

def scan_path(path, *, filename=None, intelligence=None, yara_rules_path=None, max_bytes=MAX_FILE_BYTES):
    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(target, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Only regular files can be scanned.")
        if info.st_size > max_bytes:
            raise ValueError("File exceeds the configured scan size limit.")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return scan_stream(handle, filename or target.name, intelligence=intelligence,
                               yara_rules_path=yara_rules_path, max_bytes=max_bytes)
    finally:
        os.close(fd)

def scan_directory(root, *, intelligence=None, yara_rules_path=None,
                   max_files=MAX_DIRECTORY_FILES, max_total_bytes=MAX_DIRECTORY_BYTES,
                   max_depth=MAX_DIRECTORY_DEPTH, max_file_bytes=MAX_FILE_BYTES):
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        raise ValueError("Select an existing directory that is not a symlink.")
    results, errors, total_bytes = [], [], 0
    stack = [(base, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if len(results) + len(errors) >= max_files:
                        errors.append({"path": str(entry.path), "error": "FILE_COUNT_LIMIT"})
                        return {"results": results, "errors": errors, "files_scanned": len(results),
                                "bytes_scanned": total_bytes, "limit_reached": True}
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if depth < max_depth:
                                stack.append((Path(entry.path), depth + 1))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        info = entry.stat(follow_symlinks=False)
                        if info.st_size > max_file_bytes:
                            errors.append({"path": entry.name, "error": "FILE_SIZE_LIMIT"})
                            continue
                        if total_bytes + info.st_size > max_total_bytes:
                            errors.append({"path": entry.name, "error": "DIRECTORY_BYTE_LIMIT"})
                            return {"results": results, "errors": errors, "files_scanned": len(results),
                                    "bytes_scanned": total_bytes, "limit_reached": True}
                        result = scan_path(entry.path, intelligence=intelligence,
                                           yara_rules_path=yara_rules_path, max_bytes=max_file_bytes)
                        results.append(result.to_dict())
                        total_bytes += result.size_bytes
                    except (OSError, ValueError) as exc:
                        errors.append({"path": entry.name, "error": type(exc).__name__})
        except OSError as exc:
            errors.append({"path": str(current), "error": type(exc).__name__})
    return {"results": results, "errors": errors, "files_scanned": len(results),
            "bytes_scanned": total_bytes, "limit_reached": False}
