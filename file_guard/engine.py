"""Bounded static file inspection. No text extraction, rendering, unpacking or execution."""
from dataclasses import asdict, dataclass, field
import hashlib
from pathlib import Path
import re

MAX_FILE_BYTES = 64 * 1024 * 1024
MAGIC = [
    (b"%PDF-", "PDF", {".pdf"}),
    (b"MZ", "Windows executable", {".exe", ".dll", ".scr", ".com"}),
    (b"\x7fELF", "ELF executable", {".elf", ".so", ".bin"}),
    (b"PK\x03\x04", "ZIP container", {".zip", ".apk", ".docx", ".xlsx", ".pptx", ".jar"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"GIF87a", "GIF image", {".gif"}), (b"GIF89a", "GIF image", {".gif"}),
    (b"Rar!\x1a\x07", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE document", {".doc", ".xls", ".ppt", ".msg"}),
    (b"dex\n", "Android DEX", {".dex"}),
]
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png)\.(exe|scr|com|bat|cmd|ps1)$", re.I)

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
    content_extracted: bool = False
    executed: bool = False
    def to_dict(self):
        return asdict(self)

def _type(header):
    for signature, label, extensions in MAGIC:
        if header.startswith(signature):
            return label, extensions
    return ("Empty file" if not header else "Unknown / unrecognized"), set()

def _yara(data, rules_path):
    if not rules_path or not Path(rules_path).is_file():
        return False, []
    try:
        import yara
        matches = yara.compile(filepath=str(rules_path)).match(data=data, timeout=3)
        return True, [m.rule for m in matches]
    except ImportError:
        return False, []
    except Exception:
        return True, []

def scan_bytes(data, filename, *, intelligence=None, yara_rules_path=None, max_bytes=MAX_FILE_BYTES):
    if not isinstance(data, bytes):
        raise TypeError("File data must be bytes.")
    if len(data) > max_bytes:
        raise ValueError("File exceeds the configured scan size limit.")
    name = Path(filename or "unnamed").name[:255]
    ext = Path(name).suffix.lower()
    digest = hashlib.sha256(data).hexdigest()
    detected, allowed_exts = _type(data[:4096])
    signals, score = [], 0
    if detected == "Unknown / unrecognized":
        signals.append({"code":"UNKNOWN_SIGNATURE","severity":"low","detail":"No supported file signature recognized."})
    if allowed_exts and ext not in allowed_exts:
        signals.append({"code":"EXTENSION_SIGNATURE_MISMATCH","severity":"high","detail":f"{ext or '(none)'} extension conflicts with {detected} signature."})
        score += 45
    if DOUBLE_EXT.search(name):
        signals.append({"code":"DOUBLE_EXTENSION","severity":"high","detail":"Document/image extension is followed by an executable extension."})
        score += 35
    match = intelligence.lookup(digest) if intelligence else None
    if match and match["label"] == "malicious":
        signals.append({"code":"KNOWN_MALICIOUS_HASH","severity":"critical","detail":f"Exact SHA-256 match in {match['source']}."})
        score = 100
    elif match:
        signals.append({"code":"KNOWN_BENIGN_HASH","severity":"info","detail":f"Exact benign hash match in {match['source']}."})
    yara_available, yara_matches = _yara(data, yara_rules_path)
    if yara_matches:
        signals.append({"code":"YARA_MATCH","severity":"high","detail":"Local YARA match: " + ", ".join(yara_matches[:8])})
        score = max(score, 80)
    score = min(score, 100)
    if match and match["label"] == "malicious":
        verdict, risk = "Known threat", "critical"
    elif yara_matches:
        verdict, risk = "Signature match", "high"
    elif score >= 40:
        verdict, risk = "Suspicious", "high"
    elif score >= 20:
        verdict, risk = "Needs review", "medium"
    else:
        verdict, risk = "No known threat detected", "low"
    return FileScanResult(name, len(data), digest, detected, ext, verdict, risk, score,
                          signals, match, yara_available, yara_matches)

def scan_stream(stream, filename, *, intelligence=None, yara_rules_path=None, max_bytes=MAX_FILE_BYTES):
    data = bytearray()
    while True:
        chunk = stream.read(min(1024 * 1024, max_bytes + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_bytes:
            raise ValueError("File exceeds the configured scan size limit.")
    return scan_bytes(bytes(data), filename, intelligence=intelligence,
                      yara_rules_path=yara_rules_path, max_bytes=max_bytes)
